"""The addon: options, traffic hooks, and every ``sitemap.*`` / ``repeater.*`` command.

Load it with ``mitmproxy -s burpmap.py``. Under mitmdump or mitmweb the console
integration is skipped and the site map is still built, so ``sitemap.dump`` works
headlessly.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from typing import Optional

# Default option values
DEFAULT_SITEMAP_DISCOVERY_MAX_BODY = 2 * 1024 * 1024  # 2 MB
DEFAULT_SITEMAP_DISCOVERY_MAX_LINKS = 500
DEFAULT_SITEMAP_COLLAPSE_THRESHOLD = 3
DEFAULT_SITEMAP_VISIT_MAX = 50
DEFAULT_SITEMAP_MAX_ENTRIES = 100000

import mitmproxy.types
from mitmproxy import command
from mitmproxy import connection
from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flow as mflow
from mitmproxy import http
from mitmproxy.log import ALERT

from burpmap import console
from burpmap import discovery
from burpmap import rawhttp
from burpmap.model import Display
from burpmap.model import Entry
from burpmap.model import Node
from burpmap.model import Row
from burpmap.model import SiteMap
from burpmap.repeater import Repeater

logger = logging.getLogger(__name__)

# Headers worth carrying over when requesting a URI we only saw as a link. Without
# these, "visit" is useless the moment a target needs a session.
INHERITED_HEADERS = (
    "user-agent",
    "cookie",
    "authorization",
    "accept",
    "accept-language",
)


class BurpMap:
    def __init__(self) -> None:
        self.sitemap = SiteMap()
        self.display = Display()
        self.repeater = Repeater()
        self.sitemap_views: list = []
        self.repeater_views: list = []
        self.installed = False
        self._limit_warned = False

    # ------------------------------------------------------------ addon hooks

    def load(self, loader) -> None:
        loader.add_option(
            "sitemap_scope",
            str,
            "",
            "Site map scope: a regex matched against the full URL. Empty means everything.",
        )
        loader.add_option(
            "sitemap_scope_exclude",
            str,
            "",
            "Site map scope exclusion: a regex matched against the full URL.",
        )
        loader.add_option(
            "sitemap_scope_only",
            bool,
            True,
            "Show only in-scope items in the site map. Capture is unaffected.",
        )
        loader.add_option(
            "sitemap_discovery",
            Sequence[str],
            ["html", "js", "json"],
            f"Where to look for unvisited URIs. Any of: {', '.join(discovery.SOURCES)}.",
        )
        loader.add_option(
            "sitemap_discovery_max_body",
            int,
            DEFAULT_SITEMAP_DISCOVERY_MAX_BODY,
            "Skip link extraction for response bodies larger than this many bytes.",
        )
        loader.add_option(
            "sitemap_discovery_max_links",
            int,
            DEFAULT_SITEMAP_DISCOVERY_MAX_LINKS,
            "Maximum number of links to take from a single response.",
        )
        loader.add_option(
            "sitemap_collapse",
            bool,
            False,
            "Fold numeric/UUID path segments into a single {id} node.",
        )
        loader.add_option(
            "sitemap_collapse_threshold",
            int,
            DEFAULT_SITEMAP_COLLAPSE_THRESHOLD,
            "How many id-like siblings are needed before they fold into {id}.",
        )
        loader.add_option(
            "sitemap_unvisited_only",
            bool,
            False,
            "Show only URIs that have never been requested.",
        )
        loader.add_option(
            "sitemap_visit_inherit_headers",
            bool,
            True,
            "When requesting a discovered URI, reuse cookies and headers from the page it was found on.",
        )
        loader.add_option(
            "sitemap_visit_max",
            int,
            DEFAULT_SITEMAP_VISIT_MAX,
            "Maximum number of URIs a single subtree visit will request.",
        )
        loader.add_option(
            "repeater_update_content_length",
            bool,
            True,
            "Recompute Content-Length when a repeater request is edited. Turn this "
            "off to send a deliberately wrong length.",
        )
        loader.add_option(
            "sitemap_max_entries",
            int,
            DEFAULT_SITEMAP_MAX_ENTRIES,
            "Stop adding to the site map past this many entries.",
        )

    def configure(self, updated) -> None:
        if "sitemap_scope" in updated or "sitemap_scope_exclude" in updated:
            try:
                self.display.scope.set(
                    ctx.options.sitemap_scope, ctx.options.sitemap_scope_exclude
                )
            except re.error as exc:
                raise exceptions.OptionsError(f"Invalid site map scope regex: {exc}")
        if "sitemap_discovery" in updated:
            unknown = set(ctx.options.sitemap_discovery) - set(discovery.SOURCES)
            if unknown:
                raise exceptions.OptionsError(
                    f"Unknown sitemap_discovery source(s): {', '.join(sorted(unknown))}. "
                    f"Valid: {', '.join(discovery.SOURCES)}."
                )
        self.display.scope_only = ctx.options.sitemap_scope_only
        self.display.collapse = ctx.options.sitemap_collapse
        self.display.threshold = max(2, ctx.options.sitemap_collapse_threshold)
        self.display.unvisited_only = ctx.options.sitemap_unvisited_only
        self._refresh()

    def running(self) -> None:
        if self.installed:
            return
        # mitmproxy re-executes the entry script on change and builds a fresh
        # addon, which would otherwise throw away everything collected so far.
        # The submodules stay in sys.modules across a reload, so the stashed
        # objects are instances of the very same classes.
        stashed = getattr(ctx.master, "_burpmap_state", None)
        if stashed is not None:
            self.sitemap, self.repeater = stashed
        else:
            ctx.master._burpmap_state = (self.sitemap, self.repeater)
        self.sitemap_views, self.repeater_views = console.install(
            ctx.master, self.sitemap, self.display, self.repeater
        )
        self.installed = bool(self.sitemap_views)

    def done(self) -> None:
        if self.installed:
            console.uninstall(ctx.master)
            self.sitemap_views = []
            self.repeater_views = []
            self.installed = False

    # ---------------------------------------------------------- traffic hooks

    def request(self, flow: http.HTTPFlow) -> None:
        self.sitemap.add_flow(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        self.sitemap.add_flow(flow)
        self.repeater.resolve(flow)
        self._refresh_repeater()

    def response(self, flow: http.HTTPFlow) -> None:
        self.sitemap.add_flow(flow)
        self._discover(flow)
        if self.repeater.resolve(flow) is not None:
            self._refresh_repeater()

    def _discover(self, flow: http.HTTPFlow) -> None:
        sources = tuple(ctx.options.sitemap_discovery)
        if not sources:
            return
        if self._at_limit():
            return
        try:
            links = discovery.extract(
                flow,
                sources=sources,
                max_body=ctx.options.sitemap_discovery_max_body,
                max_links=ctx.options.sitemap_discovery_max_links,
            )
        except Exception:
            logger.debug("burpmap: link extraction failed", exc_info=True)
            return
        origin = flow.request.pretty_url
        for method, url in links:
            self.sitemap.add_link(url, method, source=origin, source_flow=flow)

    def _at_limit(self) -> bool:
        _, visited, unvisited = self.sitemap.stats()
        if visited + unvisited < ctx.options.sitemap_max_entries:
            return False
        if not self._limit_warned:
            self._limit_warned = True
            logger.warning(
                f"burpmap: site map reached sitemap_max_entries "
                f"({ctx.options.sitemap_max_entries}); no longer adding links."
            )
        return True

    # ------------------------------------------------------------- UI helpers

    def _refresh(self) -> None:
        for view in self.sitemap_views:
            view.invalidate_display()
        self._refresh_repeater()
        window = getattr(ctx.master, "window", None) if ctx.master else None
        if window is not None:
            try:
                window.refresh()
            except Exception:  # pragma: no cover - during startup/shutdown
                pass

    def _refresh_repeater(self) -> None:
        for view in self.repeater_views:
            view.rebuild(force=True)

    def _focused_sitemap(self):
        window = getattr(ctx.master, "window", None)
        widget = window.current("sitemap") if window else None
        if widget is None:
            raise exceptions.CommandError("Not viewing the site map.")
        return widget

    def _require_console(self) -> None:
        if not self.installed:
            raise exceptions.CommandError(
                "burpmap's pages need mitmproxy's console UI."
            )

    def _open_flow(self, target: mflow.Flow) -> None:
        self._require_console()
        if target not in ctx.master.view:
            raise exceptions.CommandError(
                "That flow is filtered out of the flow list; clear the view filter first."
            )
        ctx.master.view.focus.flow = target
        ctx.master.switch_view("flowview")

    # ------------------------------------------------------- site map: paging

    @command.command("sitemap.view")
    def sitemap_view(self) -> None:
        """View the site map."""
        self._require_console()
        ctx.master.switch_view("sitemap")

    @command.command("repeater.view")
    def repeater_view(self) -> None:
        """View the repeater."""
        self._require_console()
        ctx.master.switch_view("repeater")

    # ---------------------------------------------------- site map: selection

    @command.command("sitemap.open")
    def sitemap_open(self) -> None:
        """Expand the focused node, or open the focused request as a flow.

        Deliberately never puts a request on the wire. A grey row may be a
        logout link or a delete endpoint, and a key called "open" is the last
        place anyone expects to send traffic from. Requesting is always `v`.
        """
        widget = self._focused_sitemap()
        row: Optional[Row] = widget.focused_row()
        if row is None:
            return
        if row.entry is None:
            widget.toggle_expand()
            return
        if row.entry.flow is not None:
            self._open_flow(row.entry.flow)
            return
        logger.log(
            ALERT,
            f"{row.entry.method} {row.entry.url} has never been requested "
            f"- press v to request it.",
        )

    @command.command("sitemap.goto")
    def sitemap_goto(self) -> None:
        """Open the focused site map entry in the flow view."""
        entry = self._focused_sitemap().focused_entry()
        if entry is None or entry.flow is None:
            raise exceptions.CommandError("No captured flow for this row.")
        self._open_flow(entry.flow)

    # ------------------------------------------------------- site map: visits

    def _build_flow(self, entry: Entry) -> http.HTTPFlow:
        """Synthesize a flow for a URI, the way view.flows.create does."""
        try:
            request = http.Request.make(entry.method.upper(), entry.url)
        except ValueError as exc:
            raise exceptions.CommandError(f"Invalid URL {entry.url}: {exc}")

        source = entry.source_flow
        if ctx.options.sitemap_visit_inherit_headers and source is not None:
            for name in INHERITED_HEADERS:
                value = source.request.headers.get(name)
                if value:
                    request.headers[name] = value
            request.headers["referer"] = source.request.pretty_url

        client = connection.Client(
            peername=("", 0),
            sockname=("", 0),
            timestamp_start=request.timestamp_start - 0.0001,
        )
        server = connection.Server(address=(request.host, request.port))
        new = http.HTTPFlow(client, server)
        new.request = request
        # Request.make leaves Host unset, and the server needs one. Note that
        # view.flows.create sets it to request.host alone, which silently drops a
        # non-default port and makes the flow come back under the wrong host.
        default_port = {"http": 80, "https": 443}.get(request.scheme)
        new.request.headers["Host"] = (
            request.host
            if request.port == default_port
            else f"{request.host}:{request.port}"
        )
        new.comment = "burpmap: requested from the site map"
        return new

    def _send(self, flows: list[http.HTTPFlow]) -> None:
        # mitmdump has no view addon, so adding to the flow list is best-effort.
        view = getattr(ctx.master, "view", None)
        if view is not None:
            view.add(flows)
        ctx.master.commands.call("replay.client", flows)

    def _entry_under_cursor(self) -> Entry:
        """The focused request, or a GET for the focused directory node.

        Burp lets you request a folder you have only ever seen named in a path,
        which is often exactly the interesting one, so a node row is not an error.
        """
        widget = self._focused_sitemap()
        entry = widget.focused_entry()
        if entry is not None:
            return entry
        row = widget.focused_row()
        if row is None:
            raise exceptions.CommandError("Nothing is focused.")
        if row.node is None:
            raise exceptions.CommandError("The focused row has no associated node.")
        if row.kind == "group":
            raise exceptions.CommandError("Cannot request a collapsed {id} group directly - expand it first.")
        return Entry(method="GET", url=row.node.path())

    @command.command("sitemap.visit")
    def sitemap_visit(self) -> None:
        """Request the focused URI."""
        entry = self._entry_under_cursor()
        self._send([self._build_flow(entry)])
        logger.log(ALERT, f"Requesting {entry.method} {entry.url}")

    @command.command("sitemap.visit.url")
    def sitemap_visit_url(self, url: str, method: str = "GET") -> None:
        """Request a URI by name. Works without the console, unlike sitemap.visit."""
        wanted = discovery.normalise(url) or url
        for entry in self.sitemap.all_entries():
            if entry.url == wanted and entry.method == method.upper():
                self._send([self._build_flow(entry)])
                return
        # Not in the map yet - request it anyway and let the hooks record it.
        self._send([self._build_flow(Entry(method=method.upper(), url=wanted))])

    @command.command("sitemap.visit.subtree")
    def sitemap_visit_subtree(self) -> None:
        """Request every unvisited URI below the cursor."""
        widget = self._focused_sitemap()
        pending = [e for e in widget.subtree_entries() if not e.visited]
        if not pending:
            logger.log(ALERT, "Nothing unvisited below the cursor.")
            return

        limit = ctx.options.sitemap_visit_max
        truncated = len(pending) > limit
        pending = pending[:limit]

        def go(answer: str) -> None:
            if answer == "n":
                return
            self._send([self._build_flow(e) for e in pending])
            note = f" (capped at {limit})" if truncated else ""
            logger.log(ALERT, f"Requesting {len(pending)} URIs{note}")

        prompt = f"Request {len(pending)} URIs"
        if hasattr(ctx.master, "prompt_for_user_choice"):
            ctx.master.prompt_for_user_choice(prompt, go)
        else:
            go("y")

    # -------------------------------------------------------- site map: scope

    @command.command("sitemap.scope.set")
    def sitemap_scope_set(self, regex: str) -> None:
        """Set the site map scope regex."""
        try:
            re.compile(regex)
        except re.error as exc:
            raise exceptions.CommandError(f"Invalid regex: {exc}")
        ctx.options.update(sitemap_scope=regex)

    @command.command("sitemap.scope.here")
    def sitemap_scope_here(self) -> None:
        """Scope the site map to the host under the cursor."""
        node: Optional[Node] = self._focused_sitemap().focused_node()
        if node is None:
            raise exceptions.CommandError("Nothing focused.")
        while node.parent is not None:
            node = node.parent
        ctx.options.update(sitemap_scope="^" + re.escape(node.key) + "/")
        logger.log(ALERT, f"Scope set to {node.key}")

    @command.command("sitemap.scope.only.toggle")
    def sitemap_scope_only_toggle(self) -> None:
        """Toggle showing only in-scope items."""
        ctx.options.update(sitemap_scope_only=not ctx.options.sitemap_scope_only)

    @command.command("sitemap.collapse.toggle")
    def sitemap_collapse_toggle(self) -> None:
        """Toggle folding id-like path segments into {id}."""
        ctx.options.update(sitemap_collapse=not ctx.options.sitemap_collapse)

    @command.command("sitemap.unvisited.toggle")
    def sitemap_unvisited_toggle(self) -> None:
        """Toggle showing only URIs that have never been requested."""
        ctx.options.update(
            sitemap_unvisited_only=not ctx.options.sitemap_unvisited_only
        )

    @command.command("sitemap.expand.all")
    def sitemap_expand_all(self) -> None:
        """Expand every node in the site map."""
        self.sitemap.set_expanded(True)
        self._refresh()

    @command.command("sitemap.collapse.all")
    def sitemap_collapse_all(self) -> None:
        """Collapse every node in the site map."""
        self.sitemap.set_expanded(False)
        self._refresh()

    # ----------------------------------------------------- site map: contents

    @command.command("sitemap.delete")
    def sitemap_delete(self) -> None:
        """Remove the focused node or request from the site map."""
        widget = self._focused_sitemap()
        row = widget.focused_row()
        if row is None:
            return
        if row.kind == "entry" and row.entry is not None and row.node is not None:
            self.sitemap.remove_entry(row.node, row.entry)
        elif row.kind == "group":
            for member in list(row.group_members):
                self.sitemap.remove_node(member)
        elif row.node is not None:
            self.sitemap.remove_node(row.node)
        self._refresh()

    @command.command("sitemap.clear")
    def sitemap_clear(self) -> None:
        """Empty the site map."""
        self.sitemap.clear()
        self._limit_warned = False
        self._refresh()

    @command.command("sitemap.rebuild")
    def sitemap_rebuild(self) -> None:
        """Rebuild the site map from the flows mitmproxy currently holds.

        Loading a saved flow file does not fire request/response hooks, so this is
        how a `.flow` dump gets into the tree.
        """
        view = getattr(ctx.master, "view", None)
        if view is None:
            raise exceptions.CommandError("No flow store to rebuild from.")
        store = getattr(view, "_store", None)
        flows = list(store.values()) if store is not None else list(view)
        count = 0
        for f in flows:
            if isinstance(f, http.HTTPFlow):
                self.sitemap.add_flow(f)
                self._discover(f)
                count += 1
        self._refresh()
        logger.log(ALERT, f"Site map rebuilt from {count} flows.")

    @command.command("sitemap.save")
    def sitemap_save(self, path: mitmproxy.types.Path) -> None:
        """Save the site map as JSON."""
        try:
            with open(path, "w", encoding="utf8") as handle:
                handle.write(self.sitemap.to_json())
        except OSError as exc:
            raise exceptions.CommandError(str(exc))
        _, visited, unvisited = self.sitemap.stats()
        logger.log(ALERT, f"Saved {visited + unvisited} site map entries to {path}")

    @command.command("sitemap.load")
    def sitemap_load(self, path: mitmproxy.types.Path) -> None:
        """Merge a saved site map back in."""
        try:
            with open(path, encoding="utf8") as handle:
                added = self.sitemap.load_json(handle.read())
        except (OSError, ValueError) as exc:
            raise exceptions.CommandError(str(exc))
        self._refresh()
        logger.log(ALERT, f"Loaded {added} site map entries from {path}")

    @command.command("sitemap.dump")
    def sitemap_dump(self) -> str:
        """Render the site map as an ASCII tree."""
        return self.sitemap.dump(self.display)

    # ---------------------------------------------------------------- repeater

    @command.command("repeater.add")
    def repeater_add(self, flows: Sequence[mflow.Flow]) -> None:
        """Send flows to the repeater as new slots."""
        added = 0
        for f in flows:
            if not isinstance(f, http.HTTPFlow):
                continue
            self.repeater.add(f)
            added += 1
        if not added:
            raise exceptions.CommandError("Only HTTP flows can go to the repeater.")
        self._refresh_repeater()
        logger.log(ALERT, f"Added {added} slot(s) to the repeater.")

    @command.command("sitemap.send.repeater")
    def sitemap_send_repeater(self) -> None:
        """Send the focused site map request to the repeater."""
        entry = self._entry_under_cursor()
        source = entry.flow if entry.flow is not None else self._build_flow(entry)
        self.repeater_add([source])

    def _repeater_widget(self):
        window = getattr(ctx.master, "window", None)
        return window.current("repeater") if window is not None else None

    def _focused_repeater(self):
        widget = self._repeater_widget()
        if widget is None:
            raise exceptions.CommandError("Not viewing the repeater.")
        return widget

    def _current_slot(self):
        slot = self.repeater.current
        if slot is None:
            raise exceptions.CommandError("The repeater is empty.")
        return slot

    @command.command("repeater.send")
    def repeater_send(self) -> None:
        """Apply any pending edit and send the current repeater slot."""
        slot = self._current_slot()
        widget = self._repeater_widget()
        if widget is not None and widget.editing:
            try:
                widget.commit_edit(ctx.options.repeater_update_content_length)
            except ValueError as exc:
                raise exceptions.CommandError(f"Not sent, the request is malformed: {exc}")
        sent = self.repeater.prepare_send(slot)
        self._send([sent])
        self._refresh_repeater()

    @command.command("repeater.edit")
    def repeater_edit(self) -> None:
        """Edit the current repeater request as raw HTTP text."""
        widget = self._focused_repeater()
        try:
            widget.begin_edit()
        except ValueError as exc:
            raise exceptions.CommandError(str(exc))

    @command.command("repeater.apply")
    def repeater_apply(self) -> None:
        """Parse the edited text back onto the request."""
        widget = self._focused_repeater()
        try:
            widget.commit_edit(ctx.options.repeater_update_content_length)
        except ValueError as exc:
            raise exceptions.CommandError(f"The request is malformed: {exc}")

    @command.command("repeater.cancel")
    def repeater_cancel(self) -> None:
        """Leave the editor, discarding the changes."""
        self._focused_repeater().cancel_edit()

    @command.command("repeater.history.restore")
    def repeater_history_restore(self) -> None:
        """Copy the selected send back over the editable template."""
        slot = self._current_slot()
        if slot.cursor < 0 or not slot.history:
            raise exceptions.CommandError("No past send selected.")
        slot.flow.request = slot.history[slot.cursor].request.copy()
        slot.cursor = -1
        self.repeater._touch()
        self._refresh()

    @command.command("repeater.open")
    def repeater_open(self) -> None:
        """Open the selected repeater exchange in the flow view."""
        slot = self._current_slot()
        target = slot.selected
        if target not in ctx.master.view:
            ctx.master.view.add([target])
        self._open_flow(target)

    @command.command("repeater.slot.next")
    def repeater_slot_next(self) -> None:
        """Select the next repeater slot."""
        self.repeater.select(1)
        self._refresh()

    @command.command("repeater.slot.prev")
    def repeater_slot_prev(self) -> None:
        """Select the previous repeater slot."""
        self.repeater.select(-1)
        self._refresh()

    @command.command("repeater.history.next")
    def repeater_history_next(self) -> None:
        """Show the next send in the current slot's history."""
        self.repeater.scroll_history(1)
        self._refresh()

    @command.command("repeater.history.prev")
    def repeater_history_prev(self) -> None:
        """Show the previous send in the current slot's history."""
        self.repeater.scroll_history(-1)
        self._refresh()

    @command.command("repeater.template")
    def repeater_template(self) -> None:
        """Show the editable template instead of a past send."""
        slot = self._current_slot()
        slot.cursor = -1
        self.repeater._touch()
        self._refresh()

    @command.command("repeater.slot.delete")
    def repeater_slot_delete(self) -> None:
        """Delete the current repeater slot."""
        self.repeater.remove(self._current_slot())
        self._refresh()

    @command.command("repeater.slot.rename")
    def repeater_slot_rename(self, name: str) -> None:
        """Rename the current repeater slot."""
        self._current_slot().name = name
        self.repeater._touch()
        self._refresh()
