"""Wiring the two pages into mitmproxy's console: windows, key contexts, help.

mitmproxy has no public API for adding a top-level view, so we reach into three
places it does expose as plain mutable state: ``WindowStack.windows`` (the pane
registry), ``keymap.Contexts`` (the set of legal key contexts) and
``quickhelp.make`` (the bottom help bar). Everything done here is undone in
:func:`uninstall` so that ``--set scripts`` hot-reload leaves nothing behind.
"""

from __future__ import annotations

import logging

from mitmproxy.tools.console import keymap as keymap_module
from mitmproxy.tools.console import quickhelp
from mitmproxy.tools.console.quickhelp import BasicKeyHelp

from burpmap.ui_repeater import RepeaterView
from burpmap.ui_sitemap import SiteMapView

logger = logging.getLogger(__name__)

WINDOW_NAMES = ("sitemap", "repeater")
CONTEXTS = ("sitemap", "repeater")

# (key, command, contexts, help). The help text is also the lookup key used by
# mitmproxy's quick-help bar, so these strings must match QUICKHELP below.
BINDINGS: list[tuple[str, str, list[str], str]] = [
    ("T", "sitemap.view", ["global"], "View the site map"),
    ("R", "repeater.view", ["global"], "View the repeater"),
    ("ctrl r", "repeater.add @focus", ["flowlist", "flowview"], "Send flow to the repeater"),
    # --- site map -----------------------------------------------------------
    ("enter", "sitemap.open", ["sitemap"], "Open the focused flow"),
    ("v", "sitemap.visit", ["sitemap"], "Request the focused URI"),
    ("V", "sitemap.visit.subtree", ["sitemap"], "Request every unvisited URI below the cursor"),
    ("ctrl r", "sitemap.send.repeater", ["sitemap"], "Send the focused request to the repeater"),
    ("S", "console.command.set sitemap_scope", ["sitemap"], "Set the site map scope"),
    ("X", "console.command.set sitemap_scope_exclude", ["sitemap"], "Set the scope exclusion"),
    ("H", "sitemap.scope.here", ["sitemap"], "Scope to the focused host"),
    ("s", "sitemap.scope.only.toggle", ["sitemap"], "Toggle showing only in-scope items"),
    ("c", "sitemap.collapse.toggle", ["sitemap"], "Toggle {id} collapsing"),
    ("u", "sitemap.unvisited.toggle", ["sitemap"], "Toggle showing only unvisited URIs"),
    ("A", "sitemap.expand.all", ["sitemap"], "Expand the whole tree"),
    ("Z", "sitemap.collapse.all", ["sitemap"], "Collapse the whole tree"),
    ("d", "sitemap.delete", ["sitemap"], "Delete the focused node from the site map"),
    (
        "z",
        'console.command.confirm "Clear site map" sitemap.clear',
        ["sitemap"],
        "Clear the site map",
    ),
    ("w", "console.command sitemap.save ", ["sitemap"], "Save the site map to file"),
    ("L", "console.command sitemap.load ", ["sitemap"], "Load a site map from file"),
    ("b", "sitemap.rebuild", ["sitemap"], "Rebuild the site map from captured flows"),
    # --- repeater -----------------------------------------------------------
    ("r", "repeater.send", ["repeater"], "Send the current repeater slot"),
    # ctrl-r also works from inside the editor, where r is just a letter.
    ("ctrl r", "repeater.send", ["repeater"], "Apply the edit and send"),
    ("e", "repeater.edit", ["repeater"], "Edit the request as raw text"),
    ("i", "repeater.edit", ["repeater"], "Edit the request as raw text"),
    ("c", "repeater.history.restore", ["repeater"], "Copy this send back to the template"),
    ("enter", "repeater.open", ["repeater"], "Open the selected repeater exchange"),
    ("]", "repeater.slot.next", ["repeater"], "Next repeater slot"),
    ("[", "repeater.slot.prev", ["repeater"], "Previous repeater slot"),
    (">", "repeater.history.next", ["repeater"], "Next send in the history"),
    ("<", "repeater.history.prev", ["repeater"], "Previous send in the history"),
    ("t", "repeater.template", ["repeater"], "Back to the editable template"),
    ("D", "repeater.slot.delete", ["repeater"], "Delete the current repeater slot"),
    (
        "N",
        "console.command repeater.slot.rename ",
        ["repeater"],
        "Rename the current repeater slot",
    ),
]

QUICKHELP_SITEMAP = {
    "Visit": "Request the focused URI",
    "Open": "Open the focused flow",
    "Send": "Send the focused request to the repeater",
    "Scope": "Set the site map scope",
    "In scope": "Toggle showing only in-scope items",
    "{id}": "Toggle {id} collapsing",
    "Unvisited": "Toggle showing only unvisited URIs",
}

QUICKHELP_REPEATER = {
    "Edit text": "Edit the request as raw text",
    "Send": "Send the current repeater slot",
    "Next slot": "Next repeater slot",
    "History": "Next send in the history",
    "Restore": "Copy this send back to the template",
    "Open flow": "Open the selected repeater exchange",
}

# Shown instead while the raw-text editor has the keyboard, where single letters
# are just letters. These keys are handled inside the widget, not by the keymap,
# so they are spelled out rather than looked up.
QUICKHELP_EDITING = {
    "Apply": BasicKeyHelp("esc"),
    "Apply+send": BasicKeyHelp("ctrl r"),
    "Discard": BasicKeyHelp("ctrl x"),
    "Switch pane": BasicKeyHelp("tab"),
}

_original_quickhelp_make = None
_master = None


def _editing_now() -> bool:
    """quickhelp.make only gets the widget *type*, so ask the live widget."""
    window = getattr(_master, "window", None) if _master is not None else None
    if window is None:
        return False
    widget = window.current("repeater")
    return bool(widget is not None and getattr(widget, "editing", False))


def _patched_quickhelp_make(widget, focused_flow, is_root_widget):
    assert _original_quickhelp_make is not None
    qh = _original_quickhelp_make(widget, focused_flow, is_root_widget)
    label = None
    if isinstance(widget, type) and issubclass(widget, SiteMapView):
        label, qh.top_items = "Site map:", dict(QUICKHELP_SITEMAP)
    elif isinstance(widget, type) and issubclass(widget, RepeaterView):
        if _editing_now():
            label, qh.top_items = "Editing:", dict(QUICKHELP_EDITING)
        else:
            label, qh.top_items = "Repeater:", dict(QUICKHELP_REPEATER)
    if label is not None:
        # quickhelp sizes the label column to the string it is given, so the
        # label needs its own trailing space, and both rows need the same width
        # or the two help rows stop lining up.
        width = max(len(qh.top_label), len(qh.bottom_label), len(label) + 1)
        qh.top_label = label.ljust(width)
        qh.bottom_label = qh.bottom_label.rstrip().ljust(width)
    return qh


def install(master, sitemap, display, repeater) -> tuple[list, list]:
    """Add both pages to every console pane.

    Returns the widgets that were created, so the addon can refresh them, or two
    empty lists when there is no console UI (mitmdump, mitmweb).
    """
    global _original_quickhelp_make, _master

    window = getattr(master, "window", None)
    if window is None:
        # mitmdump and mitmweb have no console window. The site map is still
        # built; only the TUI pages are skipped.
        return [], []

    keymap_module.Contexts.update(CONTEXTS)
    _master = master

    sitemap_views: list[SiteMapView] = []
    repeater_views: list[RepeaterView] = []
    for stack in window.stacks:
        # Each stack owns its own widget instances, exactly as mitmproxy's own
        # views do, but they share one model.
        sitemap_view = SiteMapView(master, sitemap, display)
        repeater_view = RepeaterView(master, repeater)
        stack.windows["sitemap"] = sitemap_view
        stack.windows["repeater"] = repeater_view
        sitemap_views.append(sitemap_view)
        repeater_views.append(repeater_view)

    for key, command, contexts, help_text in BINDINGS:
        try:
            master.keymap.add(key, command, contexts, help_text)
        except ValueError as exc:
            logger.warning(f"burpmap: could not bind {key}: {exc}")

    if _original_quickhelp_make is None:
        _original_quickhelp_make = quickhelp.make
        quickhelp.make = _patched_quickhelp_make
    return sitemap_views, repeater_views


def uninstall(master) -> None:
    global _original_quickhelp_make, _master

    _master = None

    if _original_quickhelp_make is not None:
        quickhelp.make = _original_quickhelp_make
        _original_quickhelp_make = None

    keymap = getattr(master, "keymap", None)
    if keymap is not None:
        for key, _command, contexts, _help in BINDINGS:
            try:
                keymap.remove(key, contexts)
            except Exception:  # pragma: no cover - teardown must never raise
                pass

    window = getattr(master, "window", None)
    if window is not None:
        for stack in window.stacks:
            remaining = [name for name in stack.stack if name not in WINDOW_NAMES]
            stack.stack = remaining or ["flowlist"]
            for name in WINDOW_NAMES:
                stack.windows.pop(name, None)
        try:
            window.refresh()
        except Exception:  # pragma: no cover - the loop may already be gone
            pass

    keymap_module.Contexts.difference_update(CONTEXTS)
