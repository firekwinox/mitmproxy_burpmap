"""The site map itself: a URL trie fed by observed flows and discovered links.

The model knows nothing about urwid or about mitmproxy's console. It is fed by
``addon.py`` and read back as a flat list of :class:`Row` objects, so the widget
in ``ui_sitemap.py`` never has to walk the tree itself.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Optional
from urllib.parse import urlsplit

DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}

_NUMERIC = re.compile(r"^\d+$")
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)
_HEXISH = re.compile(r"^[0-9a-f]{16,}$", re.I)
# A long opaque token, e.g. a slug with a build hash in it. We insist on at least
# one digit so that ordinary long words ("documentation-overview") stay put.
_TOKENISH = re.compile(r"^(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{20,}$")

ID_GROUP_KEY = "{id}"


def is_id_like(segment: str) -> bool:
    """Does this path segment look like an identifier rather than a name?"""
    return bool(
        _NUMERIC.match(segment)
        or _UUID.match(segment)
        or _HEXISH.match(segment)
        or _TOKENISH.match(segment)
    )


def split_url(url: str) -> tuple[str, list[str], str]:
    """Split an absolute URL into (root key, path segments, query).

    The root key is ``scheme://host[:port]`` with the default port elided, which
    is what we use for the top level of the tree.
    """
    u = urlsplit(url)
    scheme = (u.scheme or "http").lower()
    host = (u.hostname or "").lower()
    try:
        port = u.port
    except ValueError:  # malformed port in the authority
        port = None
    default = DEFAULT_PORTS.get(scheme)
    if port is None or port == default:
        root = f"{scheme}://{host}"
    else:
        root = f"{scheme}://{host}:{port}"
    segments = [s for s in (u.path or "/").split("/") if s]
    return root, segments, u.query


class Scope:
    """Two regexes over the full URL: what to include, and what to take back out.

    Scope only ever affects what is *displayed*. Capture is always complete, the
    same way Burp keeps out-of-scope traffic in the site map behind the "show
    only in-scope items" checkbox.
    """

    def __init__(self, include: str = "", exclude: str = "") -> None:
        self.include_src = ""
        self.exclude_src = ""
        self._include: re.Pattern | None = None
        self._exclude: re.Pattern | None = None
        self.set(include, exclude)

    def set(self, include: str = "", exclude: str = "") -> None:
        """Compile both patterns. Raises re.error, leaving the old scope intact."""
        inc = re.compile(include) if include else None
        exc = re.compile(exclude) if exclude else None
        self._include, self._exclude = inc, exc
        self.include_src, self.exclude_src = include, exclude

    def match(self, url: str) -> bool:
        if self._include is not None and not self._include.search(url):
            return False
        if self._exclude is not None and self._exclude.search(url):
            return False
        return True

    def __bool__(self) -> bool:
        return bool(self.include_src or self.exclude_src)

    def describe(self) -> str:
        if not self:
            return "all"
        parts = []
        if self.include_src:
            parts.append(self.include_src)
        if self.exclude_src:
            parts.append(f"!{self.exclude_src}")
        return " ".join(parts)


@dataclass(eq=False)
class Entry:
    """One concrete request: a method plus a query string under some node.

    ``flow`` is None for a URI we have only ever seen *referenced* — the grey
    rows. The display fields are kept separately from the flow so that a site map
    saved to disk and reloaded still shows what it knew.
    """

    method: str
    url: str
    query: str = ""
    flow: Any = None  # mitmproxy.http.HTTPFlow, kept untyped so tests need no flow
    visited: bool = False
    status: Optional[int] = None
    ctype: str = ""
    size: Optional[int] = None
    error: str = ""
    sources: set[str] = field(default_factory=set)
    # The flow whose body referenced this URI. Kept so that "visit" can inherit
    # the session's cookies and User-Agent; never serialised.
    source_flow: Any = None

    @property
    def key(self) -> str:
        return f"{self.method} {self.query}"

    def update_from_flow(self, flow: Any) -> None:
        self.flow = flow
        self.visited = True
        self.error = str(flow.error.msg) if getattr(flow, "error", None) else ""
        response = getattr(flow, "response", None)
        if response is not None:
            self.status = response.status_code
            self.ctype = (response.headers.get("content-type", "") or "").split(";")[
                0
            ].strip()
            raw = response.raw_content
            self.size = len(raw) if raw is not None else None
        else:
            self.status = None

    def to_json(self) -> dict:
        return {
            "method": self.method,
            "url": self.url,
            "query": self.query,
            "visited": self.visited,
            "status": self.status,
            "ctype": self.ctype,
            "size": self.size,
            "error": self.error,
            "sources": sorted(self.sources),
        }

    @classmethod
    def from_json(cls, d: dict) -> "Entry":
        return cls(
            method=d["method"],
            url=d["url"],
            query=d.get("query", ""),
            visited=d.get("visited", False),
            status=d.get("status"),
            ctype=d.get("ctype", ""),
            size=d.get("size"),
            error=d.get("error", ""),
            sources=set(d.get("sources", [])),
        )


@dataclass(eq=False)
class Node:
    """One path segment, or one ``scheme://host:port`` root."""

    key: str
    parent: Optional["Node"] = field(default=None, repr=False)
    children: dict[str, "Node"] = field(default_factory=dict, repr=False)
    entries: dict[str, Entry] = field(default_factory=dict, repr=False)
    expanded: bool = True

    @property
    def is_root(self) -> bool:
        return self.parent is None

    def path(self) -> str:
        """The URL this node stands for, without query string."""
        parts: list[str] = []
        node: Optional[Node] = self
        while node is not None and not node.is_root:
            parts.append(node.key)
            node = node.parent
        root = node.key if node is not None else ""
        if not parts:
            return root + "/"
        return root + "/" + "/".join(reversed(parts))

    def label(self) -> str:
        return self.key if self.is_root else "/" + self.key

    def walk(self) -> Iterable["Node"]:
        yield self
        for child in self.children.values():
            yield from child.walk()

    def all_entries(self) -> Iterable[Entry]:
        for node in self.walk():
            yield from node.entries.values()


@dataclass(eq=False)
class Row:
    """A single rendered line. The widget renders these and nothing else."""

    depth: int
    kind: str  # "node" | "entry" | "group"
    label: str
    ident: str  # stable across rebuilds, used to keep the cursor in place
    node: Optional[Node] = None
    entry: Optional[Entry] = None
    group_members: list[Node] = field(default_factory=list)
    expandable: bool = False
    expanded: bool = False
    count: int = 0  # for {id} groups


class SiteMap:
    def __init__(self) -> None:
        self.roots: dict[str, Node] = {}
        self.by_flow_id: dict[str, Entry] = {}
        # Maintained incrementally: stats() is read once per rendered frame and
        # once per response, so walking the tree for it does not scale.
        self.count_total = 0
        self.count_visited = 0
        # Expansion state for synthetic {id} groups, keyed by "<node path>\t{id}".
        self.group_expanded: set[str] = set()
        self.generation = 0

    # ------------------------------------------------------------------ build

    def _touch(self) -> None:
        self.generation += 1

    def _node_for(self, url: str, create: bool = True) -> tuple[Optional[Node], str]:
        root_key, segments, query = split_url(url)
        root = self.roots.get(root_key)
        if root is None:
            if not create:
                return None, query
            root = Node(key=root_key)
            self.roots[root_key] = root
        node = root
        for segment in segments:
            child = node.children.get(segment)
            if child is None:
                if not create:
                    return None, query
                child = Node(key=segment, parent=node)
                node.children[segment] = child
            node = child
        return node, query

    def _entry(self, url: str, method: str) -> Entry:
        node, query = self._node_for(url, create=True)
        assert node is not None
        key = f"{method} {query}"
        entry = node.entries.get(key)
        if entry is None:
            entry = Entry(method=method, url=url, query=query)
            node.entries[key] = entry
            self.count_total += 1
        return entry

    def add_flow(self, flow: Any) -> Optional[Entry]:
        """Record a real request/response. Flips a grey entry to visited."""
        request = getattr(flow, "request", None)
        if request is None:
            return None
        try:
            url = request.pretty_url
        except Exception:
            return None
        entry = self._entry(url, request.method.upper())
        was_visited = entry.visited
        entry.update_from_flow(flow)
        if not was_visited:
            self.count_visited += 1
        self.by_flow_id[flow.id] = entry
        self._touch()
        return entry

    def add_link(
        self,
        url: str,
        method: str = "GET",
        source: str = "",
        source_flow: Any = None,
    ) -> Optional[Entry]:
        """Record a URI we have seen referenced but not (yet) requested."""
        entry = self._entry(url, method.upper())
        if source:
            entry.sources.add(source)
        if source_flow is not None and entry.source_flow is None:
            entry.source_flow = source_flow
        self._touch()
        return entry

    def remove_node(self, node: Node) -> None:
        for entry in node.all_entries():
            if entry.flow is not None:
                self.by_flow_id.pop(entry.flow.id, None)
            self.count_total -= 1
            if entry.visited:
                self.count_visited -= 1
        if node.parent is not None:
            node.parent.children.pop(node.key, None)
        else:
            self.roots.pop(node.key, None)
        self._touch()

    def remove_entry(self, node: Node, entry: Entry) -> None:
        if node.entries.pop(entry.key, None) is not None:
            self.count_total -= 1
            if entry.visited:
                self.count_visited -= 1
        if entry.flow is not None:
            self.by_flow_id.pop(entry.flow.id, None)
        self._touch()

    def clear(self) -> None:
        self.roots.clear()
        self.by_flow_id.clear()
        self.group_expanded.clear()
        self.count_total = 0
        self.count_visited = 0
        self._touch()

    # ------------------------------------------------------------------ query

    def all_entries(self) -> Iterable[Entry]:
        for root in self.roots.values():
            yield from root.all_entries()

    def stats(self) -> tuple[int, int, int]:
        """(hosts, visited entries, unvisited entries)"""
        return (
            len(self.roots),
            self.count_visited,
            self.count_total - self.count_visited,
        )

    # ---------------------------------------------------------------- flatten

    def rows(
        self,
        scope: Optional[Scope] = None,
        scope_only: bool = True,
        collapse: bool = False,
        threshold: int = 3,
        unvisited_only: bool = False,
    ) -> list[Row]:
        """Flatten the visible part of the tree into display rows."""
        active_scope = scope if (scope is not None and scope_only and scope) else None
        keep_cache: dict[int, bool] = {}

        def keep_entry(entry: Entry) -> bool:
            if unvisited_only and entry.visited:
                return False
            if active_scope is not None and not active_scope.match(entry.url):
                return False
            return True

        def has_content(node: Node) -> bool:
            cached = keep_cache.get(id(node))
            if cached is not None:
                return cached
            result = any(keep_entry(e) for e in node.entries.values()) or any(
                has_content(c) for c in node.children.values()
            )
            keep_cache[id(node)] = result
            return result

        rows: list[Row] = []

        def emit_children(node: Node, depth: int) -> None:
            children = [c for c in node.children.values() if has_content(c)]
            grouped: list[Node] = []
            plain: list[Node] = []
            if collapse:
                for child in children:
                    (grouped if is_id_like(child.key) else plain).append(child)
                if len(grouped) < threshold:
                    plain = children
                    grouped = []
            else:
                plain = children

            for child in sorted(plain, key=lambda n: n.key):
                emit_node(child, depth)

            if grouped:
                ident = f"{node.path()}\t{ID_GROUP_KEY}"
                expanded = ident in self.group_expanded
                rows.append(
                    Row(
                        depth=depth,
                        kind="group",
                        label=ID_GROUP_KEY,
                        ident=ident,
                        node=node,
                        group_members=grouped,
                        expandable=True,
                        expanded=expanded,
                        count=len(grouped),
                    )
                )
                if expanded:
                    for child in sorted(grouped, key=lambda n: n.key):
                        emit_node(child, depth + 1)

        def emit_node(node: Node, depth: int) -> None:
            kept = [e for e in node.entries.values() if keep_entry(e)]
            visible_children = [c for c in node.children.values() if has_content(c)]
            # A leaf with a single plain GET is drawn as one line, like Burp shows
            # a file rather than a file plus a request beneath it.
            inline = (
                len(kept) == 1
                and not visible_children
                and kept[0].method == "GET"
                and not kept[0].query
            )
            expandable = bool(visible_children) or (len(kept) > 1 or (kept and not inline))
            rows.append(
                Row(
                    depth=depth,
                    kind="node",
                    label=node.label(),
                    ident=node.path(),
                    node=node,
                    entry=kept[0] if inline else None,
                    expandable=expandable,
                    expanded=node.expanded,
                )
            )
            if not node.expanded:
                return
            if not inline:
                for entry in sorted(kept, key=lambda e: (e.method, e.query)):
                    rows.append(
                        Row(
                            depth=depth + 1,
                            kind="entry",
                            label=entry.method + (f" ?{entry.query}" if entry.query else ""),
                            ident=f"{node.path()}\t{entry.key}",
                            node=node,
                            entry=entry,
                        )
                    )
            emit_children(node, depth + 1)

        for root in sorted(self.roots.values(), key=lambda n: n.key):
            if has_content(root):
                emit_node(root, 0)
        return rows

    def toggle_group(self, ident: str) -> None:
        if ident in self.group_expanded:
            self.group_expanded.discard(ident)
        else:
            self.group_expanded.add(ident)
        self._touch()

    def set_expanded(self, expanded: bool) -> None:
        for root in self.roots.values():
            for node in root.walk():
                node.expanded = expanded
        self._touch()

    # ----------------------------------------------------------------- output

    def dump(self, display: Optional["Display"] = None) -> str:
        """An ASCII tree, so the addon is useful under mitmdump with no TUI."""
        rows = display.rows(self) if display is not None else self.rows()
        lines = []
        for row in rows:
            marker = " "
            detail = ""
            entry = row.entry
            if row.kind == "group":
                marker = "+"
                detail = f"({row.count})"
            elif entry is not None:
                marker = "*" if entry.visited else "o"
                bits = [entry.method]
                if entry.status is not None:
                    bits.append(str(entry.status))
                elif entry.error:
                    bits.append(entry.error)
                elif not entry.visited:
                    bits.append("(link)")
                if entry.ctype:
                    bits.append(entry.ctype)
                detail = " ".join(bits)
            lines.append(f"{'  ' * row.depth}{marker} {row.label:<40} {detail}".rstrip())
        return "\n".join(lines)

    def to_json(self) -> str:
        return json.dumps(
            {"version": 1, "entries": [e.to_json() for e in self.all_entries()]},
            indent=1,
        )

    def load_json(self, text: str) -> int:
        """Merge a saved site map in. Returns the number of entries added."""
        data = json.loads(text)
        added = 0
        for raw in data.get("entries", []):
            loaded = Entry.from_json(raw)
            node, query = self._node_for(loaded.url, create=True)
            assert node is not None
            key = f"{loaded.method} {query}"
            if key in node.entries:
                node.entries[key].sources |= loaded.sources
                continue
            loaded.query = query
            node.entries[key] = loaded
            self.count_total += 1
            if loaded.visited:
                self.count_visited += 1
            added += 1
        self._touch()
        return added


@dataclass
class Display:
    """Per-session display state, shared by both console panes."""

    scope: Scope = field(default_factory=Scope)
    scope_only: bool = True
    collapse: bool = False
    threshold: int = 3
    unvisited_only: bool = False

    def rows(self, sitemap: "SiteMap") -> list[Row]:
        return sitemap.rows(
            scope=self.scope,
            scope_only=self.scope_only,
            collapse=self.collapse,
            threshold=self.threshold,
            unvisited_only=self.unvisited_only,
        )
