"""The Site Map page: a Burp-style tree of everything seen and everything linked.

The widget is deliberately dumb. All tree logic lives in ``model.SiteMap``; this
file turns :class:`model.Row` objects into urwid markup and keeps the cursor on
the same row across rebuilds.
"""

from __future__ import annotations

import urwid
from mitmproxy.tools.console import layoutwidget

from burpmap import model
from burpmap.ui_common import FOCUS_MAP
from burpmap.ui_common import GREY
from burpmap.ui_common import format_size
from burpmap.ui_common import method_attr
from burpmap.ui_common import short_ctype
from burpmap.ui_common import status_attr

DETAIL_WIDTH = 38


def _detail_markup(entry: model.Entry) -> list:
    """The right-hand column: method, status, type, size — or why there is none."""
    out: list = [(method_attr(entry.method), f"{entry.method:<6}")]
    if entry.status is not None:
        out.append((status_attr(entry.status), f"{entry.status:<4}"))
    elif entry.error:
        out.append(("error", f"{entry.error[:4]:<4}"))
    elif entry.visited:
        out.append(("warn", "... "))
    else:
        out.append((GREY, "link"))
        return out
    ctype = short_ctype(entry.ctype)
    if ctype:
        out.append(("text", f" {ctype[:14]}"))
    size = format_size(entry.size)
    if size:
        out.append((GREY, f" {size}"))
    return out


class RowItem(urwid.WidgetWrap):
    def __init__(self, row: model.Row, view: "SiteMapView") -> None:
        self.row = row
        self.view = view
        super().__init__(self._build())

    def _build(self) -> urwid.Widget:
        row = self.row
        indent = "  " * row.depth
        if row.expandable:
            twisty = "▾ " if row.expanded else "▸ "
        else:
            twisty = "  "

        left: list = [(GREY, indent + twisty)]
        entry = row.entry

        if row.kind == "group":
            left.append(("url_query_key", row.label))
            left.append((GREY, f"  ({row.count})"))
            return self._columns(left, [])

        if row.kind == "entry":
            attr = method_attr(entry.method) if entry else "text"
            if entry and not entry.visited:
                attr = GREY
            left.append((attr, row.label))
        else:
            assert row.node is not None
            if row.node.is_root:
                label_attr = "url_domain"
            elif entry is not None and not entry.visited:
                label_attr = GREY
            elif entry is not None:
                label_attr = "url_filename"
            else:
                label_attr = "text"
            marker = ""
            if entry is not None:
                marker = "● " if entry.visited else "○ "
            if marker:
                left.append((label_attr, marker))
            left.append((label_attr, row.label))

        right = _detail_markup(entry) if entry is not None else []
        return self._columns(left, right)

    def _columns(self, left: list, right: list) -> urwid.Widget:
        cols = urwid.Columns(
            [
                urwid.Text(left, wrap="clip"),
                (DETAIL_WIDTH, urwid.Text(right or "", wrap="clip")),
            ],
            dividechars=1,
        )
        return urwid.AttrMap(cols, None, focus_map=FOCUS_MAP)

    def selectable(self) -> bool:
        return True

    def mouse_event(self, size, event, button, col, row, focus):
        if event == "mouse press" and button == 1:
            self.view.toggle_expand()
            return True
        return False

    def keypress(self, size, key):
        # Let everything bubble up to mitmproxy's keymap dispatcher.
        return key


class SiteMapWalker(urwid.ListWalker):
    def __init__(self, view: "SiteMapView") -> None:
        self.view = view
        self.focus_pos = 0

    def _clamp(self, pos: int) -> int:
        return max(0, min(pos, max(0, len(self.view.rows) - 1)))

    def positions(self, reverse: bool = False):
        r = range(len(self.view.rows))
        return reversed(r) if reverse else r

    def get_focus(self):
        if not self.view.rows:
            return None, 0
        self.focus_pos = self._clamp(self.focus_pos)
        return RowItem(self.view.rows[self.focus_pos], self.view), self.focus_pos

    def set_focus(self, position: int) -> None:
        if not self.view.rows:
            return
        self.focus_pos = self._clamp(position)
        self._modified()

    def _at(self, position: int):
        if 0 <= position < len(self.view.rows):
            return RowItem(self.view.rows[position], self.view), position
        return None, None

    def get_next(self, position: int):
        return self._at(position + 1)

    def get_prev(self, position: int):
        return self._at(position - 1)


class SiteMapView(urwid.ListBox, layoutwidget.LayoutWidget):
    keyctx = "sitemap"

    def __init__(self, master, sitemap: model.SiteMap, display: model.Display) -> None:
        self.master = master
        self.sitemap = sitemap
        self.display = display
        self.rows: list[model.Row] = []
        self._generation = -1
        self._display_dirty = True
        self.walker = SiteMapWalker(self)
        super().__init__(self.walker)
        self.rebuild()

    # ------------------------------------------------------------------ title

    @property
    def title(self) -> str:  # type: ignore[override]
        hosts, visited, unvisited = self.sitemap.stats()
        bits = [f"Site map  {hosts} hosts  {visited} visited  {unvisited} unvisited"]
        if self.display.scope:
            state = "on" if self.display.scope_only else "off"
            # The header is one line; a long regex would wrap it into two.
            described = self.display.scope.describe()
            if len(described) > 60:
                described = described[:59] + "\u2026"
            bits.append(f"scope[{state}]: {described}")
        if self.display.collapse:
            bits.append("{id}")
        if self.display.unvisited_only:
            bits.append("unvisited only")
        return "  |  ".join(bits)

    # ---------------------------------------------------------------- refresh

    def invalidate_display(self) -> None:
        """Call after changing scope or a display toggle."""
        self._display_dirty = True
        self.rebuild()

    def view_changed(self) -> None:
        # Only the top window of each pane gets this, so the tree is not walked
        # while the site map is hidden behind another page.
        self.rebuild()

    def focus_changed(self) -> None:
        pass

    def layout_pushed(self, prev) -> None:
        self.rebuild()

    def rebuild(self, keep: str | None = None) -> None:
        if (
            not self._display_dirty
            and self._generation == self.sitemap.generation
            and keep is None
        ):
            return
        previous = keep
        if previous is None and 0 <= self.walker.focus_pos < len(self.rows):
            previous = self.rows[self.walker.focus_pos].ident

        self.rows = self.display.rows(self.sitemap)
        self._generation = self.sitemap.generation
        self._display_dirty = False

        if previous is not None:
            for index, row in enumerate(self.rows):
                if row.ident == previous:
                    self.walker.focus_pos = index
                    break
            else:
                self.walker.focus_pos = min(
                    self.walker.focus_pos, max(0, len(self.rows) - 1)
                )
        self.walker._modified()

    # ------------------------------------------------------------- selection

    def focused_row(self) -> model.Row | None:
        self.rebuild()
        if not self.rows:
            return None
        position = max(0, min(self.walker.focus_pos, len(self.rows) - 1))
        return self.rows[position]

    def focused_entry(self) -> model.Entry | None:
        row = self.focused_row()
        return row.entry if row else None

    def focused_node(self) -> model.Node | None:
        row = self.focused_row()
        return row.node if row else None

    def subtree_entries(self) -> list[model.Entry]:
        """Every entry under the cursor, honouring the current scope."""
        row = self.focused_row()
        if row is None:
            return []
        if row.kind == "entry" and row.entry is not None:
            candidates = [row.entry]
        elif row.kind == "group":
            candidates = [e for n in row.group_members for e in n.all_entries()]
        elif row.node is not None:
            candidates = list(row.node.all_entries())
        else:
            return []
        if self.display.scope and self.display.scope_only:
            candidates = [e for e in candidates if self.display.scope.match(e.url)]
        return candidates

    # ------------------------------------------------------------- expansion

    def set_expanded(self, expanded: bool | None) -> None:
        row = self.focused_row()
        if row is None:
            return
        if row.kind == "group":
            if expanded is None or expanded != row.expanded:
                self.sitemap.toggle_group(row.ident)
            self.rebuild(keep=row.ident)
            return
        node = row.node
        if node is None or not row.expandable:
            # Collapsing a leaf means "go to my parent", which is what every tree
            # widget does and what people's fingers expect.
            if expanded is False and node is not None and node.parent is not None:
                self.focus_ident(node.parent.path())
            return
        node.expanded = (not node.expanded) if expanded is None else expanded
        self.rebuild(keep=row.ident)

    def toggle_expand(self) -> None:
        self.set_expanded(None)

    # --------------------------------------------------------------- keypress

    def keypress(self, size, key):
        # left/right have to be handled here rather than through the keymap:
        # StackWidget.keypress swallows anything urwid's command map calls a
        # "cursor" movement before mitmproxy's key dispatcher ever sees it.
        # Because the global h/l bindings inject left/right, vim keys land here
        # too, for free.
        if key == "right":
            self.set_expanded(True)
            return None
        if key == "left":
            self.set_expanded(False)
            return None
        # g/G and the other nav.* commands inject these synthetic keys; urwid's
        # ListBox does not know them, so every view has to handle them itself.
        if key == "m_start":
            self.walker.set_focus(0)
            return None
        if key == "m_end":
            self.walker.set_focus(len(self.rows) - 1)
            return None
        return super().keypress(size, key)

    def focus_ident(self, ident: str) -> None:
        for index, row in enumerate(self.rows):
            if row.ident == ident:
                self.walker.focus_pos = index
                self.walker._modified()
                return
