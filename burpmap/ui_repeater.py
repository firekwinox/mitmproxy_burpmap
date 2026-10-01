"""The Repeater page: request on the left, response on the right, like Burp.

The request pane is a raw-text editor over the literal HTTP request. mitmproxy's
own flow view is still one keypress away (enter), but nothing here routes through
it - you edit the request line, the headers and the body as text, in place.

Editing is modal (``e`` in, ``esc`` out) because mitmproxy's console is driven by
single-letter keys: an always-live text box would swallow ``r``, ``q`` and the
rest. The header says which mode you are in, and ``ctrl-r`` applies and sends in
one go from inside the editor, which is the Burp muscle memory that matters.
"""

from __future__ import annotations

import urwid
from mitmproxy.tools.console import layoutwidget

from burpmap import rawhttp
from burpmap import repeater as repeater_model
from burpmap.ui_common import GREY
from burpmap.ui_common import format_size
from burpmap.ui_common import method_attr
from burpmap.ui_common import short_ctype
from burpmap.ui_common import status_attr

MAX_BODY_LINES = 2000


def _header_markup(fields) -> list:
    out = []
    for name, value in fields:
        out.append(
            [
                ("header", name.decode("utf-8", "replace") + ": "),
                ("text", value.decode("utf-8", "replace")),
            ]
        )
    return out


def _body_markup(message) -> list:
    raw = message.get_content(strict=False) if message is not None else None
    if not raw:
        return []
    text = raw.decode(rawhttp.body_codec(raw), "replace")
    lines = text.splitlines()
    out = [[("text", line)] for line in lines[:MAX_BODY_LINES]]
    if len(lines) > MAX_BODY_LINES:
        out.append([(GREY, f"... {len(lines) - MAX_BODY_LINES} more lines")])
    return out


class Pane(urwid.Frame):
    """A titled, scrollable column."""

    def __init__(self) -> None:
        self.walker = urwid.SimpleListWalker([])
        self.box = urwid.ListBox(self.walker)
        self.title_text = urwid.Text("")
        super().__init__(self.box, header=urwid.AttrMap(self.title_text, "heading_inactive"))

    def set_title(self, markup) -> None:
        self.title_text.set_text(markup)

    def set_lines(self, lines) -> None:
        keep = 0
        if len(self.walker):
            try:
                keep = self.box.focus_position
            except IndexError:
                keep = 0
        self.walker[:] = [urwid.Text(line or "", wrap="any") for line in lines]
        if len(self.walker):
            self.box.focus_position = min(keep, len(self.walker) - 1)

    def set_widget(self, widget) -> None:
        self.walker[:] = [widget]
        self.box.focus_position = 0


class RepeaterView(urwid.Frame, layoutwidget.LayoutWidget):
    keyctx = "repeater"

    REQUEST, RESPONSE = 0, 2

    def __init__(self, master, repeater: repeater_model.Repeater) -> None:
        self.master = master
        self.repeater = repeater
        self._generation = -1
        self.editing = False
        self.editor: urwid.Edit | None = None
        self.edit_codec = "utf-8"
        self.message = ""

        self.strip = urwid.Text("")
        self.status = urwid.Text("")
        self.request_pane = Pane()
        self.response_pane = Pane()
        self.columns = urwid.Columns(
            [
                ("weight", 1, self.request_pane),
                (1, urwid.AttrMap(urwid.SolidFill("│"), GREY)),
                ("weight", 1, self.response_pane),
            ],
            dividechars=1,
            focus_column=self.REQUEST,
        )
        super().__init__(
            self.columns,
            header=urwid.Pile(
                [urwid.AttrMap(self.strip, "heading_inactive"), self.status]
            ),
        )
        self.rebuild(force=True)

    # ------------------------------------------------------------------ title

    @property
    def title(self) -> str:  # type: ignore[override]
        slot = self.repeater.current
        if slot is None:
            return "Repeater  (empty)"
        position = f"{self.repeater.index + 1}/{len(self.repeater.slots)}"
        state = "  -- EDITING --" if self.editing else ""
        return f"Repeater  slot {position}  {slot.name}  {slot.title()}{state}"

    # ---------------------------------------------------------------- editing

    def begin_edit(self) -> None:
        slot = self.repeater.current
        if slot is None:
            raise ValueError("The repeater is empty.")
        if slot.cursor >= 0:
            # Only the template is editable; a past send is a record of what was
            # actually sent. Step back to the template rather than refusing.
            slot.cursor = -1
            self.message = "showing the template"
        rawhttp.ensure_host_header(slot.flow.request)
        text, self.edit_codec = rawhttp.request_text(slot.flow.request)
        self.editor = urwid.Edit(edit_text=text, multiline=True, allow_tab=False)
        self.editing = True
        self.rebuild(force=True)
        self.columns.focus_position = self.REQUEST

    def commit_edit(self, update_content_length: bool = True) -> None:
        """Parse the editor text back onto the template. Raises ValueError."""
        if not self.editing or self.editor is None:
            return
        slot = self.repeater.current
        if slot is None:
            self.cancel_edit()
            return
        rawhttp.apply_text(
            slot.flow.request,
            self.editor.get_edit_text(),
            self.edit_codec,
            update_content_length,
        )
        self.editing, self.editor = False, None
        self.message = "applied"
        self.repeater._touch()
        self.rebuild(force=True)

    def cancel_edit(self) -> None:
        self.editing, self.editor = False, None
        self.message = "edit discarded"
        self.rebuild(force=True)

    # ---------------------------------------------------------------- refresh

    def view_changed(self) -> None:
        self.rebuild()

    def focus_changed(self) -> None:
        pass

    def layout_pushed(self, prev) -> None:
        self.rebuild(force=True)

    def rebuild(self, force: bool = False) -> None:
        if not force and self._generation == self.repeater.generation:
            # The response pane still has to follow a reply landing on a send.
            if not self._response_pending():
                return
        self._generation = self.repeater.generation
        self.strip.set_text(self._strip_markup())
        self.status.set_text(self._status_markup())
        self._fill_request()
        self._fill_response()

    def _response_pending(self) -> bool:
        slot = self.repeater.current
        return bool(slot and slot.history and slot.selected.response is None)

    def _strip_markup(self) -> list:
        if not self.repeater.slots:
            return [("text", " no slots - ctrl-r on a site map row or a flow ")]
        out: list = [" "]
        for index, slot in enumerate(self.repeater.slots):
            label = f" {slot.name} {slot.title()} "
            out.append(("heading" if index == self.repeater.index else GREY, label))
            out.append(" ")
        return out

    def _status_markup(self) -> list:
        slot = self.repeater.current
        if slot is None:
            return [(GREY, " ctrl-r on a site map row, or on a flow, makes a slot.")]
        out: list = [" "]
        if slot.history:
            out.append((GREY, "sends: "))
            for index, sent in enumerate(slot.history):
                if sent.error:
                    label, attr = "err", "error"
                elif sent.response is not None:
                    label = str(sent.response.status_code)
                    attr = status_attr(sent.response.status_code)
                else:
                    label, attr = "...", "warn"
                out.append((attr, f"[{label}]" if index == slot.cursor else f" {label} "))
            out.append("  ")
        if self.editing:
            out.append(("alert", "-- EDITING --"))
            out.append((GREY, "  esc apply   ctrl-r apply+send   ctrl-x discard"))
        if self.message:
            out.append((GREY, f"   {self.message}"))
        return out

    def _fill_request(self) -> None:
        slot = self.repeater.current
        if slot is None:
            self.request_pane.set_title(" Request")
            self.request_pane.set_lines([[(GREY, " The repeater is empty.")]])
            return

        if self.editing and self.editor is not None:
            codec = "" if self.edit_codec == "utf-8" else f"  [{self.edit_codec}]"
            self.request_pane.set_title(
                [("alert", " Request (editing)"), (GREY, codec)]
            )
            self.request_pane.set_widget(self.editor)
            return

        showing_template = slot.cursor < 0 or not slot.history
        label = "template" if showing_template else f"send {slot.cursor + 1}"
        self.request_pane.set_title(
            [("heading_key", " Request "), (GREY, f"({label})")]
        )
        request = slot.selected.request
        lines = [
            [
                (method_attr(request.method), request.method),
                ("text", " "),
                ("url_filename", request.path or "/"),
                (GREY, f" {request.http_version}"),
            ]
        ]
        lines += _header_markup(request.headers.fields)
        body = _body_markup(request)
        if body:
            lines.append([])
            lines += body
        self.request_pane.set_lines(lines)

    def _fill_response(self) -> None:
        slot = self.repeater.current
        if slot is None:
            self.response_pane.set_title(" Response")
            self.response_pane.set_lines([])
            return

        flow = slot.selected
        response = flow.response
        if flow.error:
            self.response_pane.set_title([("error", " Response (error)")])
            self.response_pane.set_lines([[("error", f" {flow.error.msg}")]])
            return
        if response is None:
            if flow.id in self.repeater.inflight:
                self.response_pane.set_title([("warn", " Response (in flight)")])
                self.response_pane.set_lines([[("warn", " waiting...")]])
            else:
                self.response_pane.set_title([(GREY, " Response (none)")])
                self.response_pane.set_lines([[(GREY, " not sent yet - press r")]])
            return

        bits = [("heading_key", " Response  "), (status_attr(response.status_code), str(response.status_code))]
        raw = response.raw_content
        if raw is not None:
            bits.append((GREY, f"  {format_size(len(raw))}"))
        elapsed = self._elapsed(flow)
        if elapsed:
            bits.append((GREY, f"  {elapsed}"))
        self.response_pane.set_title(bits)

        lines = [
            [
                (GREY, f"{response.http_version} "),
                (status_attr(response.status_code), str(response.status_code)),
                ("text", f" {response.reason}"),
            ]
        ]
        lines += _header_markup(response.headers.fields)
        body = _body_markup(response)
        if body:
            lines.append([])
            lines += body
        self.response_pane.set_lines(lines)

    @staticmethod
    def _elapsed(flow) -> str:
        start = flow.request.timestamp_start if flow.request else None
        end = flow.response.timestamp_end if flow.response else None
        if not start or not end or end < start:
            return ""
        return f"{(end - start) * 1000:.0f}ms"

    # --------------------------------------------------------------- keypress

    def switch_pane(self) -> None:
        self.columns.focus_position = (
            self.RESPONSE if self.columns.focus_position == self.REQUEST else self.REQUEST
        )

    def keypress(self, size, key):
        # esc has to be caught before anything else while editing: globally it
        # pops the page, which would silently throw the edit away.
        if self.editing:
            if key == "esc":
                try:
                    self.commit_edit()
                except ValueError as exc:
                    self.message = f"not applied: {exc}"
                    self.rebuild(force=True)
                return None
            # ctrl-x is the advertised one: depending on the terminal, ctrl-c
            # may never reach the application at all.
            if key in ("ctrl x", "ctrl c"):
                self.cancel_edit()
                return None
        if key == "m_next":  # tab
            self.switch_pane()
            return None
        if key in ("m_start", "m_end"):
            pane = (
                self.request_pane
                if self.columns.focus_position == self.REQUEST
                else self.response_pane
            )
            if len(pane.walker):
                pane.box.focus_position = 0 if key == "m_start" else len(pane.walker) - 1
            return None
        return super().keypress(size, key)
