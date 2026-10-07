"""Repeater slots: an editable request template plus the history of its sends.

The template flow is deliberately kept inside ``master.view`` so that mitmproxy's
own editors (``console.edit.focus``, the grid editors, the external $EDITOR hook)
work on it unchanged. Re-implementing a request editor in urwid would be a lot of
code to end up worse than the one already there.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Optional
from urllib.parse import urlsplit

from mitmproxy.http import Headers

from burpmap import hackvertor
from burpmap import rawhttp

logger = logging.getLogger(__name__)

MARKER = ":repeat:"


@dataclass(eq=False)
class Slot:
    name: str
    flow: Any  # the editable template
    history: list[Any] = field(default_factory=list)  # one copy per send
    cursor: int = -1  # -1 shows the template, otherwise an index into history

    @property
    def selected(self) -> Any:
        if 0 <= self.cursor < len(self.history):
            return self.history[self.cursor]
        return self.flow

    def title(self) -> str:
        request = self.flow.request
        path = urlsplit(request.pretty_url).path or "/"
        return f"{request.method} {path}"

    def summary(self) -> str:
        if not self.history:
            return "not sent"
        codes = []
        for sent in self.history[-6:]:
            if sent.error:
                codes.append("err")
            elif sent.response is not None:
                codes.append(str(sent.response.status_code))
            else:
                codes.append("...")
        return f"{len(self.history)} sent: " + " ".join(codes)


def expand_tags(request: Any) -> None:
    """Expand Hackvertor tags in the path, header values and body, in place."""
    request.data.path = hackvertor.process(request.data.path)
    fields = [(name, hackvertor.process(value)) for name, value in request.headers.fields]
    if fields != list(request.headers.fields):
        request.headers = Headers(fields)

    body = request.get_content(strict=False)
    if not body or not hackvertor.has_tags(body):
        return
    # Setting content rewrites Content-Length. That is wanted when it matched
    # the template body, but a single wrong one, or several, was typed on
    # purpose (a smuggling test) and goes out as typed.
    lengths = request.headers.get_all("content-length")
    deliberate = len(lengths) > 1 or (
        len(lengths) == 1 and lengths[0].strip() != str(len(request.raw_content or b""))
    )
    typed = list(request.headers.fields)
    request.content = hackvertor.process(body)
    if deliberate:
        request.headers = Headers(typed)


class Repeater:
    def __init__(self) -> None:
        self.slots: list[Slot] = []
        self.index = 0
        self.generation = 0
        # flow id -> slot, so the response hook can refresh the right page
        self.inflight: dict[str, Slot] = {}
        self._counter = 0

    def _touch(self) -> None:
        self.generation += 1

    @property
    def current(self) -> Optional[Slot]:
        if not self.slots:
            return None
        self.index = max(0, min(self.index, len(self.slots) - 1))
        return self.slots[self.index]

    def add(self, flow: Any, name: str = "") -> Slot:
        """Create a slot holding an editable copy of ``flow``."""
        template = flow.copy()
        template.live = False
        template.response = None
        template.error = None
        template.is_replay = None
        template.marked = MARKER
        template.comment = "burpmap repeater template"
        # The raw-text editor needs a Host line; synthesized requests have none.
        rawhttp.ensure_host_header(template.request)
        self._counter += 1
        slot = Slot(name=name or f"#{self._counter}", flow=template)
        self.slots.append(slot)
        self.index = len(self.slots) - 1
        self._touch()
        return slot

    def remove(self, slot: Slot) -> None:
        if slot in self.slots:
            self.slots.remove(slot)
        for flow_id, pending in list(self.inflight.items()):
            if pending is slot:
                del self.inflight[flow_id]
        self.index = max(0, min(self.index, len(self.slots) - 1))
        self._touch()

    def prepare_send(self, slot: Slot) -> Any:
        """Snapshot the template into a fresh flow, ready to hand to replay.client.

        ``replay.client`` clears and rewrites the response on the flow it is given,
        so sending a copy is what makes a per-slot send history possible at all.

        Hackvertor tags are expanded on the copy only, so the template keeps
        them. A malformed tag raises hackvertor.TagError before anything is
        recorded.
        """
        sent = slot.flow.copy()
        sent.live = False
        sent.response = None
        sent.error = None
        sent.marked = MARKER
        sent.comment = f"burpmap repeater {slot.name} send {len(slot.history) + 1}"
        expand_tags(sent.request)
        slot.history.append(sent)
        slot.cursor = len(slot.history) - 1
        self.inflight[sent.id] = slot
        self._touch()
        return sent

    def resolve(self, flow: Any) -> Optional[Slot]:
        """Called from the response/error hook; returns the slot that was waiting."""
        slot = self.inflight.pop(flow.id, None)
        if slot is not None:
            self._touch()
        else:
            # This can happen if a flow is resolved twice (e.g., error then response)
            logger.debug("burpmap: flow %s resolved but was not in inflight tracking", flow.id)
        return slot

    def owns(self, flow: Any) -> bool:
        """Is this flow a repeater template or a repeater send?"""
        for slot in self.slots:
            if flow is slot.flow or flow.id == slot.flow.id:
                return True
            for sent in slot.history:
                if flow is sent or flow.id == sent.id:
                    return True
        return False

    def select(self, offset: int) -> None:
        if self.slots:
            self.index = (self.index + offset) % len(self.slots)
            self._touch()

    def scroll_history(self, offset: int) -> None:
        slot = self.current
        if slot is None or not slot.history:
            return
        cursor = slot.cursor if slot.cursor >= 0 else len(slot.history) - 1
        slot.cursor = max(0, min(cursor + offset, len(slot.history) - 1))
        self._touch()

    def clear(self) -> None:
        self.slots.clear()
        self.inflight.clear()
        self.index = 0
        self._counter = 0
        self._touch()
