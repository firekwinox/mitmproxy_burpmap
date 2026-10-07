"""Hackvertor-style tags, expanded when a repeater request is sent.

The template keeps the tags, so a request can be edited and resent with the
payload written in clear. Tags use Hackvertor's syntax and nest, innermost
first::

    <@urlencode>hello world<@/urlencode>                          ->  hello%20world
    <@urlencode><@base64encode>test<@/base64encode><@/urlencode>  ->  dGVzdA%3D%3D

Everything works on bytes, so a decode that yields binary (``<@base64decode>/w==``)
puts the raw byte on the wire rather than failing on UTF-8.

Only known tag names are tags: ``<@foo>`` is left as it is. A known tag that is
unclosed, closed by the wrong tag, or whose content does not decode raises
TagError - sending the literal tag instead would be a silent wrong request.
"""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from typing import Callable

MAX_DEPTH = 64


class TagError(ValueError):
    pass


def _base64decode(data: bytes) -> bytes:
    try:
        return base64.b64decode(data, validate=True)
    except binascii.Error as exc:
        raise TagError(f"base64decode: not base64 ({exc})") from None


TRANSFORMS: dict[str, Callable[[bytes], bytes]] = {
    "urlencode": lambda b: urllib.parse.quote_from_bytes(b, safe="").encode("ascii"),
    "urldecode": urllib.parse.unquote_to_bytes,
    "base64encode": base64.b64encode,
    "base64decode": _base64decode,
}

TAG = re.compile(rb"<@(/?)([a-z0-9_]+)>")


def has_tags(data: bytes) -> bool:
    return any(m.group(2).decode() in TRANSFORMS for m in TAG.finditer(data))


def process(data: bytes) -> bytes:
    """Expand every tag in ``data``. Raises TagError on a malformed tag."""
    # Each stack frame is (tag name, chunks collected inside it); the bottom
    # frame is the top level and has no name.
    stack: list[tuple[str, list[bytes]]] = [("", [])]
    pos = 0
    for match in TAG.finditer(data):
        closing, name = match.group(1), match.group(2).decode()
        if name not in TRANSFORMS:
            continue
        stack[-1][1].append(data[pos : match.start()])
        pos = match.end()
        if not closing:
            if len(stack) > MAX_DEPTH:
                raise TagError(f"tags nested deeper than {MAX_DEPTH}")
            stack.append((name, []))
            continue
        open_name, chunks = stack.pop() if len(stack) > 1 else ("", [])
        if open_name != name:
            expected = f"<@/{open_name}>" if open_name else "no closing tag"
            raise TagError(f"<@/{name}> found where {expected} was expected")
        stack[-1][1].append(TRANSFORMS[name](b"".join(chunks)))
    if len(stack) > 1:
        raise TagError(f"<@{stack[-1][0]}> is never closed")
    stack[0][1].append(data[pos:])
    return b"".join(stack[0][1])
