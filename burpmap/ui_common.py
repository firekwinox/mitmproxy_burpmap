"""Small rendering helpers shared by the site map and repeater pages.

Everything resolves to attribute names that already exist in
``mitmproxy.tools.console.palettes.Palette._fields``, so all six built-in themes
keep working without us registering any colours of our own.
"""

from __future__ import annotations

from mitmproxy.tools.console import palettes

GREY = "url_punctuation"

# The highlight for the row the cursor is on. "focus" is a foreground colour with
# a default background in every built-in theme - it is what mitmproxy's flow list
# uses to tint its ">>" marker, not to fill a row - so it is invisible as a row
# highlight, and in the "dark" theme it is black on black. "option_selected" is
# the entry that actually carries a background, and it is what the options page
# uses for exactly this job.
FOCUS_ATTR = "option_selected"

# AttrMap given a bare string builds {None: attr}, which only recolours runs that
# carry no attribute of their own. Every run we emit is attributed, so the map has
# to name them all; listing the whole palette keeps it correct as rows change.
FOCUS_MAP: dict = {name: FOCUS_ATTR for name in palettes.Palette._fields}
FOCUS_MAP[None] = FOCUS_ATTR

_METHOD_ATTRS = {
    "GET": "method_get",
    "POST": "method_post",
    "PUT": "method_put",
    "HEAD": "method_head",
    "DELETE": "method_delete",
}


def method_attr(method: str) -> str:
    return _METHOD_ATTRS.get(method.upper(), "method_other")


def status_attr(status: int | None) -> str:
    if status is None:
        return "text"
    if 200 <= status < 300:
        return "code_200"
    if 300 <= status < 400:
        return "code_300"
    if 400 <= status < 500:
        return "code_400"
    if 500 <= status < 600:
        return "code_500"
    return "code_other"


def format_size(size: int | None) -> str:
    if size is None:
        return ""
    for unit in ("b", "k", "m", "g"):
        if size < 1024 or unit == "g":
            if unit == "b":
                return f"{size}b"
            return f"{size:.1f}{unit}"
        size /= 1024.0
    return ""


def short_ctype(ctype: str) -> str:
    """Drop the uninformative half of a MIME type: application/json -> json."""
    if not ctype:
        return ""
    if "/" in ctype:
        major, minor = ctype.split("/", 1)
        if major in ("application", "text"):
            return minor.removeprefix("x-")
        return ctype
    return ctype
