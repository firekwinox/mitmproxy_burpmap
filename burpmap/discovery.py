"""Pull URIs out of responses so the site map can show what has *not* been visited.

Everything here is stdlib: the mitmproxy virtualenv has no BeautifulSoup or lxml,
and an addon that needs extra packages installed is an addon people will not run.
``html.parser`` is lenient enough for real-world markup.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urldefrag
from urllib.parse import urljoin
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

from burpmap.model import DEFAULT_PORTS

# Sources that can be named in the `sitemap_discovery` option.
SOURCES = ("html", "js", "json", "headers")

SKIP_SCHEMES = ("javascript:", "mailto:", "tel:", "data:", "about:", "blob:", "#")

# tag -> attributes that hold a single URL
_URL_ATTRS: dict[str, tuple[str, ...]] = {
    "a": ("href",),
    "area": ("href",),
    "link": ("href",),
    "script": ("src",),
    "img": ("src", "longdesc"),
    "iframe": ("src",),
    "frame": ("src",),
    "embed": ("src",),
    "source": ("src",),
    "track": ("src",),
    "audio": ("src",),
    "video": ("src", "poster"),
    "object": ("data",),
    "input": ("formaction",),
    "button": ("formaction",),
}
# Attributes worth reading on any tag at all.
_GENERIC_ATTRS = ("data-url", "data-href", "data-src", "data-endpoint", "data-action")

# Quoted absolute URLs and rooted paths inside script/JSON bodies.
_JS_URL = re.compile(
    r"""['"`](https?://[^'"`\s<>\\]{3,2048}|/[^'"`\s<>\\]{0,2048})['"`]"""
)
# Things that are shaped like a path but are not one.
_JS_REJECT = re.compile(r"[\s${}\\]|%[sdv]|^/[*/]|^/$")
_MIME_LIKE = re.compile(r"^/(?:[a-z0-9.+-]+)$", re.I)
_CSS_URL = re.compile(r"""url\(\s*['"]?([^'")\s]{1,2048})['"]?\s*\)""")
_REFRESH_URL = re.compile(r"url\s*=\s*['\"]?([^'\";]+)", re.I)
_LINK_HEADER = re.compile(r"<([^>]{1,2048})>")


def normalise(url: str) -> str:
    """Canonical form: lowercase scheme/host, no default port, no fragment."""
    url, _ = urldefrag(url)
    u = urlsplit(url)
    scheme = u.scheme.lower()
    host = (u.hostname or "").lower()
    if not host:
        return ""
    try:
        port = u.port
    except ValueError:
        return ""
    netloc = host
    if port is not None and port != DEFAULT_PORTS.get(scheme):
        netloc = f"{host}:{port}"
    if u.username:
        userinfo = u.username + (f":{u.password}" if u.password else "")
        netloc = f"{userinfo}@{netloc}"
    return urlunsplit((scheme, netloc, u.path or "/", u.query, ""))


def _resolve(base: str, link: str) -> str:
    link = link.strip()
    if not link:
        return ""
    lowered = link.lower()
    if lowered.startswith(SKIP_SCHEMES):
        return ""
    try:
        absolute = urljoin(base, link)
    except ValueError:
        return ""
    if not absolute.lower().startswith(("http://", "https://")):
        return ""
    return normalise(absolute)


class _LinkParser(HTMLParser):
    """Collects (method, raw link) pairs and the text of inline <script> blocks."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.base: str = ""
        self.scripts: list[str] = []
        self.styles: list[str] = []
        self._capture: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("script", "style") and "src" not in values:
            self._capture = tag

        if tag == "base" and values.get("href") and not self.base:
            self.base = values["href"]
            return

        if tag == "form":
            action = values.get("action", "")
            method = (values.get("method") or "GET").upper()
            if method not in ("GET", "POST"):
                method = "GET"
            # An empty action posts back to the current page; the caller resolves
            # "" against the page URL for us.
            self.links.append((method, action))

        for attr in _URL_ATTRS.get(tag, ()):
            if values.get(attr):
                self.links.append(("GET", values[attr]))

        for attr in _GENERIC_ATTRS:
            if values.get(attr):
                self.links.append(("GET", values[attr]))

        if values.get("srcset"):
            for candidate in values["srcset"].split(","):
                url = candidate.strip().split(" ")[0]
                if url:
                    self.links.append(("GET", url))

        if tag == "meta" and values.get("http-equiv", "").lower() == "refresh":
            m = _REFRESH_URL.search(values.get("content", ""))
            if m:
                self.links.append(("GET", m.group(1)))

    def handle_startendtag(self, tag, attrs) -> None:
        self.handle_starttag(tag, attrs)
        self._capture = None

    def handle_endtag(self, tag: str) -> None:
        if self._capture == tag:
            self._capture = None

    def handle_data(self, data: str) -> None:
        if self._capture == "script":
            self.scripts.append(data)
        elif self._capture == "style":
            self.styles.append(data)


def _sweep_text(text: str, limit: int) -> list[str]:
    """Regex-scrape quoted URLs and rooted paths out of script or JSON text."""
    found: list[str] = []
    for match in _JS_URL.finditer(text):
        candidate = match.group(1)
        if _JS_REJECT.search(candidate):
            continue
        if candidate.startswith("/") and _MIME_LIKE.match(candidate):
            # "application/json", "text/html" and friends come through as "/json".
            continue
        found.append(candidate)
        if len(found) >= limit:
            break
    return found


def extract_html(body: str, base_url: str, limit: int, sweep_inline: bool) -> list[tuple[str, str]]:
    parser = _LinkParser()
    try:
        parser.feed(body)
        parser.close()
    except Exception:
        # html.parser can raise on pathological input; keep whatever we got.
        pass

    base = _resolve(base_url, parser.base) if parser.base else base_url
    if not base:
        base = base_url

    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def push(method: str, raw: str) -> None:
        url = _resolve(base, raw) if raw else normalise(base)
        if not url:
            return
        pair = (method, url)
        if pair not in seen:
            seen.add(pair)
            out.append(pair)

    for method, raw in parser.links:
        push(method, raw)
        if len(out) >= limit:
            return out

    if sweep_inline:
        for chunk in parser.scripts:
            for raw in _sweep_text(chunk, limit):
                push("GET", raw)
        for chunk in parser.styles:
            for match in _CSS_URL.finditer(chunk):
                push("GET", match.group(1))
    return out[:limit]


def extract_headers(flow, limit: int) -> list[tuple[str, str]]:
    response = flow.response
    base = flow.request.pretty_url
    out: list[tuple[str, str]] = []
    for header in ("location", "content-location"):
        value = response.headers.get(header)
        if value:
            url = _resolve(base, value)
            if url:
                out.append(("GET", url))
    refresh = response.headers.get("refresh")
    if refresh:
        m = _REFRESH_URL.search(refresh)
        if m:
            url = _resolve(base, m.group(1))
            if url:
                out.append(("GET", url))
    link = response.headers.get("link")
    if link:
        for m in _LINK_HEADER.finditer(link):
            url = _resolve(base, m.group(1))
            if url:
                out.append(("GET", url))
    return out[:limit]


def _content_type(flow) -> str:
    return (flow.response.headers.get("content-type", "") or "").split(";")[0].strip().lower()


def extract(
    flow,
    sources=("html", "js", "json"),
    max_body: int = 2 * 1024 * 1024,
    max_links: int = 500,
) -> list[tuple[str, str]]:
    """Return (method, absolute URL) pairs referenced by this response."""
    response = getattr(flow, "response", None)
    if response is None:
        return []

    results: list[tuple[str, str]] = []
    if "headers" in sources:
        results.extend(extract_headers(flow, max_links))

    raw = response.raw_content
    if raw is None or len(raw) > max_body:
        return _dedupe(results, max_links)

    ctype = _content_type(flow)
    is_html = ctype in ("text/html", "application/xhtml+xml")
    is_js = "javascript" in ctype or "ecmascript" in ctype
    is_json = "json" in ctype

    want_html = is_html and "html" in sources
    want_js = is_js and "js" in sources
    want_json = is_json and "json" in sources
    if not (want_html or want_js or want_json):
        return _dedupe(results, max_links)

    try:
        body = response.get_text(strict=False) or ""
    except Exception:
        return _dedupe(results, max_links)

    base = flow.request.pretty_url
    if want_html:
        results.extend(
            extract_html(body, base, max_links, sweep_inline="js" in sources)
        )
    else:
        for raw_url in _sweep_text(body, max_links):
            url = _resolve(base, raw_url)
            if url:
                results.append(("GET", url))
    return _dedupe(results, max_links)


def _dedupe(pairs, limit: int) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for pair in pairs:
        if pair in seen:
            continue
        seen.add(pair)
        out.append(pair)
        if len(out) >= limit:
            break
    return out
