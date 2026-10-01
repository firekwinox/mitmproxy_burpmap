"""Raw HTTP text <-> mitmproxy Request, for the repeater's text editor.

Burp's repeater is a text box holding the literal request, and that is what
people reach for. mitmproxy stores a structured Request, so the two directions
live here: render one as the wire text, and parse edited text back.
"""

from __future__ import annotations

from mitmproxy import http
from mitmproxy.http import Headers
from mitmproxy.net.http import http1

# A body that is not valid UTF-8 still has to survive a round trip through the
# editor untouched. latin-1 maps every byte to exactly one code point, so it is
# lossless for arbitrary bytes - at the cost of showing mojibake for real text,
# which is why UTF-8 is tried first.
BINARY_CODEC = "latin-1"


def body_codec(raw: bytes) -> str:
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return BINARY_CODEC
    return "utf-8"


def host_header_for(request: http.Request) -> str:
    """What the Host header should say, port included when it is not the default."""
    default = {"http": 80, "https": 443}.get(request.scheme)
    if request.port == default:
        return request.host
    return f"{request.host}:{request.port}"


def ensure_host_header(request: http.Request) -> None:
    """Requests built by Request.make carry no Host header; the editor needs one."""
    if not request.headers.get("host"):
        request.headers["Host"] = host_header_for(request)


def request_text(request: http.Request) -> tuple[str, str]:
    """The request as wire text, plus the codec its body was decoded with.

    The request line is origin-form (``GET /path HTTP/1.1``), like Burp and like
    what actually goes on the wire, with the target carried by the Host header.
    """
    target = request.path or "/"
    lines = [f"{request.method} {target} {request.http_version}"]
    for name, value in request.headers.fields:
        lines.append(
            f"{name.decode('utf-8', 'replace')}: {value.decode('utf-8', 'replace')}"
        )
    raw = request.get_content(strict=False) or b""
    codec = body_codec(raw)
    return "\n".join(lines) + "\n\n" + raw.decode(codec, "replace"), codec


def response_text(response: http.Response) -> str:
    lines = [f"{response.http_version} {response.status_code} {response.reason}"]
    for name, value in response.headers.fields:
        lines.append(
            f"{name.decode('utf-8', 'replace')}: {value.decode('utf-8', 'replace')}"
        )
    raw = response.get_content(strict=False) or b""
    return "\n".join(lines) + "\n\n" + raw.decode(body_codec(raw), "replace")


def _split_head_and_body(text: str) -> tuple[list[bytes], str]:
    normalised = text.replace("\r\n", "\n")
    head, separator, body = normalised.partition("\n\n")
    if not separator:
        head, body = normalised, ""
    lines = [line.encode("utf-8", "surrogateescape") for line in head.split("\n") if line.strip()]
    return lines, body


def apply_text(
    request: http.Request, text: str, codec: str = "utf-8", update_content_length: bool = True
) -> None:
    """Parse edited wire text and write it over ``request``.

    Raises ValueError with a readable message if the text is not a request.
    """
    lines, body = _split_head_and_body(text)
    if not lines:
        raise ValueError("The request is empty.")

    parsed = http1.read_request_head(lines)  # raises ValueError on a bad head

    # Snapshot the typed headers now. Assigning request.headers shares the object
    # rather than copying it, so setting content later would rewrite the very
    # Content-Length we are trying to remember.
    typed_fields = list(parsed.headers.fields)

    previous_host, previous_port = request.host, request.port
    request.method = parsed.method
    request.http_version = parsed.http_version
    request.headers = parsed.headers

    if parsed.scheme:
        # absolute-form request line: the user retargeted the request outright
        request.scheme = parsed.scheme
        request.host = parsed.host
        request.port = parsed.port
    else:
        host_header = parsed.headers.get("host", "")
        if host_header:
            host, _, port = host_header.rpartition(":")
            if host and port.isdigit():
                request.host, request.port = host, int(port)
            else:
                request.host = host_header
                if host_header != previous_host:
                    request.port = {"http": 80, "https": 443}.get(
                        request.scheme, previous_port
                    )
    request.path = parsed.path

    try:
        content = body.encode(codec)
    except UnicodeEncodeError:
        content = body.encode("utf-8", "surrogateescape")

    # Message.content rewrites Content-Length on assignment, so the headers are
    # put back field by field afterwards. Going through .fields rather than
    # .get/.set keeps duplicated or contradictory framing headers verbatim -
    # two Content-Lengths, or one next to Transfer-Encoding, is a smuggling
    # test, not a typo to be helpfully corrected.
    request.content = content

    fields = list(typed_fields)
    has_length = any(name.lower() == b"content-length" for name, _ in fields)
    has_chunked = any(name.lower() == b"transfer-encoding" for name, _ in fields)

    if update_content_length and not has_chunked:
        true_length = str(len(content)).encode()
        if has_length:
            fields = [
                (name, true_length if name.lower() == b"content-length" else value)
                for name, value in fields
            ]
        elif content:
            fields.append((b"content-length", true_length))
    request.headers = Headers(fields)
