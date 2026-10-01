import unittest

from mitmproxy.test import tflow

from burpmap import rawhttp


def request(path="/api/login", method="POST", scheme="https", host="ex.com", port=443):
    flow = tflow.tflow()
    r = flow.request
    r.method, r.scheme, r.host, r.port, r.path = method, scheme, host, port, path
    r.headers.clear()
    r.headers["Content-Type"] = "application/json"
    rawhttp.ensure_host_header(r)
    r.content = b'{"u":"a"}'
    return r


class TestRender(unittest.TestCase):
    def test_request_line_is_origin_form(self):
        text, _ = rawhttp.request_text(request())
        self.assertTrue(text.startswith("POST /api/login HTTP/1.1\n"))

    def test_headers_keep_their_order_and_case(self):
        r = request()
        r.headers.clear()
        r.headers["X-Zed"] = "1"
        r.headers["AAA"] = "2"
        text, _ = rawhttp.request_text(r)
        self.assertIn("X-Zed: 1\nAAA: 2", text)

    def test_body_follows_a_blank_line(self):
        text, _ = rawhttp.request_text(request())
        head, _, body = text.partition("\n\n")
        self.assertEqual(body, '{"u":"a"}')

    def test_host_header_carries_a_non_default_port(self):
        r = request(port=8443)
        self.assertEqual(r.headers["Host"], "ex.com:8443")

    def test_host_header_omits_a_default_port(self):
        self.assertEqual(request(port=443).headers["Host"], "ex.com")

    def test_ensure_host_header_does_not_overwrite(self):
        r = request()
        r.headers["Host"] = "spoofed.example"
        rawhttp.ensure_host_header(r)
        self.assertEqual(r.headers["Host"], "spoofed.example")


class TestRoundTrip(unittest.TestCase):
    def test_unchanged_text_changes_nothing(self):
        r = request()
        before = (r.method, r.pretty_url, r.content, list(r.headers.fields))
        text, codec = rawhttp.request_text(r)
        rawhttp.apply_text(r, text, codec)
        self.assertEqual(
            (r.method, r.pretty_url, r.content, list(r.headers.fields)), before
        )

    def test_binary_body_survives(self):
        r = request()
        r.content = bytes(range(256))
        text, codec = rawhttp.request_text(r)
        self.assertEqual(codec, rawhttp.BINARY_CODEC)
        rawhttp.apply_text(r, text, codec, update_content_length=False)
        self.assertEqual(r.content, bytes(range(256)))

    def test_blank_lines_inside_the_body_are_kept(self):
        r = request()
        r.content = b"one\n\ntwo\n\nthree"
        text, codec = rawhttp.request_text(r)
        rawhttp.apply_text(r, text, codec)
        self.assertEqual(r.content, b"one\n\ntwo\n\nthree")

    def test_crlf_input_is_accepted(self):
        r = request()
        rawhttp.apply_text(r, "GET /x HTTP/1.1\r\nHost: ex.com\r\n\r\n")
        self.assertEqual(r.path, "/x")


class TestEdits(unittest.TestCase):
    def test_path_change(self):
        r = request()
        text, codec = rawhttp.request_text(r)
        rawhttp.apply_text(r, text.replace("/api/login", "/api/admin"), codec)
        self.assertEqual(r.path, "/api/admin")
        self.assertEqual(r.pretty_url, "https://ex.com/api/admin")

    def test_method_change(self):
        r = request()
        text, codec = rawhttp.request_text(r)
        rawhttp.apply_text(r, text.replace("POST ", "PUT ", 1), codec)
        self.assertEqual(r.method, "PUT")

    def test_adding_a_header(self):
        r = request()
        text, codec = rawhttp.request_text(r)
        edited = text.replace("\nContent-Type:", "\nX-New: yes\nContent-Type:")
        rawhttp.apply_text(r, edited, codec)
        self.assertEqual(r.headers["X-New"], "yes")

    def test_removing_a_header(self):
        r = request()
        text, codec = rawhttp.request_text(r)
        edited = "\n".join(
            l for l in text.split("\n") if not l.startswith("Content-Type:")
        )
        rawhttp.apply_text(r, edited, codec)
        self.assertNotIn("content-type", r.headers)

    def test_host_header_change_retargets_the_request(self):
        r = request()
        text, codec = rawhttp.request_text(r)
        rawhttp.apply_text(r, text.replace("Host: ex.com", "Host: other.test:8443"), codec)
        self.assertEqual((r.host, r.port), ("other.test", 8443))
        self.assertEqual(r.scheme, "https")

    def test_host_header_without_a_port_uses_the_scheme_default(self):
        r = request(port=8443)
        text, codec = rawhttp.request_text(r)
        rawhttp.apply_text(r, text.replace("Host: ex.com:8443", "Host: other.test"), codec)
        self.assertEqual((r.host, r.port), ("other.test", 443))

    def test_absolute_form_request_line_retargets_everything(self):
        r = request()
        text, codec = rawhttp.request_text(r)
        edited = text.replace("POST /api/login", "POST http://elsewhere.test:8080/x", 1)
        rawhttp.apply_text(r, edited, codec)
        self.assertEqual((r.scheme, r.host, r.port, r.path),
                         ("http", "elsewhere.test", 8080, "/x"))

    def test_http_version_change(self):
        r = request()
        text, codec = rawhttp.request_text(r)
        rawhttp.apply_text(r, text.replace("HTTP/1.1", "HTTP/1.0", 1), codec)
        self.assertEqual(r.http_version, "HTTP/1.0")


class TestContentLength(unittest.TestCase):
    def test_recomputed_by_default(self):
        r = request()
        text, codec = rawhttp.request_text(r)
        rawhttp.apply_text(r, text.replace('{"u":"a"}', '{"u":"administrator"}'), codec)
        self.assertEqual(r.headers["content-length"], str(len(r.content)))

    def test_left_alone_when_switched_off(self):
        # Sending a deliberately wrong Content-Length is the point of the option.
        r = request()
        text, codec = rawhttp.request_text(r)
        edited = text.replace("content-length: 9", "content-length: 9999")
        rawhttp.apply_text(r, edited, codec, update_content_length=False)
        self.assertEqual(r.headers["content-length"], "9999")

    def test_not_invented_for_a_bodyless_request(self):
        r = request()
        rawhttp.apply_text(r, "GET /x HTTP/1.1\nHost: ex.com\n\n")
        self.assertNotIn("content-length", r.headers)


class TestMalformed(unittest.TestCase):
    def apply(self, text):
        rawhttp.apply_text(request(), text)

    def test_empty(self):
        with self.assertRaises(ValueError) as cm:
            self.apply("")
        self.assertIn("empty", str(cm.exception))

    def test_only_whitespace(self):
        with self.assertRaises(ValueError):
            self.apply("\n\n\n")

    def test_garbage_request_line(self):
        with self.assertRaises(ValueError) as cm:
            self.apply("nonsense\n\n")
        self.assertIn("request line", str(cm.exception))

    def test_truncated_request_line(self):
        with self.assertRaises(ValueError):
            self.apply("GET\n\n")

    def test_the_request_is_untouched_when_parsing_fails(self):
        r = request()
        before = (r.method, r.path, r.content)
        with self.assertRaises(ValueError):
            rawhttp.apply_text(r, "nonsense\n\nbody")
        self.assertEqual((r.method, r.path, r.content), before)


class TestResponseRender(unittest.TestCase):
    def test_status_line_headers_and_body(self):
        flow = tflow.tflow(resp=True)
        flow.response.headers["content-type"] = "text/html"
        flow.response.content = b"<html>hi</html>"
        text = rawhttp.response_text(flow.response)
        self.assertTrue(text.startswith("HTTP/1.1 200 "))
        self.assertIn("content-type: text/html", text)
        self.assertTrue(text.endswith("<html>hi</html>"))


if __name__ == "__main__":
    unittest.main()


class TestFramingHeaders(unittest.TestCase):
    """Content-Length and Transfer-Encoding have to stay under the user's control.

    Message.content rewrites Content-Length on assignment, so these need explicit
    handling - and a mismatched length is a deliberate test, not a mistake.
    """

    def test_transfer_encoding_suppresses_the_recomputed_length(self):
        r = request()
        rawhttp.apply_text(
            r,
            "POST /x HTTP/1.1\nHost: ex.com\nTransfer-Encoding: chunked\n\n0\n\n",
            update_content_length=True,
        )
        self.assertNotIn("content-length", r.headers)
        self.assertEqual(r.headers["transfer-encoding"], "chunked")

    def test_both_framing_headers_can_coexist(self):
        r = request()
        rawhttp.apply_text(
            r,
            "POST /x HTTP/1.1\nHost: ex.com\nContent-Length: 6\n"
            "Transfer-Encoding: chunked\n\n0\n\nG",
            update_content_length=True,
        )
        self.assertEqual(r.headers["content-length"], "6")
        self.assertEqual(r.headers["transfer-encoding"], "chunked")

    def test_a_deliberately_short_length_is_preserved(self):
        r = request()
        rawhttp.apply_text(
            r,
            "POST /x HTTP/1.1\nHost: ex.com\nContent-Length: 3\n\nmuch longer body",
            update_content_length=False,
        )
        self.assertEqual(r.headers["content-length"], "3")
        self.assertEqual(r.content, b"much longer body")


class TestDuplicateFramingHeaders(unittest.TestCase):
    def test_two_content_lengths_are_not_merged(self):
        r = request()
        rawhttp.apply_text(
            r,
            "POST /x HTTP/1.1\nHost: ex.com\nContent-Length: 6\n"
            "Content-Length: 5\n\nbody12",
            update_content_length=False,
        )
        values = [
            v.decode() for n, v in r.headers.fields if n.lower() == b"content-length"
        ]
        self.assertEqual(values, ["6", "5"])
