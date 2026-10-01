import unittest

from mitmproxy.test import tflow

from burpmap import discovery


def html_links(body, base="https://ex.com/app/index.html", sweep=True, limit=500):
    return discovery.extract_html(body, base, limit, sweep)


class TestNormalise(unittest.TestCase):
    def test_lowercases_and_strips_default_port_and_fragment(self):
        self.assertEqual(
            discovery.normalise("HTTPS://EX.com:443/a/b?q=1#frag"),
            "https://ex.com/a/b?q=1",
        )

    def test_keeps_non_default_port(self):
        self.assertEqual(
            discovery.normalise("http://ex.com:8080/a"), "http://ex.com:8080/a"
        )

    def test_empty_path_becomes_root(self):
        self.assertEqual(discovery.normalise("https://ex.com"), "https://ex.com/")

    def test_hostless_url_is_rejected(self):
        self.assertEqual(discovery.normalise("file:///etc/passwd"), "")


class TestHtmlExtraction(unittest.TestCase):
    def test_anchors_and_relative_resolution(self):
        links = html_links('<a href="page2.html">x</a><a href="/root">y</a>')
        self.assertIn(("GET", "https://ex.com/app/page2.html"), links)
        self.assertIn(("GET", "https://ex.com/root"), links)

    def test_base_href_is_honoured(self):
        links = html_links('<base href="https://cdn.ex.com/v2/"><a href="a.html">x</a>')
        self.assertIn(("GET", "https://cdn.ex.com/v2/a.html"), links)

    def test_form_method_is_kept(self):
        links = html_links('<form action="/login" method="POST"></form>')
        self.assertIn(("POST", "https://ex.com/login"), links)

    def test_form_without_action_posts_back_to_the_page(self):
        links = html_links('<form method="post"></form>')
        self.assertIn(("POST", "https://ex.com/app/index.html"), links)

    def test_form_with_odd_method_falls_back_to_get(self):
        links = html_links('<form action="/x" method="PUT"></form>')
        self.assertIn(("GET", "https://ex.com/x"), links)

    def test_srcset_is_split(self):
        links = html_links('<img srcset="a.png 1x, b.png 2x">')
        self.assertIn(("GET", "https://ex.com/app/a.png"), links)
        self.assertIn(("GET", "https://ex.com/app/b.png"), links)

    def test_protocol_relative_url(self):
        links = html_links('<iframe src="//cdn.ex.com/f"></iframe>')
        self.assertIn(("GET", "https://cdn.ex.com/f"), links)

    def test_meta_refresh(self):
        links = html_links('<meta http-equiv="refresh" content="0; url=/next">')
        self.assertIn(("GET", "https://ex.com/next"), links)

    def test_data_attributes(self):
        links = html_links('<div data-url="/api/thing"></div>')
        self.assertIn(("GET", "https://ex.com/api/thing"), links)

    def test_non_http_schemes_are_dropped(self):
        links = html_links(
            '<a href="mailto:a@b.c">m</a><a href="javascript:x()">j</a>'
            '<a href="tel:123">t</a><a href="data:text/plain,x">d</a>'
        )
        self.assertEqual(links, [])

    def test_fragment_only_link_resolves_to_the_page_itself(self):
        links = html_links('<a href="#section">s</a>')
        self.assertEqual(links, [])

    def test_inline_script_sweep(self):
        links = html_links('<script>fetch("/api/v1/users")</script>')
        self.assertIn(("GET", "https://ex.com/api/v1/users"), links)

    def test_inline_script_sweep_can_be_disabled(self):
        links = html_links('<script>fetch("/api/v1/users")</script>', sweep=False)
        self.assertEqual(links, [])

    def test_css_url_references(self):
        links = html_links("<style>body{background:url('/img/bg.png')}</style>")
        self.assertIn(("GET", "https://ex.com/img/bg.png"), links)

    def test_results_are_deduplicated(self):
        links = html_links('<a href="/a">1</a><a href="/a">2</a>')
        self.assertEqual(links.count(("GET", "https://ex.com/a")), 1)

    def test_limit_is_respected(self):
        body = "".join(f'<a href="/p{i}">x</a>' for i in range(50))
        self.assertEqual(len(html_links(body, limit=10)), 10)

    def test_unclosed_tags_do_not_lose_earlier_links(self):
        links = html_links('<a href="/a">x<div><span><a href="/b">y')
        self.assertIn(("GET", "https://ex.com/a"), links)
        self.assertIn(("GET", "https://ex.com/b"), links)


class TestSweepRejections(unittest.TestCase):
    def sweep(self, text):
        return discovery._sweep_text(text, 100)

    def test_finds_paths_and_absolute_urls(self):
        found = self.sweep('a="/api/v1/x"; b="https://other.com/y";')
        self.assertIn("/api/v1/x", found)
        self.assertIn("https://other.com/y", found)

    def test_rejects_mime_types(self):
        self.assertEqual(self.sweep('"application/json"'), [])
        self.assertEqual(self.sweep('"text/html"'), [])

    def test_rejects_template_literals_and_format_strings(self):
        self.assertEqual(self.sweep('`/users/${id}`'), [])
        self.assertEqual(self.sweep('"/users/%s"'), [])

    def test_rejects_strings_with_whitespace(self):
        self.assertEqual(self.sweep('"/a path/with spaces"'), [])

    def test_rejects_comments_and_bare_slash(self):
        self.assertEqual(self.sweep('"//comment"'), [])
        self.assertEqual(self.sweep('"/"'), [])


class TestExtractFromFlow(unittest.TestCase):
    def make(self, ctype, body, url="https://ex.com/app/"):
        flow = tflow.tflow(resp=True)
        flow.request.scheme = "https"
        flow.request.host = "ex.com"
        flow.request.port = 443
        flow.request.path = "/app/"
        flow.response.headers["content-type"] = ctype
        flow.response.content = body
        return flow

    def test_html_source(self):
        flow = self.make("text/html", b'<a href="/x">x</a>')
        self.assertIn(("GET", "https://ex.com/x"), discovery.extract(flow))

    def test_json_source(self):
        flow = self.make("application/json", b'{"next":"/api/page/2"}')
        self.assertIn(("GET", "https://ex.com/api/page/2"), discovery.extract(flow))

    def test_javascript_source(self):
        flow = self.make("application/javascript", b'axios.get("/api/me")')
        self.assertIn(("GET", "https://ex.com/api/me"), discovery.extract(flow))

    def test_source_can_be_switched_off(self):
        flow = self.make("application/json", b'{"next":"/api/page/2"}')
        self.assertEqual(discovery.extract(flow, sources=("html",)), [])

    def test_headers_source_is_opt_in(self):
        flow = self.make("text/html", b"")
        flow.response.headers["location"] = "/after-redirect"
        self.assertNotIn(
            ("GET", "https://ex.com/after-redirect"), discovery.extract(flow)
        )
        self.assertIn(
            ("GET", "https://ex.com/after-redirect"),
            discovery.extract(flow, sources=("html", "headers")),
        )

    def test_oversized_bodies_are_skipped(self):
        flow = self.make("text/html", b'<a href="/x">x</a>' + b"." * 100)
        self.assertEqual(discovery.extract(flow, max_body=10), [])

    def test_binary_content_type_is_ignored(self):
        flow = self.make("image/png", b'\x89PNG"/not/a/link"')
        self.assertEqual(discovery.extract(flow), [])

    def test_flow_without_response(self):
        flow = tflow.tflow()
        self.assertEqual(discovery.extract(flow), [])


if __name__ == "__main__":
    unittest.main()
