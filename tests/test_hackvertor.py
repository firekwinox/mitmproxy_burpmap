import unittest

from mitmproxy.test import tflow

from burpmap import rawhttp
from burpmap.hackvertor import TagError
from burpmap.hackvertor import process
from burpmap.repeater import Repeater


class TestProcess(unittest.TestCase):
    def test_each_tag(self):
        self.assertEqual(process(b"<@urlencode>a b&c<@/urlencode>"), b"a%20b%26c")
        self.assertEqual(process(b"<@urldecode>a%20b%26c<@/urldecode>"), b"a b&c")
        self.assertEqual(process(b"<@base64encode>test<@/base64encode>"), b"dGVzdA==")
        self.assertEqual(process(b"<@base64decode>dGVzdA==<@/base64decode>"), b"test")

    def test_nesting_applies_innermost_first(self):
        self.assertEqual(
            process(b"<@urlencode><@base64encode>test<@/base64encode><@/urlencode>"),
            b"dGVzdA%3D%3D",
        )
        self.assertEqual(
            process(b"<@base64encode><@urlencode>a b<@/urlencode><@/base64encode>"),
            b"YSUyMGI=",
        )

    def test_same_tag_nested_in_itself(self):
        self.assertEqual(
            process(b"<@urlencode>%<@urlencode>%<@/urlencode><@/urlencode>"),
            b"%25%2525",
        )

    def test_surrounding_text_and_siblings_are_kept(self):
        self.assertEqual(
            process(b"q=<@urlencode>a b<@/urlencode>&r=<@urlencode>c d<@/urlencode>!"),
            b"q=a%20b&r=c%20d!",
        )

    def test_works_on_bytes(self):
        self.assertEqual(process(b"<@base64decode>/w==<@/base64decode>"), b"\xff")
        self.assertEqual(process(b"<@urldecode>%ff%00<@/urldecode>"), b"\xff\x00")
        self.assertEqual(
            process("<@urlencode>世界<@/urlencode>".encode()), b"%E4%B8%96%E7%95%8C"
        )

    def test_text_without_known_tags_is_untouched(self):
        for text in (b"plain", b"<@foo>x<@/foo>", b"<% not a tag %>", b"<@/>", b""):
            self.assertEqual(process(text), text)

    def test_unknown_tag_inside_a_known_one_is_content(self):
        self.assertEqual(process(b"<@urlencode><@foo><@/urlencode>"), b"%3C%40foo%3E")

    def test_empty_content(self):
        self.assertEqual(process(b"<@base64encode><@/base64encode>"), b"")

    def test_malformed_tags_raise(self):
        for text in (
            b"<@urlencode>x",
            b"x<@/urlencode>",
            b"<@urlencode><@base64encode>x<@/urlencode><@/base64encode>",
            b"<@base64decode>not base64!<@/base64decode>",
        ):
            with self.subTest(text=text), self.assertRaises(TagError):
                process(text)

    def test_nesting_is_bounded(self):
        ok = b"x"
        for _ in range(64):
            ok = b"<@urlencode>" + ok + b"<@/urlencode>"
        self.assertEqual(process(ok), b"x")
        with self.assertRaises(TagError):
            process(b"<@urlencode>" + ok + b"<@/urlencode>")


def slot_for(text, update_content_length=True):
    flow = tflow.tflow()
    rawhttp.apply_text(flow.request, text, update_content_length=update_content_length)
    repeater = Repeater()
    return repeater, repeater.add(flow)


class TestSend(unittest.TestCase):
    def test_tags_expand_in_the_sent_copy_only(self):
        template = (
            "POST /a?q=<@urlencode>a&b<@/urlencode> HTTP/1.1\n"
            "Host: ex.com\n"
            "X-Token: <@base64encode>me<@/base64encode>\n"
            "\n"
            "p=<@urlencode><@base64encode>test<@/base64encode><@/urlencode>"
        )
        repeater, slot = slot_for(template)
        sent = repeater.prepare_send(slot)

        self.assertEqual(sent.request.path, "/a?q=a%26b")
        self.assertEqual(sent.request.headers["x-token"], "bWU=")
        self.assertEqual(sent.request.content, b"p=dGVzdA%3D%3D")
        self.assertEqual(sent.request.headers["content-length"], "14")
        self.assertIn(b"<@urlencode>", slot.flow.request.content)
        self.assertIn("<@urlencode>", slot.flow.request.path)

    def test_binary_body_survives(self):
        repeater, slot = slot_for(
            "POST / HTTP/1.1\nHost: ex.com\n\n<@base64decode>/w==<@/base64decode>"
        )
        sent = repeater.prepare_send(slot)
        self.assertEqual(sent.request.content, b"\xff")
        self.assertEqual(sent.request.headers["content-length"], "1")

    def test_deliberately_wrong_content_length_is_kept(self):
        repeater, slot = slot_for(
            "POST / HTTP/1.1\nHost: ex.com\nContent-Length: 3\n\n"
            "<@base64encode>test<@/base64encode>",
            update_content_length=False,
        )
        sent = repeater.prepare_send(slot)
        self.assertEqual(sent.request.content, b"dGVzdA==")
        self.assertEqual(sent.request.headers["content-length"], "3")

    def test_malformed_tag_sends_nothing(self):
        repeater, slot = slot_for("POST / HTTP/1.1\nHost: ex.com\n\n<@urlencode>x")
        with self.assertRaises(TagError):
            repeater.prepare_send(slot)
        self.assertEqual(slot.history, [])
        self.assertEqual(repeater.inflight, {})

    def test_request_without_tags_is_sent_as_is(self):
        repeater, slot = slot_for(
            "POST / HTTP/1.1\nHost: ex.com\nX-Raw: caf\xe9\n\n<% raw %>"
        )
        before = slot.flow.request.copy()
        sent = repeater.prepare_send(slot)
        self.assertEqual(sent.request.headers.fields, before.headers.fields)
        self.assertEqual(sent.request.raw_content, before.raw_content)


if __name__ == "__main__":
    unittest.main()
