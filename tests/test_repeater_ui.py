"""The repeater page: split panes and the raw-text editor."""

import unittest

from mitmproxy.test import tflow

from burpmap import rawhttp
from burpmap.repeater import Repeater
from burpmap.ui_repeater import RepeaterView

SIZE = (120, 30)


def make_flow(path="/api/login", method="POST", body=b'{"u":"a"}'):
    flow = tflow.tflow(resp=True)
    flow.request.scheme, flow.request.host, flow.request.port = "https", "ex.com", 443
    flow.request.method, flow.request.path = method, path
    flow.request.content = body
    flow.response.content = b"<html>hi</html>"
    return flow


def view_with_slot(**kwargs):
    repeater = Repeater()
    repeater.add(make_flow(**kwargs))
    return RepeaterView(None, repeater), repeater


def pane_text(pane):
    return "\n".join(w.get_text()[0] for w in pane.walker)


class TestPanes(unittest.TestCase):
    def test_empty_repeater_renders_without_a_slot(self):
        view = RepeaterView(None, Repeater())
        self.assertIn("empty", view.title)
        self.assertIn("empty", pane_text(view.request_pane))

    def test_request_pane_shows_the_wire_request(self):
        view, _ = view_with_slot()
        text = pane_text(view.request_pane)
        self.assertIn("POST", text)
        self.assertIn("/api/login", text)
        self.assertIn("Host: ex.com", text)
        self.assertIn('{"u":"a"}', text)

    def test_response_pane_says_nothing_sent_yet(self):
        view, _ = view_with_slot()
        self.assertIn("not sent yet", pane_text(view.response_pane))

    def test_response_pane_shows_the_response_after_a_send(self):
        view, repeater = view_with_slot()
        slot = repeater.current
        sent = repeater.prepare_send(slot)
        sent.response = make_flow().response
        view.rebuild(force=True)
        text = pane_text(view.response_pane)
        self.assertIn("200", text)
        self.assertIn("<html>hi</html>", text)

    def test_the_two_panes_are_separate_columns(self):
        view, _ = view_with_slot()
        self.assertEqual(view.columns.focus_position, view.REQUEST)
        view.switch_pane()
        self.assertEqual(view.columns.focus_position, view.RESPONSE)
        view.switch_pane()
        self.assertEqual(view.columns.focus_position, view.REQUEST)

    def test_tab_switches_panes(self):
        view, _ = view_with_slot()
        view.keypress(SIZE, "m_next")
        self.assertEqual(view.columns.focus_position, view.RESPONSE)


class TestEditor(unittest.TestCase):
    def test_begin_edit_on_an_empty_repeater_is_refused(self):
        view = RepeaterView(None, Repeater())
        with self.assertRaises(ValueError):
            view.begin_edit()

    def test_begin_edit_loads_the_wire_text(self):
        view, _ = view_with_slot()
        view.begin_edit()
        self.assertTrue(view.editing)
        text = view.editor.get_edit_text()
        self.assertTrue(text.startswith("POST /api/login HTTP/1.1\n"))
        self.assertIn('{"u":"a"}', text)

    def test_the_editor_itself_is_in_the_request_pane(self):
        view, _ = view_with_slot()
        view.begin_edit()
        self.assertIs(view.request_pane.walker[0], view.editor)
        self.assertEqual(view.columns.focus_position, view.REQUEST)

    def test_editing_a_past_send_falls_back_to_the_template(self):
        view, repeater = view_with_slot()
        slot = repeater.current
        repeater.prepare_send(slot)
        self.assertEqual(slot.cursor, 0)
        view.begin_edit()
        self.assertEqual(slot.cursor, -1)
        self.assertIn("template", view.message)

    def test_commit_applies_the_edit_to_the_template(self):
        view, repeater = view_with_slot()
        view.begin_edit()
        view.editor.set_edit_text(
            view.editor.get_edit_text().replace("/api/login", "/api/admin")
        )
        view.commit_edit()
        self.assertFalse(view.editing)
        self.assertEqual(repeater.current.flow.request.path, "/api/admin")

    def test_commit_of_malformed_text_raises_and_stays_in_the_editor(self):
        view, repeater = view_with_slot()
        view.begin_edit()
        view.editor.set_edit_text("not a request\n\n")
        with self.assertRaises(ValueError):
            view.commit_edit()
        self.assertTrue(view.editing, "must not drop the user's text on the floor")
        self.assertEqual(repeater.current.flow.request.path, "/api/login")

    def test_cancel_discards(self):
        view, repeater = view_with_slot()
        view.begin_edit()
        view.editor.set_edit_text("GET /somewhere-else HTTP/1.1\nHost: ex.com\n\n")
        view.cancel_edit()
        self.assertFalse(view.editing)
        self.assertEqual(repeater.current.flow.request.path, "/api/login")

    def test_esc_commits_while_editing(self):
        view, repeater = view_with_slot()
        view.begin_edit()
        view.editor.set_edit_text("GET /esc-worked HTTP/1.1\nHost: ex.com\n\n")
        self.assertIsNone(view.keypress(SIZE, "esc"))
        self.assertFalse(view.editing)
        self.assertEqual(repeater.current.flow.request.path, "/esc-worked")

    def test_esc_on_bad_text_reports_and_keeps_editing(self):
        view, _ = view_with_slot()
        view.begin_edit()
        view.editor.set_edit_text("rubbish\n\n")
        view.keypress(SIZE, "esc")
        self.assertTrue(view.editing)
        self.assertIn("not applied", view.message)

    def test_esc_is_left_alone_when_not_editing(self):
        # Outside the editor esc has to keep popping the page.
        view, _ = view_with_slot()
        self.assertEqual(view.keypress(SIZE, "esc"), "esc")

    def test_ctrl_x_discards(self):
        view, repeater = view_with_slot()
        view.begin_edit()
        view.editor.set_edit_text("GET /nope HTTP/1.1\nHost: ex.com\n\n")
        self.assertIsNone(view.keypress(SIZE, "ctrl x"))
        self.assertFalse(view.editing)
        self.assertEqual(repeater.current.flow.request.path, "/api/login")

    def test_a_binary_body_round_trips_through_the_editor(self):
        view, repeater = view_with_slot(body=bytes(range(256)))
        view.begin_edit()
        self.assertEqual(view.edit_codec, rawhttp.BINARY_CODEC)
        view.commit_edit(update_content_length=False)
        self.assertEqual(repeater.current.flow.request.content, bytes(range(256)))

    def test_rebuild_does_not_clobber_the_editor(self):
        view, _ = view_with_slot()
        view.begin_edit()
        view.editor.set_edit_text("GET /in-progress HTTP/1.1\nHost: ex.com\n\n")
        view.rebuild(force=True)
        self.assertIs(view.request_pane.walker[0], view.editor)
        self.assertIn("/in-progress", view.editor.get_edit_text())

    def test_the_header_announces_edit_mode(self):
        view, _ = view_with_slot()
        view.begin_edit()
        self.assertIn("EDITING", view.title)
        self.assertIn("EDITING", str(view.status.get_text()[0]))


if __name__ == "__main__":
    unittest.main()
