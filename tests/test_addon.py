import logging
import unittest

from mitmproxy import exceptions
from mitmproxy.test import taddons
from mitmproxy.test import tflow

from burpmap.addon import BurpMap
from burpmap.model import Entry


def setUpModule():
    # Each taddons.context creates a Master, and each Master installs a logging
    # handler bound to its own event loop. Once a context exits its loop is
    # closed, so a later log record fans out to a stale handler and raises. None
    # of these tests assert on log output.
    logging.disable(logging.CRITICAL)


def tearDownModule():
    logging.disable(logging.NOTSET)


def html_flow(url_path="/app/", body=b"", ctype="text/html", host="ex.com", port=443):
    flow = tflow.tflow(resp=True)
    flow.request.scheme = "https" if port == 443 else "http"
    flow.request.host = host
    flow.request.port = port
    flow.request.path = url_path
    flow.response.headers["content-type"] = ctype
    flow.response.content = body
    return flow


class TestOptions(unittest.TestCase):
    def test_bad_scope_regex_is_rejected(self):
        addon = BurpMap()
        with taddons.context(addon) as tctx:
            with self.assertRaises(exceptions.OptionsError):
                tctx.configure(addon, sitemap_scope="(unbalanced")

    def test_unknown_discovery_source_is_rejected(self):
        addon = BurpMap()
        with taddons.context(addon) as tctx:
            with self.assertRaises(exceptions.OptionsError):
                tctx.configure(addon, sitemap_discovery=["html", "telepathy"])

    def test_scope_reaches_the_display(self):
        addon = BurpMap()
        with taddons.context(addon) as tctx:
            tctx.configure(addon, sitemap_scope=r"^https://ex\.com/")
            self.assertTrue(addon.display.scope.match("https://ex.com/a"))
            self.assertFalse(addon.display.scope.match("https://other.com/a"))

    def test_display_toggles_follow_options(self):
        addon = BurpMap()
        with taddons.context(addon) as tctx:
            tctx.configure(addon, sitemap_collapse=True, sitemap_unvisited_only=True)
            self.assertTrue(addon.display.collapse)
            self.assertTrue(addon.display.unvisited_only)


class TestHooks(unittest.TestCase):
    def test_response_records_and_discovers(self):
        addon = BurpMap()
        with taddons.context(addon):
            flow = html_flow(body=b'<a href="/never-visited">x</a>')
            addon.request(flow)
            addon.response(flow)

        urls = {e.url: e for e in addon.sitemap.all_entries()}
        self.assertIn("https://ex.com/app/", urls)
        self.assertTrue(urls["https://ex.com/app/"].visited)
        self.assertIn("https://ex.com/never-visited", urls)
        self.assertFalse(urls["https://ex.com/never-visited"].visited)

    def test_discovered_entry_remembers_the_page_it_came_from(self):
        addon = BurpMap()
        with taddons.context(addon):
            flow = html_flow(body=b'<a href="/x">x</a>')
            addon.response(flow)
        entry = [e for e in addon.sitemap.all_entries() if e.url.endswith("/x")][0]
        self.assertIs(entry.source_flow, flow)
        self.assertEqual(entry.sources, {"https://ex.com/app/"})

    def test_discovery_can_be_switched_off_entirely(self):
        addon = BurpMap()
        with taddons.context(addon) as tctx:
            tctx.configure(addon, sitemap_discovery=[])
            addon.response(html_flow(body=b'<a href="/x">x</a>'))
        self.assertEqual(addon.sitemap.stats(), (1, 1, 0))

    def test_entry_limit_stops_growth(self):
        addon = BurpMap()
        with taddons.context(addon) as tctx:
            tctx.configure(addon, sitemap_max_entries=1)
            addon.response(html_flow(body=b'<a href="/x">x</a><a href="/y">y</a>'))
        # the visited page itself is always recorded; links are not
        self.assertEqual(addon.sitemap.stats(), (1, 1, 0))

    def test_counters_stay_in_sync(self):
        addon = BurpMap()
        with taddons.context(addon):
            addon.response(html_flow(body=b'<a href="/a">a</a><a href="/b">b</a>'))
        sitemap = addon.sitemap
        walked_total = len(list(sitemap.all_entries()))
        walked_visited = len([e for e in sitemap.all_entries() if e.visited])
        self.assertEqual(sitemap.count_total, walked_total)
        self.assertEqual(sitemap.count_visited, walked_visited)

        root = sitemap.roots["https://ex.com"]
        sitemap.remove_node(root.children["a"])
        self.assertEqual(
            sitemap.count_total, len(list(sitemap.all_entries()))
        )


class TestBuildFlow(unittest.TestCase):
    def build(self, entry, **options):
        addon = BurpMap()
        with taddons.context(addon) as tctx:
            if options:
                tctx.configure(addon, **options)
            return addon._build_flow(entry)

    def test_non_default_port_survives_in_the_host_header(self):
        # view.flows.create sets Host to the bare hostname, which loses the port
        # and files the response under the wrong tree root.
        entry = Entry(method="GET", url="http://127.0.0.1:8811/secret")
        built = self.build(entry)
        self.assertEqual(built.request.headers["Host"], "127.0.0.1:8811")
        self.assertEqual(built.request.pretty_url, "http://127.0.0.1:8811/secret")

    def test_default_port_gives_a_bare_host_header(self):
        built = self.build(Entry(method="GET", url="https://ex.com/a"))
        self.assertEqual(built.request.headers["Host"], "ex.com")
        self.assertEqual(built.request.pretty_url, "https://ex.com/a")

    def test_session_headers_are_inherited_from_the_discovering_page(self):
        source = html_flow()
        source.request.headers["cookie"] = "session=abc"
        source.request.headers["user-agent"] = "probe/1.0"
        source.request.headers["x-not-inherited"] = "nope"
        entry = Entry(method="GET", url="https://ex.com/admin", source_flow=source)

        built = self.build(entry)
        self.assertEqual(built.request.headers["cookie"], "session=abc")
        self.assertEqual(built.request.headers["user-agent"], "probe/1.0")
        self.assertEqual(built.request.headers["referer"], source.request.pretty_url)
        self.assertNotIn("x-not-inherited", built.request.headers)

    def test_inheritance_can_be_switched_off(self):
        source = html_flow()
        source.request.headers["cookie"] = "session=abc"
        entry = Entry(method="GET", url="https://ex.com/admin", source_flow=source)
        built = self.build(entry, sitemap_visit_inherit_headers=False)
        self.assertNotIn("cookie", built.request.headers)

    def test_method_is_preserved(self):
        built = self.build(Entry(method="POST", url="https://ex.com/login"))
        self.assertEqual(built.request.method, "POST")

    def test_invalid_url_raises_a_command_error(self):
        with self.assertRaises(exceptions.CommandError):
            self.build(Entry(method="GET", url="not a url"))


class TestDumpCommand(unittest.TestCase):
    def test_dump_respects_scope_and_collapse(self):
        addon = BurpMap()
        with taddons.context(addon) as tctx:
            for i in range(1, 5):
                addon.sitemap.add_link(f"https://ex.com/items/{i}")
            addon.sitemap.add_link("https://other.com/x")

            self.assertIn("other.com", addon.sitemap_dump())

            tctx.configure(addon, sitemap_scope=r"^https://ex\.com/")
            self.assertNotIn("other.com", addon.sitemap_dump())

            tctx.configure(addon, sitemap_collapse=True)
            self.assertIn("{id}", addon.sitemap_dump())

    def test_console_commands_fail_cleanly_without_a_ui(self):
        addon = BurpMap()
        with taddons.context(addon):
            for call in (addon.sitemap_view, addon.repeater_view, addon.repeater_send):
                with self.assertRaises(exceptions.CommandError):
                    call()


class TestRepeaterModel(unittest.TestCase):
    def test_add_creates_an_independent_template(self):
        addon = BurpMap()
        with taddons.context(addon):
            source = html_flow()
            addon.repeater_add([source])

        slot = addon.repeater.current
        self.assertIsNotNone(slot)
        self.assertNotEqual(slot.flow.id, source.id)
        self.assertIsNone(slot.flow.response)
        # editing the template must not touch the flow it came from
        slot.flow.request.path = "/edited"
        self.assertNotEqual(source.request.path, "/edited")

    def test_send_snapshots_the_template(self):
        addon = BurpMap()
        with taddons.context(addon):
            addon.repeater_add([html_flow()])
        slot = addon.repeater.current

        first = addon.repeater.prepare_send(slot)
        slot.flow.request.path = "/changed"
        second = addon.repeater.prepare_send(slot)

        self.assertEqual(len(slot.history), 2)
        self.assertNotEqual(first.id, second.id)
        self.assertNotEqual(first.request.path, second.request.path)
        self.assertEqual(second.request.path, "/changed")

    def test_resolve_matches_the_sent_flow_back_to_its_slot(self):
        addon = BurpMap()
        with taddons.context(addon):
            addon.repeater_add([html_flow()])
        slot = addon.repeater.current
        sent = addon.repeater.prepare_send(slot)
        self.assertIs(addon.repeater.resolve(sent), slot)
        self.assertIsNone(addon.repeater.resolve(sent))

    def test_history_navigation_is_clamped(self):
        addon = BurpMap()
        with taddons.context(addon):
            addon.repeater_add([html_flow()])
        slot = addon.repeater.current
        addon.repeater.prepare_send(slot)
        addon.repeater.prepare_send(slot)

        addon.repeater.scroll_history(-10)
        self.assertEqual(slot.cursor, 0)
        addon.repeater.scroll_history(10)
        self.assertEqual(slot.cursor, 1)

    def test_non_http_flows_are_refused(self):
        addon = BurpMap()
        with taddons.context(addon):
            with self.assertRaises(exceptions.CommandError):
                addon.repeater_add([tflow.ttcpflow()])


class TestPersistenceCommands(unittest.TestCase):
    def test_save_then_load(self):
        import tempfile
        import os

        addon = BurpMap()
        with taddons.context(addon):
            addon.sitemap.add_link("https://ex.com/a")
            path = os.path.join(tempfile.mkdtemp(), "map.json")
            addon.sitemap_save(path)

            other = BurpMap()
        with taddons.context(other):
            other.sitemap_load(path)
        self.assertEqual(other.sitemap.stats(), (1, 0, 1))

    def test_load_of_a_missing_file_is_a_command_error(self):
        addon = BurpMap()
        with taddons.context(addon):
            with self.assertRaises(exceptions.CommandError):
                addon.sitemap_load("/nonexistent/burpmap-map.json")


if __name__ == "__main__":
    unittest.main()


class StubWindow:
    """Just enough of mitmproxy's Window for the commands that look one up."""

    def __init__(self, widgets):
        self.widgets = widgets
        self.refreshed = 0

    def current(self, keyctx):
        return self.widgets.get(keyctx)

    def refresh(self):
        self.refreshed += 1


class TestSitemapOpen(unittest.TestCase):
    """Enter must never put a request on the wire.

    A grey row can be a logout link or a delete endpoint. `v` requests things;
    `enter` opens them. This was wrong once, so it is pinned down here.
    """

    def setUp(self):
        from burpmap.ui_sitemap import SiteMapView

        self.addon = BurpMap()
        self.ctx = taddons.context(self.addon)
        self.ctx.__enter__()
        self.addon.response(html_flow(body=b'<a href="/never">x</a>'))
        self.view = SiteMapView(
            self.ctx.master, self.addon.sitemap, self.addon.display
        )
        self.ctx.master.window = StubWindow({"sitemap": self.view})
        self.addon.sitemap_views = [self.view]
        self.sent = []
        self.opened = []
        self.addon._send = self.sent.extend
        self.addon._open_flow = self.opened.append

    def tearDown(self):
        self.ctx.__exit__(None, None, None)

    def focus(self, label):
        self.view.rebuild()
        for index, row in enumerate(self.view.rows):
            if row.label == label:
                self.view.walker.focus_pos = index
                return row
        raise AssertionError(f"no row {label!r} in {[r.label for r in self.view.rows]}")

    def test_enter_on_an_unvisited_row_sends_nothing(self):
        row = self.focus("/never")
        self.assertFalse(row.entry.visited)
        self.addon.sitemap_open()
        self.assertEqual(self.sent, [])
        self.assertEqual(self.opened, [])
        self.assertFalse(row.entry.visited)

    def test_v_on_the_same_row_does_send(self):
        self.focus("/never")
        self.addon.sitemap_visit()
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0].request.pretty_url, "https://ex.com/never")

    def test_enter_on_a_visited_row_opens_the_flow(self):
        self.focus("/app")
        self.addon.sitemap_open()
        self.assertEqual(len(self.opened), 1)
        self.assertEqual(self.sent, [])

    def test_enter_on_a_directory_node_toggles_it(self):
        row = self.focus("https://ex.com")
        self.assertTrue(row.expandable)
        self.assertTrue(row.node.expanded)
        self.addon.sitemap_open()
        self.assertFalse(row.node.expanded)
        self.addon.sitemap_open()
        self.assertTrue(row.node.expanded)
        self.assertEqual(self.sent, [])

    def test_enter_on_a_collapsed_id_group_toggles_it(self):
        for i in range(1, 6):
            self.addon.sitemap.add_link(f"https://ex.com/items/{i}")
        self.addon.display.collapse = True
        self.view.invalidate_display()
        self.focus("{id}")
        self.addon.sitemap_open()
        self.assertEqual(self.sent, [])
        self.assertTrue(
            any(r.label == "/1" for r in self.view.rows), "group did not expand"
        )
