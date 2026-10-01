"""Install/uninstall against a stand-in for mitmproxy's console window.

These are the three pieces of mitmproxy state the addon reaches into, so they are
the three things worth pinning down: the pane registry, the legal key contexts,
and the quick-help bar.
"""

import unittest

from mitmproxy.tools.console import keymap as keymap_module
from mitmproxy.tools.console import quickhelp

from burpmap import console
from burpmap.model import Display
from burpmap.model import SiteMap
from burpmap.repeater import Repeater


class StubStack:
    def __init__(self):
        self.windows = {"flowlist": object(), "eventlog": object()}
        self.stack = ["flowlist"]


class StubWindow:
    def __init__(self):
        self.stacks = [StubStack(), StubStack()]
        self.refreshed = 0

    def refresh(self):
        self.refreshed += 1


class StubMaster:
    def __init__(self):
        self.window = StubWindow()
        self.keymap = keymap_module.Keymap(self)


class TestInstall(unittest.TestCase):
    def setUp(self):
        self.master = StubMaster()
        self.sitemap = SiteMap()
        self.display = Display()
        self.repeater = Repeater()
        self.quickhelp_before = quickhelp.make
        self.contexts_before = set(keymap_module.Contexts)

    def tearDown(self):
        console.uninstall(self.master)
        quickhelp.make = self.quickhelp_before
        keymap_module.Contexts.clear()
        keymap_module.Contexts.update(self.contexts_before)

    def install(self):
        return console.install(
            self.master, self.sitemap, self.display, self.repeater
        )

    def test_both_pages_land_in_both_panes(self):
        sitemap_views, repeater_views = self.install()
        self.assertEqual(len(sitemap_views), 2)
        self.assertEqual(len(repeater_views), 2)
        for stack in self.master.window.stacks:
            self.assertIn("sitemap", stack.windows)
            self.assertIn("repeater", stack.windows)
        # each pane needs its own widget: urwid widgets cannot be shared
        self.assertIsNot(sitemap_views[0], sitemap_views[1])
        # but they must share one model
        self.assertIs(sitemap_views[0].sitemap, sitemap_views[1].sitemap)

    def test_contexts_are_registered(self):
        self.install()
        self.assertIn("sitemap", keymap_module.Contexts)
        self.assertIn("repeater", keymap_module.Contexts)

    def test_bindings_are_registered(self):
        self.install()
        self.assertEqual(
            self.master.keymap.get("global", "T").command, "sitemap.view"
        )
        self.assertEqual(
            self.master.keymap.get("sitemap", "v").command, "sitemap.visit"
        )
        self.assertEqual(
            self.master.keymap.get("repeater", "r").command, "repeater.send"
        )

    def test_quickhelp_is_wrapped_and_covers_our_pages(self):
        from burpmap.ui_sitemap import SiteMapView

        self.install()
        self.assertIsNot(quickhelp.make, self.quickhelp_before)
        qh = quickhelp.make(SiteMapView, None, True)
        self.assertIn("Visit", qh.top_items)
        self.assertTrue(qh.top_label.startswith("Site map:"))
        # the label column must leave a gap before the first item
        self.assertTrue(qh.top_label.endswith(" "))
        self.assertEqual(len(qh.top_label), len(qh.bottom_label))

    def test_quickhelp_leaves_builtin_views_alone(self):
        from mitmproxy.tools.console.eventlog import EventLog

        self.install()
        patched = quickhelp.make(EventLog, None, True)
        original = self.quickhelp_before(EventLog, None, True)
        self.assertEqual(patched.top_items, original.top_items)

    def test_every_binding_help_string_is_reachable(self):
        # quickhelp looks bindings up by their help text; a typo in either table
        # silently drops the key from the help bar.
        self.install()
        helps = {b[3] for b in console.BINDINGS}
        for table in (console.QUICKHELP_SITEMAP, console.QUICKHELP_REPEATER):
            for help_text in table.values():
                self.assertIn(help_text, helps, help_text)


class TestUninstall(unittest.TestCase):
    def setUp(self):
        self.master = StubMaster()
        self.quickhelp_before = quickhelp.make
        self.contexts_before = set(keymap_module.Contexts)
        console.install(self.master, SiteMap(), Display(), Repeater())

    def tearDown(self):
        quickhelp.make = self.quickhelp_before
        keymap_module.Contexts.clear()
        keymap_module.Contexts.update(self.contexts_before)

    def test_everything_is_put_back(self):
        console.uninstall(self.master)
        for stack in self.master.window.stacks:
            self.assertNotIn("sitemap", stack.windows)
            self.assertNotIn("repeater", stack.windows)
        self.assertIsNone(self.master.keymap.get("global", "T"))
        self.assertIsNone(self.master.keymap.get("sitemap", "v"))
        self.assertIs(quickhelp.make, self.quickhelp_before)
        self.assertNotIn("sitemap", keymap_module.Contexts)

    def test_an_open_page_is_popped_off_the_stack(self):
        self.master.window.stacks[0].stack = ["flowlist", "sitemap"]
        self.master.window.stacks[1].stack = ["repeater"]
        console.uninstall(self.master)
        self.assertEqual(self.master.window.stacks[0].stack, ["flowlist"])
        # a stack must never be left empty
        self.assertEqual(self.master.window.stacks[1].stack, ["flowlist"])

    def test_reinstall_after_uninstall_is_clean(self):
        console.uninstall(self.master)
        console.install(self.master, SiteMap(), Display(), Repeater())
        self.assertEqual(
            self.master.keymap.get("global", "T").command, "sitemap.view"
        )
        # one binding per key, not two
        matching = [b for b in self.master.keymap.bindings if b.key == "T"]
        self.assertEqual(len(matching), 1)
        console.uninstall(self.master)


class TestNoConsole(unittest.TestCase):
    def test_install_is_a_no_op_without_a_window(self):
        class Headless:
            window = None

        sitemap_views, repeater_views = console.install(
            Headless(), SiteMap(), Display(), Repeater()
        )
        self.assertEqual((sitemap_views, repeater_views), ([], []))
        self.assertNotIn("sitemap", keymap_module.Contexts)


if __name__ == "__main__":
    unittest.main()


class TestFocusHighlight(unittest.TestCase):
    """The row under the cursor has to be visibly different in every theme."""

    def row_item(self, focused_label="/b"):
        from burpmap.ui_sitemap import RowItem

        sitemap = SiteMap()
        sitemap.add_link("https://ex.com/a/b")
        rows = Display().rows(sitemap)
        row = [r for r in rows if r.label == focused_label][0]
        return RowItem(row, None)

    def attrs(self, item, focus):
        canvas = item.render((60,), focus=focus)
        return {a for line in canvas.content() for a, _, _ in line}

    def test_focused_row_is_filled_with_the_highlight_attribute(self):
        from burpmap.ui_common import FOCUS_ATTR

        self.assertEqual(self.attrs(self.row_item(), focus=True), {FOCUS_ATTR})

    def test_unfocused_row_keeps_its_own_colours(self):
        from burpmap.ui_common import FOCUS_ATTR

        attrs = self.attrs(self.row_item(), focus=False)
        self.assertNotIn(FOCUS_ATTR, attrs)
        self.assertIn("method_get", attrs)

    def test_the_whole_row_width_is_highlighted(self):
        from burpmap.ui_common import FOCUS_ATTR

        canvas = self.row_item().render((60,), focus=True)
        self.assertEqual(canvas.cols(), 60)
        for line in canvas.content():
            # urwid splits the line into runs at the column boundaries; what
            # matters is that no run escapes the highlight and leaves a gap.
            self.assertEqual({attr for attr, _, _ in line}, {FOCUS_ATTR})
            width = sum(len(text.decode("utf8")) for _, _, text in line)
            self.assertEqual(width, 60)

    def test_the_highlight_attribute_has_a_background_in_every_palette(self):
        from mitmproxy.tools.console import palettes
        from burpmap.ui_common import FOCUS_ATTR

        for name, palette in palettes.palettes.items():
            fg, bg = palette.low[FOCUS_ATTR]
            self.assertNotEqual(bg, "default", f"{name} has no background")
            self.assertNotEqual(fg, bg, name)

    def test_every_attribute_we_emit_is_covered_by_the_focus_map(self):
        # A row attribute missing from the map would survive the highlight and
        # leave a differently coloured hole in the bar.
        from burpmap import ui_sitemap
        from burpmap.ui_common import FOCUS_MAP

        sitemap = SiteMap()
        sitemap.add_link("https://ex.com/items/1")
        sitemap.add_link("https://ex.com/items/1", "POST")
        for row in Display(collapse=True, threshold=1).rows(sitemap):
            item = ui_sitemap.RowItem(row, None)
            for line in item.render((60,), focus=False).content():
                for attr, _, _ in line:
                    self.assertIn(attr, FOCUS_MAP, f"{attr!r} not in FOCUS_MAP")
