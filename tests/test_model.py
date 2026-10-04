import unittest

from burpmap.model import Display
from burpmap.model import Scope
from burpmap.model import SiteMap
from burpmap.model import is_id_like
from burpmap.model import split_url


class TestSplitUrl(unittest.TestCase):
    def test_default_port_elided(self):
        self.assertEqual(split_url("https://ex.com:443/a/b")[0], "https://ex.com")
        self.assertEqual(split_url("http://ex.com:80/")[0], "http://ex.com")

    def test_explicit_port_kept(self):
        self.assertEqual(split_url("https://ex.com:8443/a")[0], "https://ex.com:8443")

    def test_segments_and_query(self):
        root, segments, query = split_url("https://ex.com/a//b/?x=1")
        self.assertEqual(root, "https://ex.com")
        self.assertEqual(segments, ["a", "b"])
        self.assertEqual(query, "x=1")

    def test_host_is_lowercased(self):
        self.assertEqual(split_url("HTTPS://EX.COM/A")[0], "https://ex.com")
        # the path keeps its case; only scheme and host are normalised
        self.assertEqual(split_url("HTTPS://EX.COM/A")[1], ["A"])


class TestIdLike(unittest.TestCase):
    def test_matches(self):
        for segment in [
            "1",
            "40912",
            "b3b2b0f0-0e0d-4c1b-9f2a-1f0a0b0c0d0e",
            "deadbeefdeadbeef00",
            "build-2024-a1b2c3d4e5f6g7",
        ]:
            self.assertTrue(is_id_like(segment), segment)

    def test_does_not_match_words(self):
        for segment in ["users", "api", "documentation-overview", "v2", "index.html"]:
            self.assertFalse(is_id_like(segment), segment)


class TestScope(unittest.TestCase):
    def test_empty_scope_matches_everything(self):
        self.assertTrue(Scope().match("https://anything/"))

    def test_include_and_exclude(self):
        scope = Scope(include=r"^https://ex\.com/", exclude=r"/logout")
        self.assertTrue(scope.match("https://ex.com/app"))
        self.assertFalse(scope.match("https://other.com/app"))
        self.assertFalse(scope.match("https://ex.com/logout"))

    def test_case_insensitive_matching(self):
        scope = Scope(include=r"^https://ex\.com/")
        # URLs with different cases should all match
        self.assertTrue(scope.match("https://ex.com/app"))
        self.assertTrue(scope.match("HTTPS://EX.COM/app"))
        self.assertTrue(scope.match("HtTpS://Ex.CoM/app"))
        self.assertFalse(scope.match("https://other.com/app"))

    def test_bad_regex_leaves_previous_scope_intact(self):
        scope = Scope(include="ex")
        with self.assertRaises(Exception):
            scope.set("(unbalanced")
        self.assertEqual(scope.include_src, "ex")
        self.assertTrue(scope.match("https://ex.com/"))


class FakeResponse:
    def __init__(self, status=200, ctype="text/html", body=b"hi"):
        self.status_code = status
        self.headers = {"content-type": ctype}
        self.raw_content = body


class FakeRequest:
    def __init__(self, url, method="GET"):
        self.pretty_url = url
        self.method = method


class FakeFlow:
    def __init__(self, url, method="GET", status=200):
        self.id = url + method
        self.request = FakeRequest(url, method)
        self.response = FakeResponse(status)
        self.error = None


class TestSiteMap(unittest.TestCase):
    def test_link_then_flow_flips_to_visited(self):
        sitemap = SiteMap()
        entry = sitemap.add_link("https://ex.com/a", "GET", source="https://ex.com/")
        self.assertFalse(entry.visited)
        self.assertEqual(entry.sources, {"https://ex.com/"})

        same = sitemap.add_flow(FakeFlow("https://ex.com/a"))
        self.assertIs(same, entry)
        self.assertTrue(entry.visited)
        self.assertEqual(entry.status, 200)
        # still one entry, not a duplicate
        self.assertEqual(sitemap.stats(), (1, 1, 0))

    def test_methods_are_separate_entries(self):
        sitemap = SiteMap()
        sitemap.add_link("https://ex.com/login", "GET")
        sitemap.add_link("https://ex.com/login", "POST")
        self.assertEqual(sitemap.stats(), (1, 0, 2))

    def test_query_strings_are_separate_entries(self):
        sitemap = SiteMap()
        sitemap.add_link("https://ex.com/s?q=1")
        sitemap.add_link("https://ex.com/s?q=2")
        self.assertEqual(sitemap.stats(), (1, 0, 2))

    def test_hosts_are_separate_roots(self):
        sitemap = SiteMap()
        sitemap.add_link("https://a.com/x")
        sitemap.add_link("https://b.com/x")
        self.assertEqual(len(sitemap.roots), 2)

    def test_generation_advances_on_change(self):
        sitemap = SiteMap()
        before = sitemap.generation
        sitemap.add_link("https://ex.com/a")
        self.assertGreater(sitemap.generation, before)


class TestRows(unittest.TestCase):
    def setUp(self):
        self.sitemap = SiteMap()
        for i in range(1, 6):
            self.sitemap.add_link(f"https://ex.com/api/users/{i}")
        self.sitemap.add_link("https://ex.com/login", "GET")
        self.sitemap.add_link("https://ex.com/login", "POST")

    def test_single_get_is_drawn_inline(self):
        rows = self.sitemap.rows()
        leaf = [r for r in rows if r.label == "/1"][0]
        self.assertEqual(leaf.kind, "node")
        self.assertIsNotNone(leaf.entry)  # no separate entry row beneath it

    def test_multiple_methods_get_their_own_rows(self):
        rows = self.sitemap.rows()
        labels = [r.label for r in rows if r.kind == "entry"]
        self.assertEqual(sorted(labels), ["GET", "POST"])

    def test_collapse_groups_id_siblings(self):
        rows = self.sitemap.rows(collapse=True, threshold=3)
        groups = [r for r in rows if r.kind == "group"]
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].count, 5)
        # the members are hidden until the group is expanded
        self.assertNotIn("/1", [r.label for r in rows])

    def test_collapse_respects_threshold(self):
        sitemap = SiteMap()
        sitemap.add_link("https://ex.com/a/1")
        sitemap.add_link("https://ex.com/a/2")
        rows = sitemap.rows(collapse=True, threshold=3)
        self.assertEqual([r for r in rows if r.kind == "group"], [])

    def test_expanding_a_group_reveals_members(self):
        rows = self.sitemap.rows(collapse=True, threshold=3)
        group = [r for r in rows if r.kind == "group"][0]
        self.sitemap.toggle_group(group.ident)
        rows = self.sitemap.rows(collapse=True, threshold=3)
        self.assertIn("/1", [r.label for r in rows])

    def test_collapsed_node_hides_its_children(self):
        rows = self.sitemap.rows()
        api = [r for r in rows if r.label == "/api"][0]
        api.node.expanded = False
        labels = [r.label for r in self.sitemap.rows()]
        self.assertIn("/api", labels)
        self.assertNotIn("/users", labels)

    def test_scope_hides_out_of_scope_branches(self):
        rows = self.sitemap.rows(scope=Scope(include=r"/api/"), scope_only=True)
        labels = [r.label for r in rows]
        self.assertIn("/api", labels)
        self.assertNotIn("/login", labels)

    def test_scope_only_false_shows_everything(self):
        rows = self.sitemap.rows(scope=Scope(include=r"/api/"), scope_only=False)
        self.assertIn("/login", [r.label for r in rows])

    def test_unvisited_only(self):
        self.sitemap.add_flow(FakeFlow("https://ex.com/api/users/1"))
        rows = self.sitemap.rows(unvisited_only=True)
        self.assertNotIn("/1", [r.label for r in rows])
        self.assertIn("/2", [r.label for r in rows])

    def test_idents_are_stable_across_rebuilds(self):
        first = [r.ident for r in self.sitemap.rows()]
        second = [r.ident for r in self.sitemap.rows()]
        self.assertEqual(first, second)

    def test_display_passes_its_settings_through(self):
        display = Display(collapse=True, threshold=3)
        rows = display.rows(self.sitemap)
        self.assertTrue(any(r.kind == "group" for r in rows))


class TestPersistence(unittest.TestCase):
    def test_roundtrip(self):
        sitemap = SiteMap()
        sitemap.add_flow(FakeFlow("https://ex.com/a"))
        sitemap.add_link("https://ex.com/b", "POST", source="https://ex.com/a")
        text = sitemap.to_json()

        restored = SiteMap()
        self.assertEqual(restored.load_json(text), 2)
        self.assertEqual(restored.stats(), (1, 1, 1))
        entries = {e.url: e for e in restored.all_entries()}
        # status survives even though the flow object does not
        self.assertEqual(entries["https://ex.com/a"].status, 200)
        self.assertTrue(entries["https://ex.com/a"].visited)
        self.assertEqual(entries["https://ex.com/b"].sources, {"https://ex.com/a"})

    def test_load_merges_rather_than_duplicating(self):
        sitemap = SiteMap()
        sitemap.add_link("https://ex.com/a")
        self.assertEqual(sitemap.load_json(sitemap.to_json()), 0)
        self.assertEqual(sitemap.stats(), (1, 0, 1))


class TestDump(unittest.TestCase):
    def test_markers(self):
        sitemap = SiteMap()
        sitemap.add_flow(FakeFlow("https://ex.com/seen"))
        sitemap.add_link("https://ex.com/unseen")
        text = sitemap.dump()
        self.assertIn("* /seen", text)
        self.assertIn("o /unseen", text)
        self.assertIn("(link)", text)


class TestRemoval(unittest.TestCase):
    def test_remove_node_drops_subtree(self):
        sitemap = SiteMap()
        sitemap.add_link("https://ex.com/a/b")
        sitemap.add_link("https://ex.com/c")
        node = sitemap.roots["https://ex.com"].children["a"]
        sitemap.remove_node(node)
        self.assertEqual(sitemap.stats(), (1, 0, 1))

    def test_clear(self):
        sitemap = SiteMap()
        sitemap.add_link("https://ex.com/a")
        sitemap.clear()
        self.assertEqual(sitemap.stats(), (0, 0, 0))


if __name__ == "__main__":
    unittest.main()
