"""Tier 1: ranking. Pure, so it is exhaustively testable and costs nothing."""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import BIN                                          # noqa: E402

sys.path.insert(0, BIN)
import keepass_rank as kr                                        # noqa: E402

NOW = 1_800_000_000.0


def order(paths, term, **kw):
    rows, _ = kr.rank(paths, term, now=NOW, **kw)
    return [r["path"] for r in rows]


class Tiers(unittest.TestCase):
    def test_exact_title_wins(self):
        self.assertEqual(
            order(["/GitHubEnterprise", "/GitHub", "/Work/GitHub Backup"], "github")[0],
            "/GitHub")

    def test_prefix_beats_substring(self):
        self.assertEqual(order(["/MyGitHub", "/GitHubby"], "github"),
                         ["/GitHubby", "/MyGitHub"])

    def test_word_boundary_beats_mid_word(self):
        self.assertEqual(order(["/Foobar", "/Foo bar"], "bar"),
                         ["/Foo bar", "/Foobar"])

    def test_title_beats_group(self):
        self.assertEqual(order(["/github/Mail", "/Work/GitHub"], "github"),
                         ["/Work/GitHub", "/github/Mail"])

    def test_group_beats_matched_elsewhere(self):
        # "/Bank" matched only because its URL is a github lookalike.
        self.assertEqual(order(["/Bank", "/github/Thing"], "github"),
                         ["/github/Thing", "/Bank"])

    def test_matched_elsewhere_is_labelled(self):
        rows, _ = kr.rank(["/Bank"], "github", now=NOW)
        self.assertEqual(rows[0]["why"], kr.BY_OTHER)

    def test_a_title_match_says_so(self):
        rows, _ = kr.rank(["/GitHub"], "github", now=NOW)
        self.assertEqual(rows[0]["why"], kr.BY_TITLE)

    def test_case_is_ignored(self):
        self.assertEqual(order(["/github"], "GITHUB"), ["/github"])

    def test_the_measured_real_world_case(self):
        # Exactly what keepassxc-cli returned on the probe vault, in the tree
        # order it returned it: /Bank matched on a lookalike URL, /Zebra on a
        # username. Relevance must reorder them.
        rows, _ = kr.rank(["/GitHub", "/Bank", "/Zebra", "/Gitlab"], "github", now=NOW)
        self.assertEqual(rows[0]["path"], "/GitHub")
        self.assertEqual({r["path"] for r in rows[1:]}, {"/Bank", "/Zebra", "/Gitlab"})


class Explaining(unittest.TestCase):
    """Which field matched, once username and URL are known.

    Ranking still happens on the path alone -- a title match must win whatever
    any other field says. This only refines the label on the rows that will be
    shown.
    """

    def test_a_title_match_says_title(self):
        self.assertEqual(kr.explain("/GitHub", "github", "me", "x.com"), kr.BY_TITLE)

    def test_a_url_match_says_url(self):
        # The real case: several entries titled with people's names, all
        # matching because their URL is the same phone company's site.
        self.assertEqual(kr.explain("/Phones/Alex Morgan", "telco",
                                    "20000000", "www.telco.example"), kr.BY_URL)

    def test_a_username_match_says_username(self):
        self.assertEqual(kr.explain("/Phone", "2029", "20297505", "x.com"),
                         kr.BY_USERNAME)

    def test_matching_neither_means_the_notes(self):
        # keepassxc-cli searches notes, and we never fetch them -- so an entry
        # that matched nothing visible matched its notes. That is the most the
        # picker will ever say about a field holding PINs and PUKs.
        self.assertEqual(kr.explain("/Phone", "zebrafish", "u", "x.com"),
                         kr.BY_OTHER)

    def test_the_title_wins_over_a_url_that_also_matches(self):
        self.assertEqual(kr.explain("/Telco", "telco", "u", "telco.example"),
                         kr.BY_TITLE)

    def test_missing_metadata_is_not_an_error(self):
        self.assertEqual(kr.explain("/Thing", "zzz", "", ""), kr.BY_OTHER)

    def test_an_empty_term_explains_nothing(self):
        self.assertEqual(kr.explain("/Thing", "", "u", "x"), kr.BY_TITLE)


class CapIsAppliedAfterRanking(unittest.TestCase):
    """The bug this whole module exists to fix.

    keepassxc-cli returns tree order. Taking the head of that is not "the best
    60", it is "the first 60", and with hundreds of matches the entry you want can be
    absent with nothing to tell you so.
    """

    def test_the_best_match_survives_a_cap_that_would_have_cut_it(self):
        # 900 decoys ahead of the real answer in tree order.
        paths = [f"/Decoy {i} github-ish" for i in range(900)] + ["/GitHub"]
        rows, total = kr.rank(paths, "github", now=NOW, limit=60)
        self.assertEqual(total, 901)
        self.assertEqual(len(rows), 60)
        self.assertEqual(rows[0]["path"], "/GitHub")

    def test_the_total_is_reported_so_the_ui_can_say_how_many_were_held_back(self):
        rows, total = kr.rank([f"/e{i}" for i in range(500)], "e", now=NOW, limit=10)
        self.assertEqual((len(rows), total), (10, 500))

    def test_no_limit_returns_everything(self):
        rows, total = kr.rank(["/a", "/b"], "", now=NOW)
        self.assertEqual((len(rows), total), (2, 2))


class TypedAlwaysWins(unittest.TestCase):
    """Frecency and window context break ties. They never cross a tier."""

    def test_heavy_use_cannot_beat_an_exact_title_match(self):
        frecency = {"/Bank": {"count": 9999, "last_used": NOW}}
        self.assertEqual(
            order(["/Bank", "/GitHub"], "github", frecency=frecency)[0], "/GitHub")

    def test_window_context_cannot_beat_an_exact_title_match(self):
        window = {"class": "Bank", "title": "Bank — online"}
        self.assertEqual(
            order(["/Bank", "/GitHub"], "github", window=window)[0], "/GitHub")

    def test_frecency_orders_entries_that_tied(self):
        frecency = {"/GitHub Two": {"count": 40, "last_used": NOW}}
        self.assertEqual(order(["/GitHub One", "/GitHub Two"], "github",
                               frecency=frecency)[0], "/GitHub Two")

    def test_window_context_orders_entries_that_tied(self):
        window = {"class": "firefox", "title": "GitHub Two — Mozilla Firefox"}
        self.assertEqual(order(["/GitHub One", "/GitHub Two"], "github",
                               window=window)[0], "/GitHub Two")

    def test_shorter_title_breaks_a_remaining_tie(self):
        self.assertEqual(order(["/github-enterprise-server", "/github"], "github")[0],
                         "/github")


class EmptyQuery(unittest.TestCase):
    """Nothing was typed, so use and context are all there is."""

    def test_most_used_comes_first(self):
        frecency = {"/Rare": {"count": 1, "last_used": NOW},
                    "/Daily": {"count": 80, "last_used": NOW}}
        self.assertEqual(order(["/Rare", "/Daily"], "", frecency=frecency)[0], "/Daily")

    def test_recent_use_beats_stale_use(self):
        old = NOW - 200 * 86400
        frecency = {"/Stale": {"count": 60, "last_used": old},
                    "/Fresh": {"count": 12, "last_used": NOW}}
        self.assertEqual(order(["/Stale", "/Fresh"], "", frecency=frecency)[0], "/Fresh")

    def test_window_context_surfaces_the_obvious_entry(self):
        window = {"class": "firefox", "title": "Sign in · GitHub"}
        self.assertEqual(order(["/Nextcloud", "/GitHub"], "", window=window)[0],
                         "/GitHub")

    def test_with_no_history_and_no_window_it_is_at_least_stable(self):
        self.assertEqual(order(["/b", "/a"], ""), order(["/b", "/a"], ""))


class WindowMatching(unittest.TestCase):
    def test_a_very_short_title_never_matches_the_window(self):
        # "Fi" would match half the desktop.
        self.assertEqual(kr.window_bonus("/Fi", {"title": "Firefox", "class": "firefox"}), 0.0)

    def test_no_window_is_not_an_error(self):
        self.assertEqual(kr.window_bonus("/GitHub", None), 0.0)
        self.assertEqual(kr.window_bonus("/GitHub", {}), 0.0)


class Frecency(unittest.TestCase):
    def test_touch_counts_and_does_not_mutate_the_original(self):
        before = {}
        after = kr.touch(before, "/GitHub", NOW)
        self.assertEqual(before, {})
        self.assertEqual(after["/GitHub"]["count"], 1)
        self.assertEqual(kr.touch(after, "/GitHub", NOW)["/GitHub"]["count"], 2)

    def test_an_unused_entry_scores_nothing(self):
        self.assertEqual(kr.frecency_bonus("/Never", {}, NOW), 0.0)

    def test_the_bonus_decays_with_age(self):
        row = {"/E": {"count": 10, "last_used": NOW - 60 * 86400}}
        fresh = {"/E": {"count": 10, "last_used": NOW}}
        self.assertLess(kr.frecency_bonus("/E", row, NOW),
                        kr.frecency_bonus("/E", fresh, NOW))

    def test_prune_drops_what_you_stopped_using(self):
        table = {"/Ancient": {"count": 99, "last_used": NOW - 400 * 86400},
                 "/Current": {"count": 2, "last_used": NOW}}
        kept = kr.prune(table, NOW)
        self.assertIn("/Current", kept)
        self.assertNotIn("/Ancient", kept)

    def test_prune_bounds_the_table(self):
        table = {f"/e{i}": {"count": i + 1, "last_used": NOW} for i in range(900)}
        self.assertEqual(len(kr.prune(table, NOW, keep=500)), 500)


class Merging(unittest.TestCase):
    def test_duplicates_collapse_and_order_is_kept(self):
        self.assertEqual(kr.merge(["/a", "/b"], ["/b", "/c"]), ["/a", "/b", "/c"])

    def test_either_side_may_be_empty(self):
        self.assertEqual(kr.merge([], ["/a"]), ["/a"])
        self.assertEqual(kr.merge(["/a"], []), ["/a"])


class Paths(unittest.TestCase):
    def test_a_grouped_path_splits(self):
        self.assertEqual(kr.split_path("/Work/Mail/GitHub"), ("GitHub", "/Work/Mail"))

    def test_a_root_entry_reports_the_root_group(self):
        self.assertEqual(kr.split_path("/GitHub"), ("GitHub", "/"))

    def test_titles_may_contain_the_awkward_characters(self):
        self.assertEqual(kr.split_path('/Quote"Name')[0], 'Quote"Name')
        self.assertEqual(kr.split_path("/Back\\slash")[0], "Back\\slash")


if __name__ == "__main__":
    unittest.main(verbosity=2)
