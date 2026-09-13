"""Tier 2: a supervised keepassxc-cli against a real, generated .kdbx.

Never the user's vault. `make_vault` builds a throwaway one per test class, so
there is no committed fixture whose password would have to be committed beside
it.
"""

import os
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import (BIN, PROBE_ENTRIES, PROBE_PASSWORD, cleanup,  # noqa: E402
                     make_vault, sandbox)

sys.path.insert(0, BIN)
import keepass_agent as ka                                        # noqa: E402


class VaultTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = sandbox()
        cls.db = make_vault(cls.root)

    @classmethod
    def tearDownClass(cls):
        cleanup(cls.root)

    def setUp(self):
        self.vault = ka.Vault(self.db)
        self.addCleanup(self.vault.lock)


class ValuesSpanningLinesAreNotTyped(unittest.TestCase):
    """What the pane shows must be what a paste would type.

    `show -a UserName -a URL` prints both as consecutive lines, so a username
    with a line break in it used to be read as a username AND an attacker's
    URL -- and the typed username was both lines while the pane showed one.
    """

    @classmethod
    def setUpClass(cls):
        cls.root = sandbox()
        cls.db = make_vault(cls.root, entries={"Multi": "val-multi", "Plain": "val-plain"},
                            usernames={"Multi": "support\nhttps://evil.example"})
        cls.vault = ka.Vault(cls.db)
        cls.vault.unlock(PROBE_PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.vault.lock()
        cleanup(cls.root)

    def test_the_pane_is_not_shown_a_forged_url(self):
        info = self.vault.meta("/Multi")
        self.assertEqual(info["url"], "")
        self.assertNotIn("evil", info["url"])
        self.assertTrue(info["username"].startswith("support"))
        self.assertIn("⏎", info["username"])

    def test_the_value_is_refused_rather_than_typed(self):
        with self.assertRaises(ka.LockedError) as caught:
            self.vault.field("/Multi", "UserName")
        self.assertIn("several lines", str(caught.exception))

    def test_single_line_values_are_untouched(self):
        self.assertEqual(self.vault.meta("/Plain"), {"username": "u", "url": ""})
        self.assertEqual(self.vault.field("/Plain", "Password"), "val-plain")


class Unlocking(VaultTestCase):
    def test_unlock_then_locked_state_is_reported_truthfully(self):
        self.assertFalse(self.vault.unlocked)
        self.vault.unlock(PROBE_PASSWORD)
        self.assertTrue(self.vault.unlocked)
        self.vault.lock()
        self.assertFalse(self.vault.unlocked)

    def test_wrong_password_raises_and_leaves_it_locked(self):
        with self.assertRaises(ka.LockedError) as caught:
            self.vault.unlock("not-the-password")
        self.assertIn("Invalid credentials", str(caught.exception))
        self.assertFalse(self.vault.unlocked)

    def test_wrong_password_leaves_no_child_behind(self):
        with self.assertRaises(ka.LockedError):
            self.vault.unlock("not-the-password")
        self.assertIsNone(self.vault.proc)

    def test_a_missing_database_refuses_rather_than_hanging(self):
        vault = ka.Vault(os.path.join(self.root, "no-such.kdbx"))
        with self.assertRaises(ka.LockedError):
            vault.unlock(PROBE_PASSWORD)

    def test_commands_refuse_while_locked(self):
        with self.assertRaises(ka.LockedError):
            self.vault.search("Plain")

    def test_a_slow_unlock_still_finds_the_prompt(self):
        # A real vault is an Argon2 KDF against a file that may live on a
        # network mount. An earlier version drained the pty for a fixed 6s and
        # would have parsed against a prompt it never saw.
        self.vault.unlock(PROBE_PASSWORD, unlock_timeout=120.0)
        self.assertTrue(self.vault.unlocked)
        self.assertTrue(self.vault.prompt.endswith("> "))

    def test_a_tiny_unlock_deadline_returns_promptly_either_way(self):
        # Whether a very fast local unlock beats a tiny deadline is a race, and
        # either outcome is correct. What must never happen is a hang.
        vault = ka.Vault(self.db)
        self.addCleanup(vault.lock)
        start = time.monotonic()
        try:
            vault.unlock(PROBE_PASSWORD, unlock_timeout=0.01)
        except ka.LockedError:
            pass
        self.assertLess(time.monotonic() - start, 15)

    def test_the_prompt_is_learned_from_the_database_name(self):
        self.vault.unlock(PROBE_PASSWORD)
        self.assertEqual(self.vault.prompt, "probe.kdbx> ")


class Retrieval(VaultTestCase):
    def setUp(self):
        super().setUp()
        self.vault.unlock(PROBE_PASSWORD)

    def test_every_adversarial_entry_name_round_trips(self):
        # The regression test for the quoting bug: with shlex.quote every one
        # of these returned an empty string instead of the password, and an
        # empty password is indistinguishable from a real one that is blank.
        for title, expected in PROBE_ENTRIES.items():
            with self.subTest(entry=title):
                self.assertEqual(self.vault.field("/" + title, "Password"),
                                 expected)

    def test_username_is_retrievable_too(self):
        self.assertEqual(self.vault.field("/Plain", "UserName"), "u")

    def test_a_missing_entry_raises_rather_than_returning_empty(self):
        # Returning "" here would surface as "password is empty for that
        # entry", which sends the user looking in the wrong place.
        with self.assertRaises(ka.LockedError) as caught:
            self.vault.field("/No Such Entry", "Password")
        self.assertIn("no such entry", str(caught.exception))

    def test_search_finds_by_substring(self):
        self.assertEqual(self.vault.search("Plain"), ["/Plain"])

    def test_search_with_a_space_finds_its_entry(self):
        self.assertIn("/Space Name", self.vault.search("Space Name"))

    def test_search_with_no_match_returns_an_empty_list(self):
        self.assertEqual(self.vault.search("zzz-no-such-term"), [])

    def test_search_never_leaks_the_no_results_banner_as_a_result(self):
        for entry in self.vault.search("zzz-no-such-term"):
            self.assertNotIn("No results", entry)

    def test_a_line_break_in_a_request_is_refused(self):
        # Otherwise it would close the command and inject a second one.
        with self.assertRaises(ka.LockedError):
            self.vault.field("/Plain\nls", "Password")


class ReadsAreBounded(unittest.TestCase):
    """`_read` extends its deadline on every chunk, so `cap` is the real bound.

    Without it a source that never stops talking keeps a read running forever,
    and the unlock deadline meant nothing -- it was checked only between reads,
    so one unbounded read always ran first.
    """

    def setUp(self):
        # A pty that never goes quiet: `yes` writes without pause.
        self.vault = ka.Vault("/nonexistent")
        self.proc = subprocess.Popen(["yes", "chatter"], stdout=subprocess.PIPE)
        self.vault.master = self.proc.stdout.fileno()
        self.addCleanup(self.proc.wait)
        self.addCleanup(self.proc.kill)

    def test_a_capped_read_returns_within_its_cap(self):
        start = time.monotonic()
        self.vault._read(0.2, quiet_for=0.5, cap=1.0)
        self.assertLess(time.monotonic() - start, 4.0)

    def test_an_uncapped_read_is_the_thing_cap_exists_to_bound(self):
        # Pins the behaviour rather than the bug: quiet_for really does keep
        # extending, which is why callers that need a ceiling must pass one.
        start = time.monotonic()
        self.vault._read(0.05, quiet_for=0.4, cap=0.8)
        capped = time.monotonic() - start
        self.assertLess(capped, 3.0)


class SessionPersistence(VaultTestCase):
    """The whole point of the agent: one unlock, many commands."""

    def test_one_unlock_serves_many_commands(self):
        self.vault.unlock(PROBE_PASSWORD)
        for _ in range(12):
            self.assertEqual(self.vault.search("Plain"), ["/Plain"])
            self.assertEqual(self.vault.field("/Plain", "Password"), "val-plain")
        self.assertTrue(self.vault.unlocked)

    def test_an_error_does_not_desynchronise_the_session(self):
        # A failed command must leave the pty at a clean prompt, or every
        # later answer is shifted by one.
        self.vault.unlock(PROBE_PASSWORD)
        with self.assertRaises(ka.LockedError):
            self.vault.field("/No Such Entry", "Password")
        self.assertEqual(self.vault.field("/Plain", "Password"), "val-plain")
        self.assertEqual(self.vault.search("Plain"), ["/Plain"])

    def test_lock_reaps_the_child(self):
        self.vault.unlock(PROBE_PASSWORD)
        pid = self.vault.proc.pid
        self.vault.lock()
        deadline = time.time() + 3
        while time.time() < deadline:
            if not os.path.exists(f"/proc/{pid}"):
                return
            time.sleep(0.05)
        self.fail(f"keepassxc-cli {pid} outlived the lock")

    def test_locking_twice_is_harmless(self):
        self.vault.unlock(PROBE_PASSWORD)
        self.vault.lock()
        self.vault.lock()
        self.assertFalse(self.vault.unlocked)


if __name__ == "__main__":
    unittest.main(verbosity=2)
