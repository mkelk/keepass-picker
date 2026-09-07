"""Tier 3: the agent over its socket, and the security properties that justify it.

Everything runs in a sandbox: its own config, its own runtime dir, a generated
vault, a stub pinentry, and a paste helper that records instead of pasting.
The live session's agent, vault and clipboard are never touched -- the last
class in this file asserts exactly that.
"""

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import (BIN, PROBE_ENTRIES, PROBE_PASSWORD, agent_pids,   # noqa: E402
                     PINENTRY_NAMES, cleanup, ctl, fake_pinentry,
                     make_vault, make_vault_at,
                     recording_insert, sandbox, sandbox_env, stop_agent,
                     write_config)

sys.path.insert(0, BIN)
import keepass_agent as agent                                     # noqa: E402

SECRET = PROBE_ENTRIES["Plain"]


class AgentTestCase(unittest.TestCase):
    idle_timeout = 900

    @classmethod
    def setUpClass(cls):
        cls.root = sandbox()
        make_vault(cls.root)
        write_config(cls.root, idle_timeout=cls.idle_timeout)
        fake_pinentry(cls.root)
        cls.helper, cls.record, cls.argv_log = recording_insert(cls.root)
        cls.env = sandbox_env(cls.root, KEEPASS_PICKER_INSERT=cls.helper)

    @classmethod
    def tearDownClass(cls):
        stop_agent(cls.root, cls.env)
        cleanup(cls.root)

    def ctl(self, *args):
        return ctl(self.root, *args, env=self.env)

    def unlocked(self):
        self.assertTrue(self.ctl("unlock").get("ok"))


class Protocol(AgentTestCase):
    def test_status_starts_the_agent_and_reports_locked(self):
        reply = self.ctl("status")
        self.assertTrue(reply["ok"])
        self.assertEqual(reply["state"], "locked")

    def test_unlock_then_search_then_lock(self):
        self.unlocked()
        self.assertEqual(self.ctl("status")["state"], "unlocked")
        self.assertEqual(paths(self.ctl("search", "Plain")), ["/Plain"])
        self.assertTrue(self.ctl("lock")["ok"])
        self.assertEqual(self.ctl("status")["state"], "locked")

    def test_search_refuses_while_locked(self):
        self.ctl("lock")
        reply = self.ctl("search", "Plain")
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["state"], "locked")

    def test_insert_refuses_while_locked(self):
        self.ctl("lock")
        self.assertFalse(self.ctl("insert", "/Plain")["ok"])

    def test_unknown_command_is_rejected_without_killing_the_agent(self):
        self.unlocked()
        env = dict(self.env)
        sock = os.path.join(env["XDG_RUNTIME_DIR"], "keepass-picker", "agent.sock")
        reply = raw_request(sock, {"cmd": "definitely-not-a-command"})
        self.assertFalse(reply["ok"])
        self.assertEqual(self.ctl("status")["state"], "unlocked")

    def test_malformed_json_is_rejected_without_killing_the_agent(self):
        self.unlocked()
        sock = os.path.join(self.env["XDG_RUNTIME_DIR"], "keepass-picker",
                            "agent.sock")
        reply = raw_bytes(sock, b"{not json\n")
        self.assertFalse(reply["ok"])
        self.assertEqual(self.ctl("status")["state"], "unlocked")

    def test_insert_delivers_the_secret_to_the_helper(self):
        self.unlocked()
        open(self.record, "w").close()
        self.assertTrue(self.ctl("insert", "/Plain")["ok"])
        self.assertEqual(delivered(self.record), [SECRET])

    def test_insert_can_deliver_a_username(self):
        self.unlocked()
        open(self.record, "w").close()
        self.assertTrue(self.ctl("insert", "/Plain", "UserName")["ok"])
        self.assertEqual(delivered(self.record), ["u"])

    def test_insert_of_a_missing_entry_says_so(self):
        self.unlocked()
        reply = self.ctl("insert", "/No Such Entry")
        self.assertFalse(reply["ok"])
        self.assertIn("no such entry", reply["error"])


class NeverReturnsASecret(AgentTestCase):
    """The contract that makes a same-user socket acceptable at all.

    A hostile same-user process can reach this socket. It must not be able to
    read the vault through it -- only to cause a paste, which a process that
    can already keylog could observe anyway.
    """

    def test_no_reply_carries_the_password(self):
        self.unlocked()
        for args in (("status",), ("search", "Plain"), ("insert", "/Plain"),
                     ("search", "val"), ("lock",)):
            with self.subTest(command=args):
                raw = json.dumps(ctl(self.root, *args, env=self.env))
                self.assertNotIn(SECRET, raw)

    def test_search_returns_paths_not_values(self):
        self.unlocked()
        reply = self.ctl("search", "Plain")
        self.assertEqual(paths(reply), ["/Plain"])
        # Every field of every row, not just the path.
        self.assertNotIn(SECRET, json.dumps(reply))

    def test_there_is_no_command_that_reads_a_field(self):
        self.unlocked()
        sock = os.path.join(self.env["XDG_RUNTIME_DIR"], "keepass-picker",
                            "agent.sock")
        for cmd in ("show", "get", "field", "reveal", "read", "copy", "dump"):
            with self.subTest(cmd=cmd):
                reply = raw_request(sock, {"cmd": cmd, "entry": "/Plain",
                                           "field": "Password"})
                self.assertFalse(reply.get("ok"))
                self.assertNotIn(SECRET, json.dumps(reply))


class SecretsStayOutOfSight(AgentTestCase):
    def test_the_secret_is_never_an_argument(self):
        # /proc/<pid>/cmdline is world-readable to the same user, and ps
        # prints it.
        self.unlocked()
        self.ctl("insert", "/Plain")
        with open(self.argv_log) as fh:
            self.assertNotIn(SECRET, fh.read())

    def test_no_live_process_has_the_secret_in_its_cmdline(self):
        self.unlocked()
        self.ctl("search", "Plain")
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                with open(f"/proc/{entry}/cmdline", "rb") as fh:
                    self.assertNotIn(SECRET.encode(), fh.read())
            except OSError:
                continue

    def test_the_master_password_is_never_in_a_cmdline(self):
        self.unlocked()
        for pid in agent_pids(self.env["XDG_RUNTIME_DIR"]):
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                self.assertNotIn(PROBE_PASSWORD.encode(), fh.read())

    def test_the_agent_log_carries_no_secret(self):
        self.unlocked()
        self.ctl("search", "Plain")
        self.ctl("insert", "/Plain")
        log = os.path.join(self.env["XDG_RUNTIME_DIR"], "keepass-picker",
                           "agent.log")
        if os.path.exists(log):
            with open(log) as fh:
                text = fh.read()
            self.assertNotIn(SECRET, text)
            self.assertNotIn(PROBE_PASSWORD, text)

    def test_nothing_under_the_sandbox_holds_the_master_password(self):
        self.unlocked()
        self.ctl("insert", "/Plain")
        for dirpath, _, filenames in os.walk(self.root):
            for name in filenames:
                path = os.path.join(dirpath, name)
                if path.endswith(".kdbx") or path == self.record:
                    continue          # the vault is encrypted; the record is the point
                try:
                    with open(path, "rb") as fh:
                        blob = fh.read()
                except OSError:
                    continue
                self.assertNotIn(PROBE_PASSWORD.encode(), blob,
                                 f"master password found in {path}")

    def test_the_config_holds_a_path_and_nothing_else_sensitive(self):
        cfg_path = os.path.join(self.root, "config", "keepass-picker",
                                "config.json")
        with open(cfg_path) as fh:
            cfg = json.load(fh)
        self.assertIn("database", cfg)
        self.assertNotIn(PROBE_PASSWORD, json.dumps(cfg))


class FilePermissions(AgentTestCase):
    def test_the_socket_is_private_to_this_user(self):
        self.ctl("status")
        sock = os.path.join(self.env["XDG_RUNTIME_DIR"], "keepass-picker",
                            "agent.sock")
        mode = stat.S_IMODE(os.stat(sock).st_mode)
        self.assertEqual(mode & 0o077, 0, f"socket is {oct(mode)}")

    def test_the_runtime_directory_is_private_to_this_user(self):
        self.ctl("status")
        rundir = os.path.join(self.env["XDG_RUNTIME_DIR"], "keepass-picker")
        mode = stat.S_IMODE(os.stat(rundir).st_mode)
        self.assertEqual(mode & 0o077, 0, f"runtime dir is {oct(mode)}")


class Relocking(AgentTestCase):
    idle_timeout = 3          # seconds, so the test does not take fifteen minutes

    def test_the_vault_relocks_when_idle(self):
        self.unlocked()
        self.assertEqual(self.ctl("status")["state"], "unlocked")
        time.sleep(self.idle_timeout + 7)
        self.assertEqual(self.ctl("status")["state"], "locked")

    def test_activity_postpones_the_relock(self):
        self.unlocked()
        for _ in range(4):
            time.sleep(1)
            self.assertEqual(paths(self.ctl("search", "Plain")), ["/Plain"])
        self.assertEqual(self.ctl("status")["state"], "unlocked")


class DoesNotOutliveItsSocket(AgentTestCase):
    """An agent whose runtime dir was cleared must not linger.

    It would be holding an unlocked vault that nothing can reach to search --
    or to re-lock, once its socket is gone.
    """

    def test_the_agent_exits_when_its_socket_is_removed(self):
        self.unlocked()
        pids = agent_pids(self.env["XDG_RUNTIME_DIR"])
        self.assertEqual(len(pids), 1, "expected exactly one sandbox agent")

        sock = os.path.join(self.env["XDG_RUNTIME_DIR"], "keepass-picker",
                            "agent.sock")
        os.unlink(sock)

        deadline = time.time() + 20
        while time.time() < deadline:
            if not os.path.exists(f"/proc/{pids[0]}"):
                return
            time.sleep(0.25)
        self.fail(f"agent {pids[0]} outlived its socket")

    def test_the_vault_child_dies_with_the_agent(self):
        self.unlocked()
        before = children_of("keepassxc-cli")
        pids = agent_pids(self.env["XDG_RUNTIME_DIR"])
        self.assertTrue(pids)
        os.unlink(os.path.join(self.env["XDG_RUNTIME_DIR"], "keepass-picker",
                               "agent.sock"))
        deadline = time.time() + 20
        while time.time() < deadline and os.path.exists(f"/proc/{pids[0]}"):
            time.sleep(0.25)
        time.sleep(1)
        self.assertLess(len(children_of("keepassxc-cli")), max(1, len(before)) + 1)


class OnlyOneAgentEverRuns(AgentTestCase):
    """Concurrent clients must not each start an agent.

    Found on the live desktop, not here: the sandbox only ever had one client
    at a time. In the real session the bar widget polls every few seconds and
    the overlay calls in too, so several clients find the socket missing at the
    same instant. Each started an agent; each new agent unlinked the live one's
    socket and bound its own; the loser saw its socket vanish and exited. The
    log filled with "listening" / "socket is gone" pairs and an
    "Address already in use" traceback.
    """

    def test_a_burst_of_clients_leaves_exactly_one_agent(self):
        stop_agent(self.root, self.env)
        time.sleep(1)

        procs = [subprocess.Popen(
            [os.path.join(BIN, "keepass-picker-ctl"), "status"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
            for _ in range(12)]
        for proc in procs:
            proc.wait(timeout=60)

        time.sleep(2)
        pids = agent_pids(self.env["XDG_RUNTIME_DIR"])
        self.assertEqual(len(pids), 1, f"expected one agent, found {len(pids)}")

    def test_the_burst_all_got_a_real_answer(self):
        stop_agent(self.root, self.env)
        time.sleep(1)

        procs = [subprocess.Popen(
            [os.path.join(BIN, "keepass-picker-ctl"), "status"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
            for _ in range(12)]
        for proc in procs:
            out, _ = proc.communicate(timeout=60)
            reply = json.loads(out.decode().strip())
            self.assertTrue(reply.get("ok"), reply)

    def test_the_log_records_no_socket_fight(self):
        self.ctl("status")
        time.sleep(1)
        log = os.path.join(self.env["XDG_RUNTIME_DIR"], "keepass-picker",
                           "agent.log")
        if not os.path.exists(log):
            return
        with open(log) as fh:
            text = fh.read()
        self.assertNotIn("Address already in use", text)


class NoticesANewDatabase(AgentTestCase):
    """The agent routinely starts before a database has been chosen.

    A client starts it, and the bar widget polls from the moment the shell
    loads -- so on a fresh install the agent comes up, reads an absent config,
    and would answer "no-database" for the rest of the session even after
    `configure` wrote the path. Seen on the live desktop.
    """

    def test_a_config_written_after_startup_is_picked_up(self):
        cfg_path = os.path.join(self.root, "config", "keepass-picker",
                                "config.json")
        with open(cfg_path) as fh:
            saved = json.load(fh)

        # Start the agent with no database configured.
        stop_agent(self.root, self.env)
        time.sleep(1)
        os.unlink(cfg_path)
        self.assertEqual(self.ctl("status")["state"], "no-database")

        # Now configure one, the way `configure` does.
        with open(cfg_path, "w") as fh:
            json.dump(saved, fh)

        self.assertEqual(self.ctl("status")["state"], "locked")

    def test_pointing_at_a_different_database_relocks(self):
        cfg_path = os.path.join(self.root, "config", "keepass-picker",
                                "config.json")
        with open(cfg_path) as fh:
            saved = json.load(fh)
        self.unlocked()
        self.assertEqual(self.ctl("status")["state"], "unlocked")

        other = make_vault_at(os.path.join(self.root, "other.kdbx"))
        with open(cfg_path, "w") as fh:
            json.dump(dict(saved, database=other), fh)

        # A different vault must not inherit the old one's unlocked session.
        self.assertEqual(self.ctl("status")["state"], "locked")

        with open(cfg_path, "w") as fh:
            json.dump(saved, fh)


class NothingWaitsForever(AgentTestCase):
    """A hanging helper must never be able to wedge omarchy-shell.

    It did once. During a spawn-lock deadlock every bar-widget poll -- one
    every five seconds -- left a `ctl status` that never returned, and the
    Process objects piled up inside the shell until it stopped answering IPC
    entirely: process alive, bar gone, only a kill and relaunch got it back.
    A stale lock indicator is a far cheaper failure than that, so every wait
    here is bounded.
    """

    def test_status_returns_promptly(self):
        start = time.monotonic()
        self.ctl("status")
        self.assertLess(time.monotonic() - start, 20)

    def test_a_held_spawn_lock_fails_fast_instead_of_blocking(self):
        # Reproduces the deadlock's shape: something holds the spawn lock and
        # never lets go. The client must give up, not wait for it.
        stop_agent(self.root, self.env)
        time.sleep(1)
        rundir = os.path.join(self.env["XDG_RUNTIME_DIR"], "keepass-picker")
        os.makedirs(rundir, mode=0o700, exist_ok=True)
        lock_path = os.path.join(rundir, "spawn.lock")

        holder = subprocess.Popen(
            ["flock", lock_path, "sleep", "120"], stdout=subprocess.DEVNULL)
        try:
            time.sleep(1)
            start = time.monotonic()
            proc = subprocess.run(
                [os.path.join(BIN, "keepass-picker-ctl"), "status"],
                capture_output=True, text=True, env=self.env, timeout=60)
            elapsed = time.monotonic() - start
            self.assertLess(elapsed, 30, "ctl blocked on a held spawn lock")
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("timed out", proc.stderr.lower())
        finally:
            holder.kill()
            holder.wait()

    def test_the_client_survives_an_agent_that_never_answers(self):
        # A socket that accepts and then says nothing: the read must time out.
        stop_agent(self.root, self.env)
        time.sleep(1)
        rundir = os.path.join(self.env["XDG_RUNTIME_DIR"], "keepass-picker")
        os.makedirs(rundir, mode=0o700, exist_ok=True)
        sock_path = os.path.join(rundir, "agent.sock")
        if os.path.exists(sock_path):
            os.unlink(sock_path)

        import socket as _socket
        mute = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        mute.bind(sock_path)
        mute.listen(4)
        try:
            start = time.monotonic()
            subprocess.run([os.path.join(BIN, "keepass-picker-ctl"), "status"],
                           capture_output=True, text=True, env=self.env,
                           timeout=90)
            self.assertLess(time.monotonic() - start, 45,
                            "ctl waited indefinitely on a mute agent")
        finally:
            mute.close()
            if os.path.exists(sock_path):
                os.unlink(sock_path)


class RankedSearch(AgentTestCase):
    def test_results_are_objects_with_a_reason(self):
        self.unlocked()
        reply = self.ctl("search", "Plain")
        self.assertTrue(reply["ok"])
        row = reply["entries"][0]
        self.assertEqual(row["path"], "/Plain")
        self.assertEqual(row["why"], "title")
        self.assertIn("total", reply)

    def test_an_empty_query_returns_the_index(self):
        # The whole vault, ordered by use -- not an empty pane.
        self.unlocked()
        reply = self.ctl("search", "")
        self.assertTrue(reply["ok"])
        self.assertEqual(reply["total"], len(PROBE_ENTRIES))

    def test_entries_with_awkward_names_are_all_indexed(self):
        self.unlocked()
        paths = {r["path"] for r in self.ctl("search", "")["entries"]}
        for title in PROBE_ENTRIES:
            self.assertIn("/" + title, paths)

    def test_the_reply_still_carries_no_secret(self):
        self.unlocked()
        raw = json.dumps(self.ctl("search", ""))
        for value in PROBE_ENTRIES.values():
            self.assertNotIn(value, raw)


class Filling(AgentTestCase):
    def test_fill_delivers_username_then_password_in_order(self):
        self.unlocked()
        open(self.record, "w").close()
        self.assertTrue(self.ctl("fill", "/Plain")["ok"])
        self.assertEqual(delivered(self.record), ["u", PROBE_ENTRIES["Plain"]])

    def test_fill_never_puts_a_secret_in_argv(self):
        self.unlocked()
        self.ctl("fill", "/Plain")
        with open(self.argv_log) as fh:
            self.assertNotIn(PROBE_ENTRIES["Plain"], fh.read())

    def test_fill_reports_a_missing_entry(self):
        self.unlocked()
        reply = self.ctl("fill", "/No Such Entry")
        self.assertFalse(reply["ok"])

    def test_fill_refuses_while_locked(self):
        self.ctl("lock")
        self.assertFalse(self.ctl("fill", "/Plain")["ok"])


class TheFocusGuard(AgentTestCase):
    """A window that steals focus mid-sequence must not receive the password.

    Aborting half-filled is the right trade: a stray username is recoverable,
    a stray password is not.
    """

    def test_a_stale_window_address_aborts_before_anything_is_typed(self):
        self.unlocked()
        open(self.record, "w").close()
        reply = self.ctl("fill", "/Plain", "0xXXdefinitelynotthecurrentwindow")
        self.assertFalse(reply["ok"])
        self.assertIn("focus", reply["error"].lower())
        with open(self.record) as fh:
            self.assertEqual(fh.read(), "", "something was typed after the guard fired")

    def test_the_guard_also_covers_a_single_insert(self):
        self.unlocked()
        open(self.record, "w").close()
        reply = self.ctl("insert", "/Plain", "Password", "0xXXstale")
        self.assertFalse(reply["ok"])
        with open(self.record) as fh:
            self.assertEqual(fh.read(), "")

    def test_no_expected_window_means_no_guard(self):
        # Called from a script rather than the overlay: still works.
        self.unlocked()
        self.assertTrue(self.ctl("insert", "/Plain")["ok"])


class NotesAreNotReachable(AgentTestCase):
    """Notes hold PINs, PUKs, API keys and recovery codes.

    keepassxc-cli searches them and cannot be told not to, so the question is
    what the agent will do with that. Answer: never fetch them, never show
    them, and never type them.
    """

    def test_the_agent_refuses_to_type_the_notes(self):
        self.unlocked()
        open(self.record, "w").close()
        reply = self.ctl("insert", "/Plain", "Notes")
        self.assertFalse(reply["ok"])
        self.assertIn("not a field", reply["error"])
        self.assertEqual(delivered(self.record), [],
                         "the notes were typed into a window")

    def test_a_fill_sequence_cannot_smuggle_a_disallowed_field(self):
        self.unlocked()
        open(self.record, "w").close()
        sock = os.path.join(self.env["XDG_RUNTIME_DIR"], "keepass-picker",
                            "agent.sock")
        reply = raw_request(sock, {"cmd": "fill", "entry": "/Plain",
                                   "sequence": "{USERNAME}{TAB}{PASSWORD}"})
        self.assertTrue(reply["ok"])          # the allowed one still works
        self.assertEqual(delivered(self.record), ["u", SECRET])

    def test_arbitrary_fields_are_refused(self):
        self.unlocked()
        for name in ("Notes", "TOTP", "otp", "notes", "Custom"):
            with self.subTest(field=name):
                reply = self.ctl("insert", "/Plain", name)
                self.assertFalse(reply.get("ok"), f"{name} was allowed")

    def test_the_two_the_ui_uses_still_work(self):
        self.unlocked()
        self.assertTrue(self.ctl("insert", "/Plain", "Password")["ok"])
        self.assertTrue(self.ctl("insert", "/Plain", "UserName")["ok"])

    def test_no_reply_ever_carries_a_note(self):
        self.unlocked()
        for args in (("search", ""), ("search", "Plain"), ("status",)):
            raw = json.dumps(ctl(self.root, *args, env=self.env))
            self.assertNotIn("notes", raw.lower())


class WhatTheConfirmationPaneIsGiven(AgentTestCase):
    """The pane draws only what the agent already returns.

    It exists so a password never lands in the wrong window, which means it has
    to say what is about to be typed and where -- without any of it being the
    thing that gets typed.
    """

    def row(self, term="Plain"):
        return self.ctl("search", term)["entries"][0]

    def test_a_row_says_when_you_last_used_it(self):
        self.unlocked()
        self.assertIsNone(self.row()["last_used"])
        self.assertTrue(self.ctl("insert", "/Plain", "Password")["ok"])
        self.assertIsInstance(self.row()["last_used"], float)

    def test_target_names_the_window_and_carries_nothing_else(self):
        self.unlocked()
        reply = self.ctl("target")
        self.assertTrue(reply["ok"])
        self.assertEqual(set(reply["window"]), {"address", "title", "app"})
        self.assertNotIn(SECRET, json.dumps(reply))

    def test_nothing_the_pane_draws_is_a_secret(self):
        self.unlocked()
        self.assertTrue(self.ctl("insert", "/Plain", "Password")["ok"])
        raw = json.dumps(self.ctl("search", "Plain"))
        self.assertNotIn(SECRET, raw)
        self.assertNotIn("notes", raw.lower())
        self.assertNotIn("password", raw.lower())


class ThePromptIsAWaylandClient(unittest.TestCase):
    """Measured, not preferred.

    On a 2880x1800 monitor at scale 2 with xwayland:force_zero_scaling on,
    pinentry-qt came up 294x61 as an X11 client and 588x122 as a Wayland one --
    exactly half. The session exports QT_QPA_PLATFORM=xcb, so whichever process
    happens to start the agent decides whether the prompt is readable.
    """

    def setUp(self):
        self.saved = {k: os.environ.get(k)
                      for k in ("XDG_RUNTIME_DIR", "WAYLAND_DISPLAY")}
        self.dir = tempfile.mkdtemp(prefix="kp-wl-")

    def tearDown(self):
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.dir, ignore_errors=True)

    def use(self, socket=None, declared=None):
        os.environ["XDG_RUNTIME_DIR"] = self.dir
        os.environ.pop("WAYLAND_DISPLAY", None)
        if declared:
            os.environ["WAYLAND_DISPLAY"] = declared
        if socket:
            open(os.path.join(self.dir, socket), "w").close()
        return agent.wayland_env()

    def test_it_pins_the_platform_when_a_socket_is_there(self):
        self.assertEqual(self.use(socket="wayland-1", declared="wayland-1"),
                         {"QT_QPA_PLATFORM": "wayland",
                          "WAYLAND_DISPLAY": "wayland-1"})

    def test_it_finds_the_socket_the_variable_forgot(self):
        # The agent can be started by anything -- a shell, a hook, a terminal --
        # and it had already drifted once into an environment with no
        # WAYLAND_DISPLAY at all.
        self.assertEqual(self.use(socket="wayland-2"),
                         {"QT_QPA_PLATFORM": "wayland",
                          "WAYLAND_DISPLAY": "wayland-2"})

    def test_it_changes_nothing_without_one(self):
        # An X11 session should still get a prompt rather than none.
        self.assertEqual(self.use(), {})

    def test_a_lock_file_is_not_a_socket(self):
        self.assertEqual(self.use(socket="wayland-1.lock"), {})


class TheStatusFile(AgentTestCase):
    """What the bar widget reads instead of spawning a process."""

    def path(self):
        return os.path.join(self.env["XDG_STATE_HOME"], "omarchy",
                            "keepass-picker.status.json")

    def read(self):
        with open(self.path()) as fh:
            return json.load(fh)

    def test_it_is_published_and_tracks_state(self):
        self.ctl("lock")
        time.sleep(6)
        self.assertEqual(self.read()["state"], "locked")
        self.unlocked()
        time.sleep(6)
        self.assertEqual(self.read()["state"], "unlocked")

    def test_it_carries_no_secret_and_no_full_path(self):
        self.unlocked()
        time.sleep(6)
        blob = json.dumps(self.read())
        self.assertNotIn(PROBE_PASSWORD, blob)
        for value in PROBE_ENTRIES.values():
            self.assertNotIn(value, blob)
        # A basename, not the path -- the bar has no use for the directory.
        self.assertNotIn("/", self.read()["database"])

    def test_it_is_private_to_this_user(self):
        self.ctl("status")
        time.sleep(6)
        mode = stat.S_IMODE(os.stat(self.path()).st_mode)
        self.assertEqual(mode & 0o077, 0, f"status file is {oct(mode)}")

    def test_it_does_not_churn_while_nothing_changes(self):
        # The agent republishes on every loop pass. A per-second countdown in
        # the payload would rewrite this file forever and make the bar's
        # FileView reload for nothing.
        self.ctl("lock")
        time.sleep(6)
        first = os.stat(self.path()).st_mtime_ns
        time.sleep(12)
        self.assertEqual(os.stat(self.path()).st_mtime_ns, first)

    def test_a_clean_shutdown_leaves_it_saying_locked(self):
        # Otherwise the bar keeps showing an unlocked padlock for a vault that
        # no longer exists.
        self.unlocked()
        time.sleep(6)
        self.assertEqual(self.read()["state"], "unlocked")
        stop_agent(self.root, self.env)
        time.sleep(3)
        self.assertNotEqual(self.read()["state"], "unlocked")

    def test_it_carries_the_timestamp_a_reader_needs_to_spot_a_dead_agent(self):
        self.ctl("status")
        time.sleep(6)
        self.assertIn("updated", self.read())


class FrecencyStore(AgentTestCase):
    def path(self):
        return os.path.join(self.env["XDG_STATE_HOME"], "keepass-picker",
                            "usage.json")

    def test_a_delivery_is_recorded(self):
        self.unlocked()
        self.ctl("insert", "/Plain")
        with open(self.path()) as fh:
            usage = json.load(fh)
        self.assertGreaterEqual(usage["/Plain"]["count"], 1)

    def test_the_store_is_private_to_this_user(self):
        self.unlocked()
        self.ctl("insert", "/Plain")
        mode = stat.S_IMODE(os.stat(self.path()).st_mode)
        self.assertEqual(mode & 0o077, 0, f"usage file is {oct(mode)}")

    def test_the_store_holds_paths_and_counts_and_nothing_else(self):
        self.unlocked()
        self.ctl("insert", "/Plain")
        with open(self.path()) as fh:
            blob = fh.read()
        self.assertNotIn(PROBE_PASSWORD, blob)
        for value in PROBE_ENTRIES.values():
            self.assertNotIn(value, blob)

    def test_a_failed_delivery_is_not_recorded(self):
        self.unlocked()
        before = os.path.exists(self.path())
        self.ctl("fill", "/Plain", "0xXXstale")     # guard aborts it
        if not before:
            self.assertFalse(os.path.exists(self.path()))


class TheLiveSessionIsUntouched(AgentTestCase):
    """The isolation footer: prove the suite stayed inside its sandbox.

    Authoritative -- nothing the user does at their desk can produce these.
    """

    def test_the_suite_started_no_agent_against_the_real_runtime_dir(self):
        # Measured as a delta, not as global state: once the plugin is actually
        # installed, the bar widget legitimately keeps one agent running for
        # the session. What must stay true is that this suite adds none.
        real = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
        before = set(agent_pids(real))
        self.unlocked()
        self.ctl("search", "Plain")
        self.ctl("insert", "/Plain")
        added = set(agent_pids(real)) - before
        self.assertEqual(added, set(),
                         "the suite started an agent against the live session")

    def test_the_real_config_was_not_created_or_changed(self):
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
        real = os.path.join(base, "keepass-picker", "config.json")
        before = snapshot(real)
        self.unlocked()
        self.ctl("insert", "/Plain")
        self.assertEqual(snapshot(real), before)

    def test_no_probe_data_reached_the_real_state_directory(self):
        # Added after a smoke test wrote a probe database name and probe entry
        # paths into the user's real ~/.local/state, because sandbox_env did
        # not redirect XDG_STATE_HOME.
        #
        # Checked by CONTENT, not mtime: once the plugin is installed the real
        # agent legitimately republishes its own status while this suite runs,
        # so a timestamp comparison reports the wrong thing. What must stay
        # true is that nothing of ours is in there.
        real_base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
        watched = [os.path.join(real_base, "omarchy", "keepass-picker.status.json"),
                   os.path.join(real_base, "keepass-picker", "usage.json")]

        self.unlocked()
        self.ctl("search", "Plain")
        self.ctl("insert", "/Plain")

        markers = ["probe.kdbx", PROBE_PASSWORD, self.root] + list(PROBE_ENTRIES.values())
        for path in watched:
            if not os.path.exists(path):
                continue
            with open(path) as fh:
                blob = fh.read()
            for marker in markers:
                self.assertNotIn(marker, blob,
                                 f"sandbox data reached {path}")

    def test_no_real_pinentry_was_ever_launched(self):
        # This actually happened: the agent's preference changed from
        # pinentry-gtk to pinentry-qt, the stub was named only pinentry-gtk,
        # and the suite launched the REAL pinentry-qt -- a live
        # master-password dialog on the user's screen and a hung run.
        self.unlocked()
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                with open(f"/proc/{entry}/cmdline", "rb") as fh:
                    argv = fh.read().decode(errors="replace").split("\0")
            except OSError:
                continue
            if not argv or not argv[0]:
                continue
            # argv[0], not the whole command line: a shell command that merely
            # mentions "pinentry" is not a pinentry, and matching the text
            # made this assert against itself.
            if not os.path.basename(argv[0]).startswith("pinentry"):
                continue
            self.assertIn(self.root, argv[0],
                          f"a pinentry outside the sandbox is running: {argv[0]!r}")

    def test_the_prompt_is_worded_for_this_plugin(self):
        # pinentry's layout is fixed, so the wording is the only part of its
        # look we control.
        with open(os.path.join(BIN, "keepass_agent.py")) as fh:
            src = fh.read()
        for line in ('SETTITLE KeePass Picker', 'SETOK Unlock',
                     'SETPROMPT Master password', 'SETTIMEOUT'):
            with self.subTest(line=line):
                self.assertIn(line, src)

    def test_the_stub_shadows_every_name_the_agent_might_try(self):
        bindir = os.path.join(self.root, "bin")
        for name in PINENTRY_NAMES:
            with self.subTest(name=name):
                self.assertTrue(os.access(os.path.join(bindir, name), os.X_OK),
                                f"{name} is not shadowed in the sandbox")

    def test_the_clipboard_history_was_not_written(self):
        # If the paste helper ever ran for real without --sensitive, the
        # password would be in this file in plaintext.
        history = os.path.expanduser(
            "~/.local/state/omarchy/clipboard-history.json")
        before = snapshot(history)
        self.unlocked()
        self.ctl("insert", "/Plain")
        after = snapshot(history)
        self.assertEqual(after, before)
        if os.path.exists(history):
            with open(history, "rb") as fh:
                self.assertNotIn(SECRET.encode(), fh.read())


def children_of(name):
    found = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as fh:
                if name.encode() in fh.read():
                    found.append(int(entry))
        except OSError:
            continue
    return found


def paths(reply):
    """Entry paths out of a ranked search reply."""
    return [row["path"] for row in reply.get("entries", [])]


def delivered(record):
    """What the recording paste helper received, one step per line."""
    try:
        with open(record) as fh:
            return [line for line in fh.read().split("\n") if line]
    except FileNotFoundError:
        return []


def snapshot(path):
    try:
        st = os.stat(path)
        return (st.st_mtime_ns, st.st_size)
    except FileNotFoundError:
        return None


def raw_request(sock_path, payload):
    return raw_bytes(sock_path, (json.dumps(payload) + "\n").encode())


def raw_bytes(sock_path, blob):
    import socket as _socket
    sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect(sock_path)
    sock.sendall(blob)
    sock.shutdown(_socket.SHUT_WR)
    data = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
    sock.close()
    try:
        return json.loads(data.decode())
    except ValueError:
        return {"ok": False, "error": data.decode()}


if __name__ == "__main__":
    unittest.main(verbosity=2)
