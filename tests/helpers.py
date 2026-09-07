"""Shared fixtures. No test ever touches the real vault, agent or clipboard."""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(REPO, "bin")
sys.path.insert(0, BIN)

# AF_UNIX sun_path is ~107 bytes. A sandbox under a deep TMPDIR blows it, so
# runtime dirs go somewhere short and are cleaned up by name.
SHORT_TMP = "/tmp/kp-test"

PROBE_PASSWORD = "probe-pass"

# Entry names chosen to break a naive quoter. keepassxc-cli's interactive shell
# is not POSIX: single quotes do nothing and backslashes need escaping.
PROBE_ENTRIES = {
    "Plain":          "val-plain",
    "Space Name":     "val-space",
    'Quote"Name':     "val-dquote",
    "Single'Quote":   "val-squote",
    "Back\\slash":    "val-bslash",
}


def sandbox():
    """A private HOME-equivalent: config, runtime dir and a throwaway vault."""
    os.makedirs(SHORT_TMP, mode=0o700, exist_ok=True)
    root = tempfile.mkdtemp(prefix="kp-", dir=SHORT_TMP)
    os.chmod(root, 0o700)
    return root


def make_vault(root, password=PROBE_PASSWORD, entries=None):
    """Build a real .kdbx from scratch.

    Generated, never a committed fixture: a checked-in vault would need its
    password checked in beside it, and this way the test data cannot drift
    into resembling anything real.
    """
    entries = PROBE_ENTRIES if entries is None else entries
    path = os.path.join(root, "probe.kdbx")
    run_cli(["db-create", "-p", path], f"{password}\n{password}\n")
    for title, value in entries.items():
        run_cli(["add", "-p", "-u", "u", path, title],
                f"{password}\n{value}\n{value}\n")
    return path


def make_vault_at(path, password=PROBE_PASSWORD, entries=None):
    """A second throwaway vault, for the "database changed" case."""
    entries = {"Other": "val-other"} if entries is None else entries
    run_cli(["db-create", "-p", path], f"{password}\n{password}\n")
    for title, value in entries.items():
        run_cli(["add", "-p", "-u", "u", path, title],
                f"{password}\n{value}\n{value}\n")
    return path


def run_cli(args, stdin_text):
    proc = subprocess.run(["keepassxc-cli", *args], input=stdin_text,
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"keepassxc-cli {args[0]} failed: {proc.stderr}")
    return proc.stdout


def write_config(root, **overrides):
    cfg_dir = os.path.join(root, "config", "keepass-picker")
    os.makedirs(cfg_dir, exist_ok=True)
    cfg = {"database": os.path.join(root, "probe.kdbx"), "idle_timeout": 900,
           "pinentry": PINENTRY_NAMES[0]}
    cfg.update(overrides)
    path = os.path.join(cfg_dir, "config.json")
    with open(path, "w") as fh:
        json.dump(cfg, fh, indent=2)
    return path


# Every name the agent will try, in its own order. The stub has to cover ALL
# of them: when the agent's preference changed from pinentry-gtk to
# pinentry-qt, a stub named only "pinentry-gtk" stopped shadowing anything and
# the suite launched the REAL pinentry-qt -- a live master-password dialog on
# the user's screen, and a hung test run. Config pins the choice as well, so
# this cannot depend on ordering again.
PINENTRY_NAMES = ("pinentry-stub", "pinentry-qt", "pinentry-gnome3",
                  "pinentry-gtk", "pinentry")


def fake_pinentry(root):
    """An Assuan stub, so no test ever pops a real password dialog.

    It takes the password from $FAKE_PIN rather than baking it in, so the
    "no file under the sandbox holds the master password" assertion stays
    honest instead of having to carve out an exception for its own scaffolding.
    """
    bindir = os.path.join(root, "bin")
    os.makedirs(bindir, exist_ok=True)
    path = os.path.join(bindir, PINENTRY_NAMES[0])
    with open(path, "w") as fh:
        fh.write(
            "#!/bin/bash\n"
            "echo 'OK Pleased to meet you'\n"
            "while IFS= read -r line; do\n"
            "  case \"$line\" in\n"
            "    GETPIN) printf 'D %s\\nOK\\n' \"$FAKE_PIN\" ;;\n"
            "    BYE)    echo 'OK closing connection'; exit 0 ;;\n"
            "    *)      echo OK ;;\n"
            "  esac\n"
            "done\n")
    os.chmod(path, 0o755)
    # Shadow every other candidate too, so even a mis-set config cannot reach a
    # real binary through the sandbox PATH.
    for alias in PINENTRY_NAMES[1:]:
        link = os.path.join(bindir, alias)
        if not os.path.exists(link):
            with open(link, "w") as fh:
                fh.write(f'#!/bin/bash\nexec {path!r} "$@"\n')
            os.chmod(link, 0o755)
    return bindir


def recording_insert(root):
    """Replace the paste helper with one that records instead of pasting.

    The real helper drives the live clipboard and sends a keystroke to whatever
    window has focus. That must never happen in an unattended run.
    """
    bindir = os.path.join(root, "bin")
    os.makedirs(bindir, exist_ok=True)
    record = os.path.join(root, "pasted.txt")
    argv_log = os.path.join(root, "pasted.argv")
    path = os.path.join(bindir, "keepass-picker-insert")
    with open(path, "w") as fh:
        # Appends, so a fill sequence can be asserted as a sequence rather than
        # only its last step.
        fh.write("#!/bin/bash\n"
                 f"cat >> {record!r}\n"
                 f"printf '\\n' >> {record!r}\n"
                 f"printf '%s\\n' \"$*\" >> {argv_log!r}\n")
    os.chmod(path, 0o755)
    return path, record, argv_log


def sandbox_env(root, **extra):
    env = dict(os.environ)
    env["XDG_CONFIG_HOME"] = os.path.join(root, "config")
    env["XDG_RUNTIME_DIR"] = os.path.join(root, "run")
    # The agent writes frecency and the bar's status file under XDG_STATE_HOME.
    # Without redirecting it a test run lands probe entry paths and a probe
    # database name in the user's real state directory -- which is exactly what
    # happened the first time this was left out.
    env["XDG_STATE_HOME"] = os.path.join(root, "state")
    os.makedirs(env["XDG_RUNTIME_DIR"], mode=0o700, exist_ok=True)
    os.makedirs(env["XDG_STATE_HOME"], mode=0o700, exist_ok=True)
    env["PATH"] = os.path.join(root, "bin") + os.pathsep + env["PATH"]
    env.setdefault("FAKE_PIN", PROBE_PASSWORD)
    env.update(extra)
    return env


def ctl(root, *args, env=None):
    """Run keepass-picker-ctl inside the sandbox; returns the parsed reply."""
    proc = subprocess.run([os.path.join(BIN, "keepass-picker-ctl"), *args],
                          capture_output=True, text=True,
                          env=env or sandbox_env(root))
    out = proc.stdout.strip()
    try:
        return json.loads(out) if out else {"ok": False, "error": proc.stderr.strip()}
    except ValueError:
        return {"ok": False, "error": out or proc.stderr.strip()}


def stop_agent(root, env=None):
    env = env or sandbox_env(root)
    sock = os.path.join(env["XDG_RUNTIME_DIR"], "keepass-picker", "agent.sock")
    if os.path.exists(sock):
        ctl(root, "lock", env=env)
    for pid in agent_pids(env["XDG_RUNTIME_DIR"]):
        try:
            os.kill(pid, 15)
        except OSError:
            pass


def agent_pids(runtime_dir):
    """Every keepass-agent whose XDG_RUNTIME_DIR is this sandbox."""
    found = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as fh:
                cmdline = fh.read().decode(errors="replace")
            if "keepass-agent" not in cmdline and "keepass_agent" not in cmdline:
                continue
            with open(f"/proc/{entry}/environ", "rb") as fh:
                environ = fh.read().decode(errors="replace")
            if f"XDG_RUNTIME_DIR={runtime_dir}" in environ:
                found.append(int(entry))
        except OSError:
            continue
    return found


def cleanup(root):
    shutil.rmtree(root, ignore_errors=True)
