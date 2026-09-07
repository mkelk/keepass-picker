#!/usr/bin/env python3
"""Session agent for keepass-picker.

Holds one KeePass database unlocked by supervising an interactive
`keepassxc-cli open` child over a pty. The master password lives only in that
child's memory, where ptrace_scope=1 protects it -- the same boundary KeePassXC
itself relies on. It is never written to disk, never placed in argv, and never
stored anywhere that serves it back to a caller.

The agent listens on an AF_UNIX socket only (mode 0600, in a 0700 directory).
That is a local file, not a network socket: nothing here opens a port.

Contract with callers, and the reason the agent exists at all:

    THE AGENT NEVER RETURNS A SECRET OVER THE SOCKET.

`search` returns entry paths. `insert` fetches the value and performs the paste
itself. So the worst a hostile same-user process can do is trigger a paste into
the focused window -- it cannot dump the vault. See
docs/thoughts/2026-09-04-unlock-model-decision.md.
"""

import errno
import json
import os
import pty
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import termios
import time
import fcntl

import keepass_rank as rank

APP = "keepass-picker"

# Strip ANSI CSI/OSC. keepassxc-cli's readline emits bracketed-paste toggles
# (\x1b[?2004h / \x1b[?2004l) around every command.
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07")

DEFAULTS = {
    "database": "",
    "idle_timeout": 900,      # seconds of inactivity before the vault re-locks
    "pre_type_delay": 0.15,
    "paste_key": "shift+Insert",
    "max_results": 60,        # applied AFTER ranking, never before
    # Fields a caller may have fetched and typed. Notes are deliberately NOT
    # here: they hold PINs, PUKs, API keys and recovery codes, and nothing in
    # the picker's UI ever asks for them. Widen it only if you mean to.
    "allowed_fields": ["UserName", "Password"],
    # keepassxc-cli's search covers notes and cannot be told not to. This
    # cannot un-search them, but it drops the results, so nothing over the
    # socket ever confirms that a string appears in a note.
    "search_notes": True,
    "frecency": True,         # remember what you use, to order what you see
    "fill_sequence": "{USERNAME}{TAB}{PASSWORD}",
    "fill_step_delay": 0.12,
    "pinentry": "",           # blank picks the best available; see ask_password
    "pinentry_icon_theme": "",   # blank prefers a monochrome set over the theme's
    "mask_character": "\u00b7",  # what stands in for each typed character
}


def config_path():
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, APP, "config.json")


def load_config():
    cfg = dict(DEFAULTS)
    try:
        with open(config_path()) as fh:
            cfg.update(json.load(fh))
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as exc:
        log(f"config unreadable, using defaults: {exc}")
    return cfg


def runtime_dir():
    base = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    path = os.path.join(base, APP)
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def socket_path():
    return os.path.join(runtime_dir(), "agent.sock")


def state_dir():
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    path = os.path.join(base, APP)
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def usage_path():
    """Frecency. A plaintext record of which credentials are used, so 0600."""
    return os.path.join(state_dir(), "usage.json")


def status_path():
    """What the bar widget reads.

    Published here rather than answered over the socket so the bar can run a
    FileView and no process at all. A widget that spawns a helper every few
    seconds is what wedged the shell once already.
    """
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    path = os.path.join(base, "omarchy")
    os.makedirs(path, exist_ok=True)
    return os.path.join(path, "keepass-picker.status.json")


def write_private_json(path, payload):
    """Atomic replace, 0600, never a partially written file for a reader."""
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(payload, fh)
    os.replace(tmp, path)


def log(msg):
    # Never called with a secret. Keep it that way.
    print(f"[keepass-agent] {msg}", file=sys.stderr, flush=True)


class LockedError(Exception):
    """The vault is not open."""


class Vault:
    """A supervised `keepassxc-cli open` child."""

    def __init__(self, database):
        self.database = database
        self.proc = None
        self.master = None
        self.prompt = None
        self.opened_at = None

    @property
    def unlocked(self):
        return self.proc is not None and self.proc.poll() is None

    # -- pty plumbing ----------------------------------------------------

    def _read(self, timeout, quiet_for=0.35, cap=None):
        """Drain the pty until it goes quiet.

        Each chunk pushes the quiet deadline out, which is what makes this
        settle on a complete answer rather than half of one -- but it also
        means `timeout` alone bounds nothing while output keeps arriving.
        `cap` is the absolute ceiling for callers that need one.
        """
        out = b""
        deadline = time.monotonic() + timeout
        ceiling = None if cap is None else time.monotonic() + cap
        while time.monotonic() < deadline:
            if ceiling is not None and time.monotonic() >= ceiling:
                break
            ready, _, _ = select.select([self.master], [], [], 0.1)
            if not ready:
                continue
            try:
                chunk = os.read(self.master, 65536)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
            deadline = time.monotonic() + quiet_for
        return out.decode("utf-8", errors="replace")

    def _read_until_prompt(self, timeout=10.0):
        out, deadline = "", time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                out += self._read(0.3)
                raise LockedError(clean(out) or "keepassxc-cli exited")
            ready, _, _ = select.select([self.master], [], [], 0.1)
            if not ready:
                continue
            try:
                chunk = os.read(self.master, 65536)
            except OSError:
                break
            if not chunk:
                break
            out += chunk.decode("utf-8", errors="replace")
            if clean(out).endswith(self.prompt):
                return out
        raise LockedError("timed out waiting for keepassxc-cli")

    # -- lifecycle -------------------------------------------------------

    def unlock(self, password, unlock_timeout=120.0):
        """Open the database. `password` is written straight to the pty."""
        if self.unlocked:
            return
        if not self.database or not os.path.isfile(self.database):
            raise LockedError("no database configured")

        master, slave = pty.openpty()
        # A wide pty keeps readline from redisplaying long input across lines.
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 4096, 0, 0))
        self.proc = subprocess.Popen(
            ["keepassxc-cli", "open", self.database],
            stdin=slave, stdout=slave, stderr=slave,
            close_fds=True, start_new_session=True,
        )
        os.close(slave)
        self.master = master

        self._read(3.0, quiet_for=0.2)            # the password prompt
        os.write(self.master, password.encode() + b"\n")

        # Wait for the shell prompt, not for a fixed slice of time. A real vault
        # is an Argon2 KDF against a file that may live on a network mount, so
        # this can take many seconds; draining for a fixed 6s would return
        # before the prompt appeared and leave us parsing against a prompt we
        # never actually saw.
        reply, deadline = "", time.monotonic() + unlock_timeout
        opened = False
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if self.proc.poll() is not None:      # wrong password: the child dies
                reply += self._read(0.5)
                self._teardown()
                raise LockedError(first_error(reply) or "could not unlock database")
            # Bounded by what is left, so the deadline means the deadline
            # rather than "the deadline, plus one more full read".
            reply += self._read(min(1.0, remaining), quiet_for=0.3,
                                cap=remaining)
            tail = clean(reply).rstrip("\n").splitlines()
            if tail and tail[-1].endswith("> "):
                opened = True
                break
        if not opened:
            self._teardown()
            raise LockedError(
                f"keepassxc-cli did not open the database within {unlock_timeout}s")

        tail = clean(reply).rstrip("\n").splitlines()
        self.prompt = tail[-1] if tail else "> "
        self.opened_at = time.time()
        log(f"unlocked {os.path.basename(self.database)}")

    def lock(self):
        if self.proc is None:
            return
        try:
            os.write(self.master, b"exit\n")
            self.proc.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass
        self._teardown()
        log("locked")

    def _teardown(self):
        if self.proc is not None and self.proc.poll() is None:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
            except OSError:
                pass
            self.proc.wait()
        if self.master is not None:
            try:
                os.close(self.master)
            except OSError:
                pass
        self.proc = self.master = self.prompt = self.opened_at = None

    # -- commands --------------------------------------------------------

    def run(self, command):
        """Send one shell command, return its output lines."""
        if not self.unlocked:
            raise LockedError("vault is locked")
        os.write(self.master, command.encode() + b"\n")
        raw = clean(self._read_until_prompt())
        lines = raw.split("\n")
        # First line is the echoed command; last is the prompt we stopped on.
        return [ln.rstrip("\r") for ln in lines[1:-1]]

    def index(self):
        """Every entry path in the vault, once per unlock.

        Paths, never values. This is what lets the picker answer a keystroke
        without a round-trip through the cli, and what makes an empty query
        mean "your most-used" rather than "nothing".
        """
        out = self.run("ls -R -f")
        paths = []
        for line in out:
            line = line.strip()
            if not line or line.endswith("/"):
                continue          # groups, not entries
            paths.append(line if line.startswith("/") else "/" + line)
        return paths

    def search(self, term):
        out = self.run(f"search {kpquote(term)}")
        if any("No results for that search term" in ln for ln in out):
            return []
        return [ln for ln in out if ln.strip()]

    def meta(self, entry):
        """UserName and URL for one entry, in a single round-trip.

        These two and no others. Notes are searched by keepassxc-cli but are
        never fetched: they hold PINs, PUKs and recovery codes, and the picker
        has no business putting those anywhere.
        """
        out = self.run(f"show -a UserName -a URL {kpquote(entry)}")
        for line in out:
            if "Could not find entry with path" in line:
                return {"username": "", "url": ""}
        lines = [ln for ln in out]
        return {"username": lines[0] if len(lines) > 0 else "",
                "url": lines[1] if len(lines) > 1 else ""}

    def field(self, entry, name):
        """Fetch one attribute. The only method that yields a secret."""
        out = self.run(f"show -a {kpquote(name)} {kpquote(entry)}")
        for ln in out:
            if "Could not find entry with path" in ln:
                raise LockedError(f"no such entry: {entry}")
            if ln.startswith("Unknown command"):
                raise LockedError("keepassxc-cli rejected the request")
        return "\n".join(out).strip("\n")


INJECTION_RE = re.compile(r"[\r\n\x00]")


def kpquote(value):
    """Quote one argument for keepassxc-cli's interactive shell.

    Its tokenizer is NOT POSIX: it understands double quotes with backslash
    escapes, and does not understand single quotes at all. Python's
    shlex.quote produces single-quoted strings, which this shell silently
    mis-parses -- it returns an *empty* result rather than an error, so every
    entry whose path contains a space would look like an entry with an empty
    password. Verified against entry names containing a space, a double quote,
    a single quote and a backslash.
    """
    if INJECTION_RE.search(value):
        # A newline would end this command and begin another one. Refuse rather
        # than guess: this shell has no escaping that survives it.
        raise LockedError("entry path contains a line break; refusing to run it")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def clean(text):
    return ANSI_RE.sub("", text).replace("\r\n", "\n").replace("\r", "")


def first_error(text):
    for line in clean(text).splitlines():
        line = line.strip()
        if line.startswith("Error"):
            return line
    return ""


ICON_DIRS = ("/usr/share/icons", os.path.expanduser("~/.local/share/icons"))

# Preferred for the prompt because they are monochrome line icons. The set an
# Omarchy theme names is usually a full-colour desktop set -- Yaru-red here --
# which puts a filled green tick and a filled red cross on a dialog whose whole
# register is flat and grey. Subdued wins on a password prompt.
MONOCHROME_ICON_SETS = ("breeze-dark", "breeze", "Adwaita")


def icon_set_installed(name):
    return bool(name) and any(os.path.isdir(os.path.join(d, name))
                              for d in ICON_DIRS)


def theme_icon_set():
    """The icon set the active Omarchy theme names, e.g. "Yaru-red"."""
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    path = os.path.join(base, "omarchy", "current", "theme", "icons.theme")
    try:
        with open(path) as fh:
            name = fh.read().strip().splitlines()[0].strip()
    except (OSError, IndexError):
        return ""
    # Only if it is actually installed: naming a missing set is worse than
    # naming none, because Qt then finds nothing at all rather than falling
    # back, and pinentry's reveal-password button renders as an empty box.
    return name if icon_set_installed(name) else ""


def pinentry_icon_set(preferred=""):
    """Monochrome if one is available, the theme's own set otherwise."""
    if preferred:
        return preferred if icon_set_installed(preferred) else ""
    for name in MONOCHROME_ICON_SETS:
        if icon_set_installed(name):
            return name
    return theme_icon_set()


def theme_colors():
    """The active Omarchy theme's palette, or {} if it cannot be read.

    `~/.local/state/omarchy/current/theme` is the symlink omarchy-theme-set
    maintains, so this follows a theme change with no work on our part.
    """
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    path = os.path.join(base, "omarchy", "current", "theme", "colors.toml")
    try:
        import tomllib
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
        return {k: v for k, v in data.items() if isinstance(v, str)}
    except Exception:
        return {}


# Qt6 QPalette colour roles, in the order qt6ct writes them.
PALETTE_ROLES = (
    "WindowText", "Button", "Light", "Midlight", "Dark", "Mid", "Text",
    "BrightText", "ButtonText", "Base", "Window", "Shadow", "Highlight",
    "HighlightedText", "Link", "LinkVisited", "AlternateBase", "NoRole",
    "ToolTipBase", "ToolTipText", "PlaceholderText",
)


def wayland_env():
    """Make pinentry a Wayland client, whatever the agent inherited.

    MEASURED on a 2880x1800 monitor at scale 2, with Hyprland's
    `xwayland:force_zero_scaling = true`:

        QT_QPA_PLATFORM=xcb       294 x 61   xwayland: true
        QT_QPA_PLATFORM=wayland   588 x 122  xwayland: false

    Exactly half. The session exports QT_QPA_PLATFORM=xcb, so pinentry came up
    as an X11 client, and Hyprland does not upscale those -- it renders at 1x
    on a 2x display and the prompt is unreadably small.

    This is not a preference, it is a correctness fix, and it is pinned here
    rather than left to the environment because the agent can be started by
    anything: a client spawn from the shell, a login hook, a terminal. It had
    already drifted once that way.

    Falls back to whatever was inherited if there is no Wayland socket to talk
    to, so an X11 session still gets a prompt rather than none.
    """
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    socket = os.environ.get("WAYLAND_DISPLAY") or "wayland-0"
    if not runtime:
        return {}
    if not os.path.exists(os.path.join(runtime, socket)):
        # Whatever the variable says, take a socket that is actually there.
        try:
            found = sorted(n for n in os.listdir(runtime)
                           if n.startswith("wayland-") and not n.endswith(".lock"))
        except OSError:
            found = []
        if not found:
            return {}
        socket = found[0]
    return {"QT_QPA_PLATFORM": "wayland", "WAYLAND_DISPLAY": socket}


def pinentry_theme_env(icon_preference=""):
    """Point pinentry at a qt6ct config built from the active Omarchy theme.

    pinentry rejects Qt's own `-stylesheet`, and QT_QPA_PLATFORMTHEME=gtk3 --
    the session default -- hands it Adwaita-dark, because Omarchy themes
    nothing in GTK. qt6ct is a platform theme that DOES take a custom palette,
    and both QT_QPA_PLATFORMTHEME and XDG_CONFIG_HOME are per-process, so this
    repaints pinentry alone and touches no other application.

    Returns {} when qt6ct is not installed or the theme cannot be read, and
    the prompt then looks exactly as it did before.
    """
    if not which("qt6ct"):
        return {}
    c = theme_colors()
    if not c:
        return {}

    bg = c.get("background", "#121212")
    field = c.get("lighter_background", c.get("dark_background", bg))
    fg = c.get("foreground", "#bebebe")
    dim = c.get("light_foreground", fg)
    accent = c.get("accent", "#e68e0d")
    muted = c.get("muted", "#333333")

    def argb(hex_colour):
        return "#ff" + str(hex_colour).lstrip("#")

    palette = {
        "WindowText": fg, "Button": field, "Light": muted, "Midlight": muted,
        "Dark": bg, "Mid": muted, "Text": fg, "BrightText": accent,
        "ButtonText": fg, "Base": field, "Window": bg, "Shadow": bg,
        "Highlight": accent, "HighlightedText": bg, "Link": accent,
        "LinkVisited": accent, "AlternateBase": bg, "NoRole": bg,
        "ToolTipBase": field, "ToolTipText": fg, "PlaceholderText": dim,
    }
    active = ", ".join(argb(palette[r]) for r in PALETTE_ROLES)
    disabled = ", ".join(argb(dim if r.endswith("Text") else palette[r])
                         for r in PALETTE_ROLES)

    try:
        home = os.path.join(runtime_dir(), "qtconfig")
        confdir = os.path.join(home, "qt6ct")
        os.makedirs(confdir, mode=0o700, exist_ok=True)

        scheme = os.path.join(confdir, "omarchy.conf")
        with open(scheme, "w") as fh:
            fh.write("[ColorScheme]\n"
                     f"active_colors={active}\n"
                     f"inactive_colors={active}\n"
                     f"disabled_colors={disabled}\n")

        # An explicit background, because the palette alone did not give one:
        # under Fusion the dialog came out translucent and the desktop behind
        # it showed through, which is worse than the untheme it replaced.
        # qt6ct takes a stylesheet even though pinentry rejects Qt's own
        # -stylesheet argument, so this is the way in.
        sheet = os.path.join(confdir, "omarchy.qss")
        with open(sheet, "w") as fh:
            fh.write(
                f"QWidget {{ background-color: {bg}; color: {fg}; }}\n"
                f"QDialog, QMessageBox {{ background-color: {bg}; }}\n"
                f"QLabel {{ background-color: transparent; color: {fg}; }}\n"
                f"QLineEdit {{ background-color: {field}; color: {fg};"
                f" border: 1px solid {muted}; border-radius: 6px; padding: 6px 8px; }}\n"
                f"QLineEdit:focus {{ border: 1px solid {accent}; }}\n"
                f"QPushButton {{ background-color: {field}; color: {fg};"
                f" border: 1px solid {muted}; border-radius: 6px; padding: 5px 14px; }}\n"
                f"QPushButton:hover, QPushButton:default {{ border: 1px solid {accent}; }}\n"
                f"QProgressBar {{ background-color: {field}; border: 1px solid {muted};"
                " border-radius: 4px; }\n"
                f"QProgressBar::chunk {{ background-color: {accent}; }}\n")

        icons = pinentry_icon_set(icon_preference)
        with open(os.path.join(confdir, "qt6ct.conf"), "w") as fh:
            fh.write("[Appearance]\n"
                     "style=Fusion\n"
                     "custom_palette=true\n"
                     f"color_scheme_path={scheme}\n"
                     + (f"icon_theme={icons}\n" if icons else "")
                     + "standard_dialogs=default\n"
                     "\n[Fonts]\n"
                     'general="monospace,11,-1,5,50,0,0,0,0,0"\n'
                     'fixed="monospace,11,-1,5,50,0,0,0,0,0"\n'
                     "\n[Interface]\n"
                     # QSettings reads a plain path back as a one-element
                     # QStringList; the @Variant encoding qt6ct writes itself
                     # is binary and not worth reproducing by hand.
                     f"stylesheets={sheet}\n")
        return {"QT_QPA_PLATFORMTHEME": "qt6ct", "XDG_CONFIG_HOME": home}
    except OSError as exc:
        log(f"could not write the pinentry theme: {exc}")
        return {}


def ask_password(database, preferred=None, cfg=None):
    """Prompt via pinentry. The value never touches disk or argv."""
    # pinentry-qt FIRST, deliberately. pinentry-gtk is GTK2: it does not set
    # itself floating, so Hyprland tiles it into a full half-screen, and the
    # 2010-era toolkit looks nothing like the shell. pinentry-qt floats itself,
    # sizes to its content, and is Qt like omarchy-shell.
    #
    # All of them keep the passphrase in libgcrypt secure memory -- mlock'd,
    # never swapped, wiped on free. That is the reason this prompt is a
    # separate process at all rather than a field in the picker: QML strings
    # are immutable, garbage-collected and never zeroed, in a shell that lives
    # for the whole session and hosts other people's plugins.
    cfg = cfg or {}
    order = ([preferred] if preferred else []) + [
        "pinentry-qt", "pinentry-gnome3", "pinentry-gtk", "pinentry"]
    binary = next((b for b in order if b and which(b)), None)
    if binary is None:
        raise LockedError("no pinentry available to prompt for the password")

    # No stylesheet argument: pinentry parses its own options and rejects Qt's,
    # so `-stylesheet` gets "invalid option". The palette arrives through the
    # platform theme instead -- see pinentry_theme_env.
    env = dict(os.environ)
    if binary.endswith("-qt"):
        env.update(pinentry_theme_env(cfg.get("pinentry_icon_theme", "")))
        # Half-size under XWayland on a scaled monitor. See wayland_env.
        env.update(wayland_env())
    proc = subprocess.Popen([binary], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, text=True, env=env)
    name = os.path.basename(database) or "database"

    def send(line):
        proc.stdin.write(line + "\n")
        proc.stdin.flush()
        while True:
            reply = proc.stdout.readline()
            if not reply:
                raise LockedError("pinentry closed unexpectedly")
            if reply.startswith(("OK", "ERR", "D ")):
                return reply.rstrip("\n")

    try:
        proc.stdout.readline()                      # greeting
        # pinentry's layout is fixed -- a title, a description, a masked field
        # and two buttons -- so the wording is the only part of its look we
        # control. Make it read like the plugin rather than like gpg. It picks
        # up the desktop's dark theme on its own (QT_QPA_PLATFORMTHEME=gtk3).
        # A middot rather than the style's default bullet: at monospace 11
        # the bullets are chunky and run into one another. The middot is
        # also the separator the picker's own footer uses.
        send("OPTION invisible-char=" + (cfg.get("mask_character") or "\u00b7"))
        send("SETTITLE KeePass Picker")
        send(f"SETDESC Unlock {name}")
        send("SETPROMPT Master password")
        send("SETOK Unlock")
        send("SETCANCEL Cancel")
        # Do not sit on screen forever if the picker was summoned by accident
        # or the user walked away. The agent treats a timeout as a cancel.
        send("SETTIMEOUT 120")
        reply = send("GETPIN")
        if reply.startswith("ERR"):
            raise LockedError("unlock cancelled")
        if not reply.startswith("D "):
            raise LockedError("unlock cancelled")
        pin = unescape_assuan(reply[2:])
        send("BYE")
        return pin
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass
        proc.wait(timeout=5)


def unescape_assuan(value):
    out, i = [], 0
    while i < len(value):
        if value[i] == "%" and i + 2 < len(value) + 1:
            out.append(chr(int(value[i + 1:i + 3], 16)))
            i += 3
        else:
            out.append(value[i])
            i += 1
    return "".join(out)


def which(binary):
    for d in os.environ.get("PATH", "/usr/bin").split(os.pathsep):
        candidate = os.path.join(d, binary)
        if os.access(candidate, os.X_OK):
            return candidate
    return None


SEQUENCE_RE = re.compile(r"\{([A-Z]+)\}")

FILL_KEYS = {"TAB": "Tab", "ENTER": "Return"}
FILL_FIELDS = {"USERNAME": "UserName", "PASSWORD": "Password"}


def parse_sequence(text):
    """`{USERNAME}{TAB}{PASSWORD}` -> [("field","UserName"),("key","Tab"),...].

    KeePassXC's syntax, because it is the one every neighbouring tool uses.
    Unknown tokens are refused rather than skipped: a sequence that silently
    drops a step would paste a password into the wrong field.
    """
    steps, position = [], 0
    for match in SEQUENCE_RE.finditer(str(text)):
        if match.start() != position:
            raise LockedError(f"fill_sequence has stray text: {text!r}")
        token = match.group(1)
        if token in FILL_FIELDS:
            steps.append(("field", FILL_FIELDS[token]))
        elif token in FILL_KEYS:
            steps.append(("key", FILL_KEYS[token]))
        else:
            raise LockedError(f"fill_sequence has an unknown token: {{{token}}}")
        position = match.end()
    if position != len(str(text)) or not steps:
        raise LockedError(f"fill_sequence is not valid: {text!r}")
    return steps


def focused_window():
    """Address, class and title of the window a paste would land in."""
    try:
        out = subprocess.run(["hyprctl", "activewindow", "-j"],
                             capture_output=True, text=True, timeout=3)
        data = json.loads(out.stdout or "{}")
    except (OSError, ValueError, subprocess.SubprocessError):
        return {}
    if not isinstance(data, dict) or not data.get("address"):
        return {}
    return {"address": data.get("address"), "class": data.get("class") or "",
            "title": data.get("title") or ""}


def notify(title, body):
    for command in (["omarchy-notification-send", title, body],
                    ["notify-send", title, body]):
        if which(command[0]):
            try:
                subprocess.Popen(command, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
            except OSError:
                pass
            return


def press(key):
    """A bare keystroke. No secret, so argv is fine."""
    try:
        subprocess.run(["wtype", "-k", key], timeout=5,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def paste(secret, cfg):
    """Hand the secret to the insert helper on stdin -- never in argv."""
    # Overridable so the test suite can substitute a recorder: the real helper
    # drives the live clipboard and sends a keystroke to whatever window has
    # focus, which must never happen in an unattended run.
    helper = os.environ.get("KEEPASS_PICKER_INSERT") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "keepass-picker-insert")
    env = dict(os.environ,
               KEEPASS_PICKER_PASTE_KEY=str(cfg["paste_key"]),
               KEEPASS_PICKER_PRE_TYPE_DELAY=str(cfg["pre_type_delay"]))
    proc = subprocess.Popen([helper], stdin=subprocess.PIPE, env=env)
    proc.communicate(secret.encode())
    return proc.returncode == 0


class Agent:
    def __init__(self):
        self.cfg = load_config()
        self.vault = Vault(self.cfg["database"])
        self.last_activity = time.monotonic()
        self.socket_id = None
        self.lock_fd = None
        self.config_stamp = None
        self.entry_index = None          # paths only, rebuilt on each unlock
        self.meta_cache = {}             # path -> username/url, for display
        self.usage = self.load_usage()
        self.published = None
        try:
            self.config_stamp = os.stat(config_path()).st_mtime_ns
        except OSError:
            pass

    def idle_remaining(self):
        timeout = float(self.cfg["idle_timeout"])
        if timeout <= 0:
            return None
        return max(0.0, timeout - (time.monotonic() - self.last_activity))

    def expire_if_idle(self):
        remaining = self.idle_remaining()
        if remaining is not None and remaining <= 0 and self.vault.unlocked:
            log("idle timeout reached")
            self.vault.lock()
            self.entry_index = None
            self.meta_cache = {}
            self.publish()

    def handle(self, request):
        self.refresh_config()
        cmd = request.get("cmd")

        if cmd == "status":
            # unlocked_for tells the picker the vault is live before you type
            # a character. Seconds since the pty came up, or None while locked.
            opened = self.vault.opened_at
            return {
                "ok": True,
                "state": self.state(),
                "database": self.vault.database,
                "idle_remaining": self.idle_remaining(),
                "unlocked_for": (time.time() - opened) if opened else None,
            }

        if cmd == "lock":
            self.vault.lock()
            self.entry_index = None
            self.meta_cache = {}
            self.meta_cache = {}
            self.publish()
            return {"ok": True, "state": self.state()}

        if cmd == "reload":
            self.config_stamp = None      # force it, even if mtime is unchanged
            self.refresh_config()
            return {"ok": True, "state": self.state()}

        if cmd == "unlock":
            if self.vault.unlocked:
                return {"ok": True, "state": "unlocked"}
            password = ask_password(self.vault.database,
                                    self.cfg.get("pinentry"), self.cfg)
            try:
                self.vault.unlock(password)
            finally:
                del password
            self.build_index()
            self.touch()
            self.publish()
            return {"ok": True, "state": "unlocked"}

        if cmd == "search":
            self.require_unlocked()
            term = str(request.get("term", ""))
            window = request.get("window") or None
            rows, total = self.ranked(term, window)
            self.touch()
            return {"ok": True, "entries": rows, "total": total,
                    "shown": len(rows)}

        if cmd == "insert":
            self.require_unlocked()
            entry = str(request.get("entry", ""))
            name = str(request.get("field", "Password"))
            if not entry:
                return {"ok": False, "error": "no entry given"}
            if not self.field_allowed(name):
                # Least privilege: the agent's reach should be what the UI
                # actually uses, not whatever a caller thinks to ask for.
                return {"ok": False,
                        "error": f"{name} is not a field this agent will type"}
            return self.deliver(entry, [("field", name)], request)

        if cmd == "fill":
            self.require_unlocked()
            entry = str(request.get("entry", ""))
            if not entry:
                return {"ok": False, "error": "no entry given"}
            steps = parse_sequence(request.get("sequence")
                                   or self.cfg["fill_sequence"])
            for kind, value in steps:
                if kind == "field" and not self.field_allowed(value):
                    return {"ok": False,
                            "error": f"{value} is not a field this agent will type"}
            return self.deliver(entry, steps, request)

        if cmd == "target":
            # The address only. It exists solely so the overlay can hand it
            # back with a delivery request and the focus guard can tell whether
            # the window changed in between. Nothing about the window steers
            # what any key does -- that guess is what made Enter unpredictable.
            # The address drives the focus guard. The title is DISPLAY ONLY --
            # the pane states where a paste will land so a wrong window is
            # caught before Enter, not after. It steers nothing: Enter still
            # means password in every window, which is the whole point of
            # having removed window-class behaviour.
            win = focused_window()
            return {"ok": True,
                    "window": {"address": win.get("address", ""),
                               "title": win.get("title", ""),
                               "app": win.get("class", "")}}

        return {"ok": False, "error": f"unknown command: {cmd}"}

    # -- ranking ---------------------------------------------------------

    def ranked(self, term, window):
        """Candidates, ordered, then capped. Never capped before ordering."""
        limit = int(self.cfg.get("max_results", 60))
        index = self.entry_index or []

        if not term:
            # Nothing typed: frecency and window context are all there is.
            rows, total = rank.rank(index, "", frecency=self.usage,
                                    window=window, now=time.time(), limit=limit)
            return self.decorate(rows, ""), total

        # The index answers title and path matching with no round-trip.
        # keepassxc-cli's own search covers username, URL and NOTES, so it is
        # always consulted rather than only when the local pass came up thin --
        # gating it on that hid notes matches exactly when the vault was busy.
        # Measured at 1200 entries: about 5ms, which is not worth gating.
        local = [p for p in index
                 if rank.match_tier(p, term)[0] > rank.MATCHED_ELSEWHERE]
        try:
            candidates = rank.merge(local, self.vault.search(term))
        except LockedError:
            candidates = local

        rows, total = rank.rank(candidates, term, frecency=self.usage,
                                window=window, now=time.time(), limit=limit)
        rows = self.decorate(rows, term)
        if not self.cfg.get("search_notes", True):
            # A row that matched nothing visible matched its notes. Dropping it
            # closes the only channel by which a caller could confirm that a
            # guessed string appears in a note.
            dropped = [r for r in rows if r["why"] == rank.BY_OTHER]
            rows = [r for r in rows if r["why"] != rank.BY_OTHER]
            total -= len(dropped)
        return rows, total

    def field_allowed(self, name):
        allowed = self.cfg.get("allowed_fields") or ["UserName", "Password"]
        return any(str(name).lower() == str(a).lower() for a in allowed)

    # -- delivery --------------------------------------------------------

    def deliver(self, entry, steps, request):
        """Run a sequence into the focused window, guarding the target.

        The guard matters most between steps: a window that steals focus after
        the username would otherwise receive the password. Aborting half-filled
        is the right trade -- a stray username is recoverable, a stray password
        is not.
        """
        expected = str(request.get("expect_window") or "")

        def target_changed():
            if not expected:
                return False
            return focused_window().get("address") != expected

        if target_changed():
            notify("KeePass Picker", "Focus moved — nothing was pasted.")
            return {"ok": False, "error": "focus moved before pasting"}

        delivered_any = False
        for kind, value in steps:
            if kind == "key":
                if not press(value):
                    return {"ok": False, "error": f"could not press {value}"}
                time.sleep(float(self.cfg.get("fill_step_delay", 0.12)))
                continue

            secret = self.vault.field(entry, value)
            self.touch()
            if not secret:
                if not delivered_any:
                    return {"ok": False,
                            "error": f"{value} is empty for that entry"}
                del secret
                continue

            if target_changed():
                del secret
                notify("KeePass Picker",
                       "Focus moved mid-fill — the rest was not typed.")
                return {"ok": False, "error": "focus moved during the sequence"}

            ok = paste(secret, self.cfg)
            del secret
            if not ok:
                return {"ok": False, "error": "could not paste"}
            delivered_any = True
            time.sleep(float(self.cfg.get("fill_step_delay", 0.12)))

        if delivered_any:
            self.record_use(entry)
        return {"ok": True}

    def build_index(self):
        self.meta_cache = {}
        try:
            self.entry_index = self.vault.index()
            log(f"indexed {len(self.entry_index)} entries")
        except LockedError as exc:
            self.entry_index = []
            log(f"could not index the vault: {exc}")

    def decorate(self, rows, term):
        """Attach username and URL to the rows that will actually be shown.

        Lazy and cached rather than built at unlock: a full metadata sweep of
        a thousand-entry vault is a thousand round-trips, most of them for
        entries you will never look at in this session.
        """
        for row in rows:
            path = row["path"]
            info = self.meta_cache.get(path)
            if info is None:
                try:
                    info = self.vault.meta(path)
                except LockedError:
                    info = {"username": "", "url": ""}
                self.meta_cache[path] = info
            row["username"] = info["username"]
            row["url"] = info["url"]
            row["why"] = rank.explain(path, term, info["username"], info["url"])
            # When you last used it, so the pane can say "3 days ago" and settle
            # which of three identical titles is the live one. An epoch second,
            # never a secret, and absent for an entry you have not used.
            used = (self.usage or {}).get(path, {}).get("last_used")
            row["last_used"] = float(used) if used else None
        return rows

    def load_usage(self):
        if not self.cfg.get("frecency", True):
            return {}
        try:
            with open(usage_path()) as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def record_use(self, entry):
        """Remember one use, so the next empty query starts with it."""
        if not self.cfg.get("frecency", True):
            return
        now = time.time()
        self.usage = rank.prune(rank.touch(self.usage, entry, now), now)
        try:
            write_private_json(usage_path(), self.usage)
        except OSError as exc:
            log(f"could not record use: {exc}")

    # -- what the bar reads ----------------------------------------------

    def publish(self):
        """Write the status file the bar widget watches.

        The bar therefore runs one FileView and no process. Nothing here is a
        secret: a state word, the database's basename, and seconds remaining.
        """
        state = self.state()
        remaining = self.idle_remaining()
        # Coarse, and only while unlocked. A per-second countdown would rewrite
        # this file every loop and make the bar's FileView churn for nothing;
        # while locked there is no countdown worth showing at all.
        relocks_in = None
        if state == "unlocked" and remaining is not None:
            relocks_in = int(remaining // 30) * 30
        payload = {
            "state": state,
            "database": os.path.basename(self.vault.database or ""),
            "relocks_in": relocks_in,
        }
        if payload == self.published:
            return
        # `updated` is outside the comparison on purpose: it is how a reader
        # tells a live agent from a file left behind by a dead one, and it must
        # not itself be a reason to rewrite.
        payload = dict(payload, updated=int(time.time()))
        try:
            write_private_json(status_path(), payload)
            self.published = {k: v for k, v in payload.items() if k != "updated"}
        except OSError as exc:
            log(f"could not publish status: {exc}")

    def refresh_config(self):
        """Re-read the config when it changes on disk.

        A client starts the agent, so the agent routinely comes up BEFORE the
        user has chosen a database -- the bar widget polls from the moment the
        shell loads. Without this it would keep answering "no-database" for the
        life of the session, long after `configure` wrote the path.
        """
        try:
            stamp = os.stat(config_path()).st_mtime_ns
        except OSError:
            stamp = None
        if stamp == self.config_stamp:
            return
        self.config_stamp = stamp
        self.cfg = load_config()
        if self.cfg["database"] != self.vault.database:
            self.vault.lock()
            self.vault = Vault(self.cfg["database"])
            self.entry_index = None
            log("configuration changed; database reloaded")
        self.publish()

    def owns(self, path):
        try:
            live = os.stat(path)
        except OSError:
            return False
        return (live.st_dev, live.st_ino) == self.socket_id

    def state(self):
        if not self.vault.database:
            return "no-database"
        if not os.path.isfile(self.vault.database):
            return "missing-database"
        return "unlocked" if self.vault.unlocked else "locked"

    def require_unlocked(self):
        if not self.vault.unlocked:
            raise LockedError("vault is locked")

    def touch(self):
        self.last_activity = time.monotonic()

    # -- server ----------------------------------------------------------

    def serve(self):
        path = socket_path()

        # ONE agent per session. Every client auto-starts one if the socket is
        # missing, and the bar widget polls every few seconds, so without this
        # a burst of clients spawns a burst of agents that then fight over the
        # socket: each new one unlinks the live one's file and binds its own,
        # and the loser exits. Observed on the live desktop as dozens of
        # "listening" / "socket is gone" pairs and an "Address already in use".
        lock_path = os.path.join(runtime_dir(), "agent.lock")
        self.lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            log("another agent already holds the lock; exiting")
            return

        # Only now, holding the lock, is it safe to clear a stale socket --
        # nothing can be listening on it.
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(path)
        except OSError as exc:
            if exc.errno == errno.ENAMETOOLONG or "too long" in str(exc):
                raise SystemExit(
                    f"XDG_RUNTIME_DIR is too long for an AF_UNIX socket "
                    f"({len(path)} bytes, limit is ~107): {path}")
            raise
        os.chmod(path, 0o600)
        server.listen(8)
        bound = os.stat(path)
        self.socket_id = (bound.st_dev, bound.st_ino)
        log(f"listening on {path}")

        self.publish()
        try:
            while True:
                self.expire_if_idle()
                self.publish()
                if not self.owns(path):
                    # Our socket was removed or replaced -- the runtime dir was
                    # cleared, or another agent took over. Do not linger holding
                    # an unlocked vault that nothing can reach or re-lock.
                    log("socket is gone; exiting")
                    return
                ready, _, _ = select.select([server], [], [], 5.0)
                if not ready:
                    continue
                conn, _ = server.accept()
                try:
                    self.serve_one(conn)
                finally:
                    conn.close()
        finally:
            self.vault.lock()
            self.entry_index = None
            self.published = None
            self.publish()          # so the bar does not keep showing "unlocked"
            try:
                os.unlink(path)
            except OSError:
                pass

    def serve_one(self, conn):
        if not same_user(conn):
            log("rejected a connection from another uid")
            return
        conn.settimeout(120)
        try:
            data = b""
            while not data.endswith(b"\n"):
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
            request = json.loads(data.decode() or "{}")
        except (OSError, ValueError) as exc:
            reply({"ok": False, "error": f"bad request: {exc}"}, conn)
            return

        try:
            response = self.handle(request)
        except LockedError as exc:
            response = {"ok": False, "error": str(exc), "state": self.state()}
        except Exception as exc:                    # keep the agent alive
            log(f"unhandled error: {exc!r}")
            response = {"ok": False, "error": "internal error"}
        reply(response, conn)


def same_user(conn):
    creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                            struct.calcsize("3i"))
    _, uid, _ = struct.unpack("3i", creds)
    return uid == os.getuid()


def reply(payload, conn):
    try:
        conn.sendall((json.dumps(payload) + "\n").encode())
    except OSError:
        pass


def main():
    os.umask(0o077)
    agent = Agent()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: sys.exit(0))
    try:
        agent.serve()
    except SystemExit:
        agent.vault.lock()
        raise


if __name__ == "__main__":
    main()
