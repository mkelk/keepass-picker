# Contributing

This repository **is** the plugin: `omarchy plugin add` clones it and installs
the clone root, so `manifest.json` and the two QML entry points sit at the top
level and everything here ships to a user's `~/.config/omarchy/plugins/`.

Design history, measurements and the working notes live in a private sibling
repository. Nothing from there belongs here — and nothing here may name a real
vault, a real entry, a real path under someone's home, or a real machine.

## The pieces

```
Overlay.qml            the picker: search, results, confirmation pane
BarWidget.qml          the bar glyph: lock state from a status file, no process
bin/keepass-agent      entry point -> keepass_agent.py
bin/keepass_agent.py   the agent: holds keepassxc-cli open, answers a socket, pastes
bin/keepass_rank.py    ranking, pure: no I/O, no clock
bin/keepass-picker-ctl the client both QML files call; spawns the agent on demand
bin/keepass-picker-insert  the paste: wl-copy --sensitive, press the paste key, exit
tests/                 see below
scripts/dev-install    mirror this tree into ~/.config/omarchy/plugins and rescan
```

The agent supervises an interactive `keepassxc-cli open` over a pty. The vault
is decrypted only inside that child, which KeePassXC marks non-dumpable. The
agent listens on `$XDG_RUNTIME_DIR/keepass-picker/agent.sock`, re-locks on an
idle timer, publishes a status file for the bar, and exits when its socket is
gone.

## Five rules a change must keep

Every one of these has a test. Do not weaken the test to land the change.

1. **The agent never returns a secret over the socket.** `search` answers with
   paths, usernames and URLs. `insert` and `fill` fetch the value and perform
   the paste themselves.
2. **No secret ever enters QML.** `omarchy-shell` is long-lived and unsandboxed
   and hosts every plugin in one engine; anything in a QML property stays in
   its heap for the session. There is no reveal, and there never will be.
3. **No secret in `argv`.** `/proc/<pid>/cmdline` is world-readable to the same
   user. Values travel on stdin.
4. **Only `UserName` and `Password` are ever fetched or typed.** `Notes` hold
   PINs, PUKs, API keys and recovery codes. They are searched by
   `keepassxc-cli` because it cannot be told not to, and never read by us.
5. **Never use `omarchy-clipboard-paste-text` or plain `wl-copy`.** Both write
   the value into `~/.local/state/omarchy/clipboard-history.json` in plaintext.
   The paste path is `wl-copy --sensitive --foreground`, then kill.

And one about the prompt: **the master password is typed into `pinentry`, not
into the picker.** pinentry keeps it in `mlock`'d memory and exits; the shell
does neither.

## Tests

```bash
./tests/run-all.sh                 # the gate: eight steps, ~3 minutes, every step runs
python3 tests/test_parsing.py      # pure logic, and assertions about the QML source
python3 tests/test_rank.py         # ranking: what you typed wins, what you use breaks ties
python3 tests/test_qml_tokens.py   # every Style/Color token the QML names exists
python3 tests/test_vault.py        # a real .kdbx, generated per run
python3 tests/test_agent.py        # the socket protocol and the security properties
```

Every run gets its own config, runtime directory, generated vault, stub
pinentry and recording paste helper, and asserts afterwards that the live
session was untouched: no agent started against the real runtime dir, no file
written under the real state dir, no real pinentry launched, clipboard history
byte-identical. Keep it that way — a test that reaches the real vault is a bug
in the test.

`tests/live-paste.sh` types into your focused window. It runs only when you ask
it to, and never as part of the gate.

**Tests generate their vault; nothing is committed.** A checked-in `.kdbx`
would need its password checked in beside it. The probe entries are chosen to
break a naive quoter (spaces, both kinds of quote, a backslash), not to look
real.

## Gates before a commit

- Any change: `./tests/run-all.sh` and `omarchy plugin validate .`
- QML touched: `qmllint Overlay.qml BarWidget.qml`, then
  `./scripts/dev-install --restart` before judging behaviour. The plugin is
  `keepLoaded`, so an already-instantiated overlay serves stale code after a
  plain hot-reload.
- Agent touched: `dev-install` does **not** restart the agent. Kill it
  (`pkill -f bin/keepass-agent`) after locking; the next client call spawns a
  fresh one from the installed code.
- Before any shell restart: `omarchy-shell lock isLocked` must be `false`. A
  restart kills the lock screen, which runs in the same Quickshell process.

## Traps

Each of these cost real time. Read them before they cost yours.

- **`qmllint` and `qmlformat` report a syntax error as exit 255 with no
  output at all.** Non-zero and silent means a parse error, not a lint warning.
- **`Border.surfaceSpec(section, token, fallbackColor, ...)` takes a
  fallback.** It is used only when the theme leaves the token unset. Passing
  `Color.accent` there does nothing on a theme that sets `menu.border`; build
  the spec with the colour asserted.
- **`Color.menu.selectedText` is the accent on the shipped themes.** Using it
  for a row's ink paints the selected row's title in the accent colour.
- **`menu.background` can equal the desktop background.** Taking the token
  straight leaves the card with no body. It is tinted 4.5% toward the ink.
- **Do not set `lineHeight` on the row's two lines.** A monospace face already
  leads at about 1.3×; adding 1.35 multiplies it and puts a gap back between
  the lines. The row height is measured from two invisible `Text` items in the
  real font, so it can never be shorter than its content.
- **The prompt must be a Wayland client.** Omarchy's session exports
  `QT_QPA_PLATFORM=xcb` and Hyprland forces zero XWayland scaling, so an X11
  pinentry renders at half size on a 2× display. `wayland_env()` pins the
  platform; do not remove it.
- **`keepassxc-cli`'s interactive shell is not POSIX.** Single quotes do
  nothing and a single-quoted argument silently parses to *empty*. `kpquote()`
  double-quotes with backslash escapes. Use it for every argument.
- **`hyprctl activewindow` returns a window's class and title and nothing
  else.** There is no URL. `WILL TYPE INTO` names the app — or the host for a
  Chromium web-app window, whose class carries it — and cannot do more.
- **Screenshots of the real vault are never committed.** `preview.png` was
  shot against a throwaway demo vault with a stub pinentry. If you re-shoot,
  do the same.
- **The screen is scale 2.** `hyprctl` reports logical pixels; `grim` writes
  physical ones. Measure in one unit.

## Releasing

The marketplace reads the tip of `main`. **Bump `version` in `manifest.json`**
with every release — a push with the same version ships code without marking a
release — and run `omarchy plugin validate .` first: a commit that fails
validation flips the public listing to a visible failed state.
