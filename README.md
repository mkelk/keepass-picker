# KeePass Picker

Search your KeePass vault from a keystroke and type the credential into the
window you were just in. **Read-only and offline.** KeePassXC stays the
engine, the writer and the security boundary; this plugin only asks it
questions.

![The picker: a ranked list of entries on the left, and a pane confirming the title, the app that will receive the keystrokes, username, URL and last use on the right](preview.png)

## Why you will want it

- **One keystroke, in any window.** `SUPER+SHIFT+K` opens the picker over
  whatever you are doing; `Enter` types the password into it and the picker is
  gone. `Shift+Enter` for the username, `Ctrl+Enter` for both.
- **Unlock once, not per lookup.** The vault stays open in `keepassxc-cli`'s
  own protected memory and re-locks itself after fifteen idle minutes. The bar
  glyph tells you which state it is in.
- **Ranked, and honest about why.** What you typed always wins; what you use
  breaks ties. The matched characters are highlighted, and a row says when it
  matched on the URL or the username rather than the title.
- **You see where the password is going before you press Enter.** The pane
  names the app that has focus, so a password never lands in the wrong field —
  and if focus moves while the picker is up, nothing is typed at all.
- **Nothing leaves the machine.** No network port, no daemon you did not ask
  for, no browser extension. Two small state files, neither containing a
  secret.

## Requirements

Omarchy Quattro with third-party shell plugins enabled, and:

| Package | For |
|---|---|
| `keepassxc` | `keepassxc-cli`, which holds the vault and answers every query |
| `pinentry` | `pinentry-qt`, the master-password prompt |
| `wl-clipboard` | `wl-copy --sensitive`, the paste path |
| `wtype` | pressing the paste key in the target window |
| `python` | the agent |
| `qt6ct` *(optional)* | paints the prompt in your Omarchy theme; without it the prompt is plain |

```bash
sudo pacman -S --needed keepassxc pinentry wl-clipboard wtype qt6ct
```

No AUR package, no runtime network dependency, no privileged helper, no sudo.

## Install

```bash
omarchy plugin add https://github.com/mkelk/keepass-picker.git --enable
~/.config/omarchy/plugins/mkelk.keepass-picker/bin/keepass-picker-ctl configure
```

`configure` lets you pick a `.kdbx` file. Only its **path** is stored — never a
password. It scans `$HOME` once, which can take a while over a cloud mount;
narrow it with `search_paths` if you like.

Bind a key in `~/.config/hypr/bindings.lua`:

```lua
o.bind("SUPER + SHIFT + K", "KeePass Picker", "omarchy-shell shell toggle mkelk.keepass-picker")
```

Optionally, keep the master-password prompt out of screen shares and fully
opaque — the same treatment Omarchy gives 1Password and Bitwarden. In
`~/.config/hypr/windows.lua`:

```lua
local pinentry = "^(pinentry-qt|pinentry-gtk|pinentry-gnome3|pinentry)$"
o.window(pinentry, { no_screen_share = true, float = true, center = true })
o.window(pinentry, { tag = "-default-opacity" })
o.window(pinentry, { opacity = "1 1" })
o.window(pinentry, { no_blur = true })
```

The bar widget lands in the right-hand cluster. Move it with
`omarchy bar move mkelk.keepass-picker --section right --index 0`.

### Update

```bash
omarchy plugin update mkelk.keepass-picker --yes && omarchy restart shell
```

### Remove

```bash
~/.config/omarchy/plugins/mkelk.keepass-picker/bin/keepass-picker-ctl lock
omarchy plugin remove mkelk.keepass-picker
```

The agent exits on its own once its socket is gone. Removal leaves three
things behind, none of them a secret — delete them if you want a clean slate:

- `~/.config/keepass-picker/config.json` — the database path and your settings
- `~/.local/state/keepass-picker/usage.json` — which entries you used, and when
- `~/.local/state/omarchy/keepass-picker.status.json` — the lock state the bar read

Your `.kdbx` is never modified, so there is nothing to undo there.

## Using it

Open the picker. If the vault is locked, the master-password prompt appears
straight away; cancel it and the picker tells you so. Once unlocked, an empty
query shows the entries you use most, and every keystroke narrows the list.

| Key | |
|---|---|
| type | Search titles, usernames, URLs and notes |
| `Enter` | Type the **password** into the window you came from |
| `Shift+Enter` | Type the **username** |
| `Ctrl+Enter` | Type **both** — username, Tab, password |
| `↑` `↓` / `Tab` `Shift+Tab` | Move through the results |
| `Ctrl+U` | Open the entry's URL (`http`/`https` only) |
| `Ctrl+L` | Lock the vault |
| `Esc` | Clear the query; again to dismiss |

**Enter delivers; the modifier picks the field.** That rule holds in every
window — the picker never guesses from where you are. `Ctrl+Enter` sends a real
Tab between the fields, so in a terminal it will trigger completion rather than
move to a second field; it carries no trailing Enter, so nothing runs.

Each row is the entry's title over its username. The pane beside the list
describes the row under the cursor: **title**, **will type into** (the app that
has focus), **username**, **URL** and **last used**. It shows enough to commit
with confidence and nothing that would need hiding.

The bar glyph is a padlock: closed while locked, open while unlocked. Click it
to open the picker.

## Security

The design has one rule everything else follows from: **a secret exists in
exactly two places — inside `keepassxc-cli`, and in the window you paste it
into.** Nothing in between ever holds one.

**What holds the vault.** A small agent supervises an interactive
`keepassxc-cli open` session. The database is decrypted only inside that
process, which KeePassXC marks non-dumpable — `ptrace` and `/proc/<pid>/mem`
are refused even to your own user, and it cannot write a core dump. That is
the same boundary KeePassXC itself relies on, and it was verified on a live
session rather than assumed. The agent re-locks after `idle_timeout` seconds
(default 900) or on `Ctrl+L`, and exits the moment its socket is gone rather
than linger holding an unlocked vault nothing can reach.

**What the master password touches.** Only `pinentry`. It keeps the password in
libgcrypt secure memory — `mlock`'d, never swapped, wiped on free — and exits
immediately. It is not typed into the picker on purpose: `omarchy-shell` is a
long-lived, unsandboxed process that hosts every plugin in one QML engine, and
QML strings are never zeroed. The password is never written to disk, never
placed in a command line, and never kept in a store that hands it back.

**What the agent will and will not do.** It answers `search` with entry paths,
usernames and URLs. When asked to `insert`, it fetches the field and pastes it
itself — **no secret ever crosses the socket, and no secret ever enters QML.**
It will fetch and type `UserName` and `Password` and nothing else; a request
for `Notes` or any other field is refused (`allowed_fields`). Notes routinely
hold PINs, PUKs, API keys and recovery codes, so they are never fetched,
displayed, stored or typed.

**The paste path.** `wl-copy --sensitive` holds the value only until the paste
key is pressed, then the clipboard owner exits and the value is gone. Omarchy's
clipboard history is never touched — verified byte-identical before and after.
If the focused window changes between opening the picker and the paste, the
agent aborts and tells you; mid-fill, a stray username is recoverable and a
stray password is not, so it stops there.

**What it stores.** Two files, both `0600`, neither containing a secret: a
status file with the lock state, the database's basename and a coarse
countdown; and `usage.json`, a record of which entries you used and when.
That second file is a plaintext list of which credentials you use — set
`"frecency": false` to not keep it.

**What it does not protect against — read this part.**

- **Another process running as you can already do what the picker can.** It
  can ask the agent to type any password into a window it controls, and it
  could keylog the paste regardless. The plugin does not widen that door, but
  it does not close it either: same-user isolation is a limit of the desktop,
  not of this plugin.
- **The search covers notes, and you can infer from that.** `keepassxc-cli
  search` matches title, username, URL *and notes*, and cannot be told
  otherwise. A hit that matched only in the notes is labelled so — never
  shown. For you that is useful. For a hostile same-user process it is a
  yes/no oracle over note contents. Set `"search_notes": false` to drop
  notes-only hits before anything crosses the socket.
- **Edits made elsewhere are not seen until the next unlock.** The agent
  serves what it read when the vault opened. Change a password in KeePassXC
  while the picker is unlocked and the picker will type the old one until it
  re-locks. Press `Ctrl+L` after editing.
- **The vault's own security is KeePassXC's.** This plugin adds no encryption
  and removes none; it never writes the `.kdbx`.

## Configuration

`~/.config/keepass-picker/config.json`. It holds a database path and settings,
never a password.

| Key | Default | |
|---|---|---|
| `database` | `""` | Absolute path to the `.kdbx` |
| `idle_timeout` | `900` | Seconds of inactivity before the vault re-locks; `0` disables |
| `search_notes` | `true` | `false` drops hits that matched only in the notes |
| `allowed_fields` | `["UserName", "Password"]` | The only fields the agent will fetch and type |
| `frecency` | `true` | Remember what you use, to order what you see |
| `max_results` | `60` | Applied after ranking, never before |
| `paste_key` | `"shift+Insert"` | What is pressed to paste; terminals usually want `ctrl+shift+v` |
| `fill_sequence` | `"{USERNAME}{TAB}{PASSWORD}"` | What `Ctrl+Enter` types. `{USERNAME}` `{PASSWORD}` `{TAB}` `{ENTER}` |
| `fill_step_delay` | `0.12` | Seconds between steps of a fill |
| `pre_type_delay` | `0.15` | Seconds before the first keystroke; virtual keyboards need a moment |
| `search_paths` | `$HOME` | Colon-separated roots `configure` scans for `.kdbx` files. Keep them disjoint |
| `pinentry` | `""` | Which pinentry to use; blank prefers `pinentry-qt` |
| `pinentry_icon_theme` | `""` | Blank prefers a monochrome icon set over the theme's colourful one |
| `mask_character` | `"·"` | What stands in for each typed character in the prompt |

The prompt is painted in your active Omarchy theme when `qt6ct` is installed:
the agent generates a palette from the theme's `colors.toml` and points **only
pinentry** at it, so nothing else on your desktop is affected and none of your
own Qt or GTK configuration is written. It follows a theme switch with no work.

## Development

```bash
./scripts/dev-install --restart   # mirror this tree into ~/.config/omarchy/plugins and restart the shell
./tests/run-all.sh                # the gate: 8 steps, ~3 min
omarchy plugin validate .
```

No test touches your real vault, agent or clipboard: each run gets its own
config, runtime directory, generated vault, stub pinentry and recording paste
helper, and asserts afterwards that the live session was untouched.
`tests/live-paste.sh` is the one exception and only runs when you ask it to.

How the pieces fit, the rules a change must keep, and the traps a developer
will hit are in [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Acknowledgements

This plugin stands on other people's work, and it is worth saying which.

- **[Omarchy](https://github.com/omacom/omarchy)** (MIT) — the shell and its
  plugin system, obviously; and more specifically the paste helper.
  `bin/keepass-picker-insert` is derived from Omarchy's own
  `omarchy-menu-emoji-insert`: `wl-copy --sensitive --foreground`, press the
  paste key, kill the clipboard owner. The picker's chrome follows the shipped
  overlays — the clipboard manager for the list shape, the Tailscale panel for
  the accent ring.
- **[1Passchy](https://github.com/rafaelsantana6/1passchy)** (MIT) by Rafael
  Santana — a read-only 1Password plugin for the same bar. Its `op-bridge` script
  states a four-rule security contract in its header: a secret never reaches
  QML, a secret never appears in `argv`, copies are marked `--sensitive`,
  authentication is never handled in the bridge. Those rules were adopted here
  unchanged, and the first three are the spine of this plugin's design. Also
  lifted: `umask 077`, a `0700` state directory, `0600` files, atomic replace,
  JSON-only stdout.
- **[voxtype](https://voxtype.io)** (MIT) — push-to-talk voice typing for
  Linux. Its output layer is the most considered text-injection code around,
  and its lessons shaped the paste path: paste rather than type, a
  configurable paste keystroke because terminals want `Ctrl+Shift+V`, and a
  pre-type delay because virtual keyboards drop the first character otherwise.
  Lessons, not code.
- **[KeePassXC](https://keepassxc.org)** — the engine. Every security property
  this plugin claims about the vault is KeePassXC's: the non-dumpable process,
  the format, the CLI that holds a database open. The plugin only asks it
  questions.

Related, and considered: [omarchy-keepassxc](https://github.com/japetheape/omarchy-keepassxc)
shows the KeePassXC GUI's lock state in the bar by reading its window title.
This plugin does not, because its session is independent of the GUI — the
desktop app need not be running at all.

## License

MIT. `bin/keepass-picker-insert` is derived from an MIT-licensed Omarchy script;
its notice is in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md). Not
affiliated with or endorsed by the KeePass or KeePassXC projects.
