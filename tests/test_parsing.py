"""Tier 1: pure logic. No vault, no child processes, no I/O."""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import BIN, REPO                                    # noqa: E402

sys.path.insert(0, BIN)
import keepass_agent as ka                                       # noqa: E402


class Quoting(unittest.TestCase):
    """keepassxc-cli's shell is not POSIX. This is the rule that fits it."""

    def test_plain_word_is_still_quoted(self):
        self.assertEqual(ka.kpquote("Plain"), '"Plain"')

    def test_spaces_survive(self):
        self.assertEqual(ka.kpquote("Space Name"), '"Space Name"')

    def test_double_quote_is_backslash_escaped(self):
        self.assertEqual(ka.kpquote('Quote"Name'), '"Quote\\"Name"')

    def test_backslash_is_doubled(self):
        self.assertEqual(ka.kpquote("Back\\slash"), '"Back\\\\slash"')

    def test_single_quote_is_left_alone(self):
        # Single quotes are not special to this shell; quoting them would break it.
        self.assertEqual(ka.kpquote("Single'Quote"), '"Single\'Quote"')

    def test_never_emits_a_single_quoted_string(self):
        # The bug this function exists to prevent: shlex.quote produces
        # '...' which this shell mis-parses into an empty result, so an entry
        # with a space looks like an entry with an empty password.
        for name in ("Space Name", "a b c", "x'y"):
            self.assertFalse(ka.kpquote(name).startswith("'"))

    def test_line_break_is_refused_not_escaped(self):
        # A newline would end the command and start another one.
        for hostile in ("a\nsearch b", "a\r\nb", "a\x00b"):
            with self.assertRaises(ka.LockedError):
                ka.kpquote(hostile)


class AnsiStripping(unittest.TestCase):
    def test_strips_bracketed_paste_toggles(self):
        raw = "ls\r\n\x1b[?2004l\rExample Entry\r\n\x1b[?2004hprobe.kdbx> "
        self.assertEqual(ka.clean(raw), "ls\nExample Entry\nprobe.kdbx> ")

    def test_leaves_plain_text_alone(self):
        self.assertEqual(ka.clean("nothing to strip"), "nothing to strip")

    def test_normalises_crlf(self):
        self.assertEqual(ka.clean("a\r\nb\rc"), "a\nbc")

    def test_a_password_of_escape_characters_is_not_mangled(self):
        # Passwords are output, not echoed input, so they must survive intact.
        self.assertEqual(ka.clean("p@ss[]{}?w0rd"), "p@ss[]{}?w0rd")


class ErrorExtraction(unittest.TestCase):
    def test_finds_the_invalid_credentials_line(self):
        raw = ("\r\nError while reading the database: Invalid credentials were "
               "provided, please try again.\r\nIf this reoccurs, then your "
               "database file may be corrupt.\r\n")
        self.assertIn("Invalid credentials", ka.first_error(raw))

    def test_returns_empty_when_there_is_no_error(self):
        self.assertEqual(ka.first_error("probe.kdbx> "), "")


class AssuanDecoding(unittest.TestCase):
    def test_percent_escapes_are_decoded(self):
        self.assertEqual(ka.unescape_assuan("a%25b"), "a%b")
        self.assertEqual(ka.unescape_assuan("a%0Ab"), "a\nb")

    def test_plain_password_passes_through(self):
        self.assertEqual(ka.unescape_assuan("correct horse"), "correct horse")


class Config(unittest.TestCase):
    def test_defaults_apply_when_no_file_exists(self):
        env = dict(os.environ, XDG_CONFIG_HOME="/nonexistent-kp-test")
        old = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = env["XDG_CONFIG_HOME"]
        try:
            cfg = ka.load_config()
            self.assertEqual(cfg["database"], "")
            self.assertEqual(cfg["paste_key"], "shift+Insert")
            self.assertGreater(cfg["idle_timeout"], 0)
        finally:
            if old is None:
                del os.environ["XDG_CONFIG_HOME"]
            else:
                os.environ["XDG_CONFIG_HOME"] = old

    def test_defaults_carry_no_password_key(self):
        # Nothing in the config schema is a place to put a master password.
        self.assertNotIn("password", " ".join(ka.DEFAULTS).lower())


class PasteKeyParsing(unittest.TestCase):
    """The insert helper splits `ctrl+shift+v` into wtype's flags."""

    def parse(self, paste_key):
        script = (
            'IFS="+" read -ra parts <<<"$1"\n'
            'key="${parts[-1]}"; unset "parts[-1]"\n'
            'press=(); release=()\n'
            'for mod in "${parts[@]}"; do press+=(-M "$mod"); release+=(-m "$mod"); done\n'
            'echo "${press[@]} -k $key ${release[@]}"\n')
        return subprocess.run(["bash", "-c", script, "-", paste_key],
                              capture_output=True, text=True).stdout.strip()

    def test_single_modifier(self):
        self.assertEqual(self.parse("shift+Insert"), "-M shift -k Insert -m shift")

    def test_two_modifiers(self):
        self.assertEqual(self.parse("ctrl+shift+v"),
                         "-M ctrl -M shift -k v -m ctrl -m shift")

    def test_bare_key(self):
        self.assertEqual(self.parse("Insert"), "-k Insert")


class InsertHelperContract(unittest.TestCase):
    """Pin the flags that make the paste safe. See docs/HANDOVER.md."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(REPO, "bin", "keepass-picker-insert")) as fh:
            cls.src = fh.read()

    def test_marks_the_clipboard_sensitive(self):
        # Without this the password lands in
        # ~/.local/state/omarchy/clipboard-history.json in plaintext.
        self.assertIn("--sensitive", self.src)

    def test_owns_the_clipboard_in_the_foreground_and_kills_it(self):
        # So the secret leaves the clipboard rather than lingering there.
        self.assertIn("--foreground", self.src)
        self.assertIn('kill "$copy_pid"', self.src)

    def test_reads_the_secret_from_stdin(self):
        self.assertIn("secret=$(cat)", self.src)

    def test_never_uses_the_unsafe_omarchy_helper(self):
        # omarchy-clipboard-paste-text calls plain wl-copy: no --sensitive.
        self.assertNotIn("omarchy-clipboard-paste-text", self.src)

    def test_pastes_rather_than_types(self):
        # wtype emits wrong symbols under non-US keymaps, and that corruption
        # is invisible on a string you cannot see.
        self.assertIn("-k ", self.src)
        self.assertNotRegex(self.src, r"wtype\s+\"\$secret\"")


class FillSequences(unittest.TestCase):
    """KeePassXC's syntax, because it is what every neighbouring tool uses."""

    def test_the_default_parses_to_the_three_steps(self):
        self.assertEqual(ka.parse_sequence("{USERNAME}{TAB}{PASSWORD}"),
                         [("field", "UserName"), ("key", "Tab"),
                          ("field", "Password")])

    def test_enter_is_supported(self):
        self.assertEqual(ka.parse_sequence("{PASSWORD}{ENTER}")[-1], ("key", "Return"))

    def test_an_unknown_token_is_refused_not_skipped(self):
        # Silently dropping a step would put a password in the wrong field.
        with self.assertRaises(ka.LockedError):
            ka.parse_sequence("{USERNAME}{NOPE}{PASSWORD}")

    def test_stray_text_is_refused(self):
        for bad in ("{USERNAME} {PASSWORD}", "hello{PASSWORD}", "{PASSWORD}!"):
            with self.subTest(sequence=bad):
                with self.assertRaises(ka.LockedError):
                    ka.parse_sequence(bad)

    def test_an_empty_sequence_is_refused(self):
        with self.assertRaises(ka.LockedError):
            ka.parse_sequence("")


def qml_code(filename):
    """QML with `//` comments removed.

    These checks are about what a file *does*, and each names something the
    comments legitimately discuss -- the comment explaining why there is no
    TextInput contains the word TextInput.
    """
    out = []
    with open(os.path.join(REPO, filename)) as fh:
        for line in fh:
            cut = line.find("//")
            out.append(line if cut < 0 else line[:cut] + "\n")
    return "".join(out)


class PinentryTheming(unittest.TestCase):
    """Repaint pinentry in the desktop's colours, without touching anything else.

    pinentry rejects Qt's `-stylesheet`, and the session's
    QT_QPA_PLATFORMTHEME=gtk3 hands it Adwaita-dark because Omarchy themes
    nothing in GTK. qt6ct is a platform theme that does take a custom palette,
    and the environment that selects it is per-process.
    """

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="kp-theme-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        theme = os.path.join(self.root, "omarchy", "current", "theme")
        os.makedirs(theme)
        with open(os.path.join(theme, "colors.toml"), "w") as fh:
            fh.write('accent = "#e68e0d"\nbackground = "#121212"\n'
                     'foreground = "#bebebe"\nlighter_background = "#1e1e1e"\n'
                     'muted = "#333333"\nlight_foreground = "#8a8a8d"\n')
        self._env = dict(os.environ)
        os.environ["XDG_STATE_HOME"] = self.root
        os.environ["XDG_RUNTIME_DIR"] = self.root
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(self._env)))

    def test_the_palette_comes_from_the_active_theme(self):
        colors = ka.theme_colors()
        self.assertEqual(colors["accent"], "#e68e0d")
        self.assertEqual(colors["background"], "#121212")

    def test_a_missing_theme_is_not_an_error(self):
        os.environ["XDG_STATE_HOME"] = os.path.join(self.root, "nope")
        self.assertEqual(ka.theme_colors(), {})
        self.assertEqual(ka.pinentry_theme_env(), {})

    def test_without_qt6ct_it_changes_nothing(self):
        # Degrades to exactly the behaviour before this existed.
        if ka.which("qt6ct"):
            self.skipTest("qt6ct is installed on this machine")
        self.assertEqual(ka.pinentry_theme_env(), {})

    def test_a_monochrome_icon_set_is_preferred_over_the_themes(self):
        # An Omarchy theme names a full-colour desktop set (Yaru-red here),
        # which puts a filled green tick and a filled red cross on a dialog
        # whose whole register is flat and grey.
        chosen = ka.pinentry_icon_set()
        if chosen:
            self.assertIn(chosen, ka.MONOCHROME_ICON_SETS + (ka.theme_icon_set(),))

    def test_an_explicit_icon_preference_wins(self):
        for name in ka.MONOCHROME_ICON_SETS:
            if ka.icon_set_installed(name):
                self.assertEqual(ka.pinentry_icon_set(name), name)
                break

    def test_an_uninstalled_preference_is_dropped_not_passed_on(self):
        # Naming a missing set leaves Qt with nothing rather than a fallback.
        self.assertEqual(ka.pinentry_icon_set("NoSuchIconSetAnywhere"), "")

    def test_the_mask_character_is_configurable_and_not_a_fat_bullet(self):
        self.assertEqual(ka.DEFAULTS["mask_character"], "\u00b7")

    def test_the_icon_set_comes_from_the_theme(self):
        # Without one, Qt has no icon theme at all: pinentry's reveal-password
        # button renders as an empty box and its padlock falls back to a
        # colourful GTK emoji on an otherwise flat dialog.
        theme = os.path.join(self.root, "omarchy", "current", "theme")
        with open(os.path.join(theme, "icons.theme"), "w") as fh:
            fh.write("Adwaita\n")          # installed everywhere
        self.assertEqual(ka.theme_icon_set(), "Adwaita")

    def test_an_uninstalled_icon_set_is_not_named(self):
        # Naming a missing set is worse than naming none: Qt then finds
        # nothing at all rather than falling back.
        theme = os.path.join(self.root, "omarchy", "current", "theme")
        with open(os.path.join(theme, "icons.theme"), "w") as fh:
            fh.write("NoSuchIconSetAnywhere\n")
        self.assertEqual(ka.theme_icon_set(), "")

    def test_a_missing_icons_file_is_not_an_error(self):
        self.assertEqual(ka.theme_icon_set(), "")

    def test_the_config_names_every_palette_role(self):
        # A short list silently leaves roles at Qt's defaults.
        self.assertEqual(len(ka.PALETTE_ROLES), 21)
        self.assertIn("Highlight", ka.PALETTE_ROLES)
        self.assertIn("PlaceholderText", ka.PALETTE_ROLES)

    def test_it_only_ever_repaints_pinentry(self):
        # Per-process env, never a write to the user's own Qt or GTK config.
        with open(os.path.join(REPO, "bin", "keepass_agent.py")) as fh:
            src = fh.read()
        fn = src[src.index("def pinentry_theme_env"):src.index("def ask_password")]
        self.assertIn("runtime_dir()", fn)
        for forbidden in ("gtk-3.0", "gsettings", "~/.config/qt6ct",
                          "expanduser(\"~/.config"):
            with self.subTest(token=forbidden):
                self.assertNotIn(forbidden, fn)


class BarWidgetRunsNoProcess(unittest.TestCase):
    """The shell-wedge regression, pinned by a grep.

    The bar widget polled `keepass-picker-ctl status` every five seconds. When
    those calls hung they accumulated inside omarchy-shell until it stopped
    answering IPC: process alive, bar gone, only a kill and relaunch recovered
    it. The convention is a status file and one FileView, so this widget must
    never spawn anything again.
    """

    @classmethod
    def setUpClass(cls):
        cls.src = qml_code("BarWidget.qml")

    def test_it_declares_no_process(self):
        self.assertNotRegex(self.src, r"\bProcess\s*\{")

    def test_it_launches_nothing(self):
        for forbidden in ("execDetached", "keepass-picker-ctl"):
            with self.subTest(token=forbidden):
                self.assertNotIn(forbidden, self.src)

    def test_it_reads_the_status_file_instead(self):
        self.assertIn("FileView", self.src)
        self.assertIn("keepass-picker.status.json", self.src)

    def test_a_stale_status_file_is_not_trusted(self):
        # Nothing restarts the agent now, so a status file can outlive it. Only
        # a live agent can hold an unlocked vault.
        self.assertIn("stale", self.src)
        self.assertRegex(self.src, r"unlocked\s*:\s*vaultState === \"unlocked\" && !root\.stale")

    def test_staleness_re_evaluates_on_a_clock_not_a_self_assignment(self):
        # `statusUpdated = statusUpdated` emits no change signal in QML, so the
        # padlock would never go stale.
        self.assertNotIn("root.statusUpdated = root.statusUpdated", self.src)
        self.assertIn("root.now = Date.now()", self.src)

    def test_it_uses_the_shared_base_class(self):
        # Where vertical-bar support comes from.
        self.assertRegex(self.src, r"\bBarWidget\s*\{")
        self.assertIn('moduleName: "mkelk.keepass-picker"', self.src)


class OverlayKeepsSecretsOut(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = qml_code("Overlay.qml")

    def test_no_text_input_competes_for_focus(self):
        # Every shipped overlay drives the filter from Keys.onPressed instead.
        self.assertNotRegex(self.src, r"\bTextInput\b")

    def test_the_filter_is_driven_from_key_events(self):
        self.assertIn("event.text", self.src)

    def test_it_never_asks_the_agent_to_reveal_anything(self):
        # Naming a FIELD is fine -- "Password" is an argument to insert. Naming
        # a command that returns a value is not.
        for forbidden in ('"show"', '"reveal"', '"get"', '"dump"'):
            with self.subTest(token=forbidden):
                self.assertNotIn(forbidden, self.src)

    def test_the_row_model_carries_labels_only(self):
        for key in ("entryPath:", "title:", "group:", "why:"):
            self.assertIn(key, self.src)
        for leaked in ("password:", "secret:", "value:"):
            self.assertNotIn(leaked, self.src)

    def test_it_shows_what_tells_two_entries_apart(self):
        # A vault can hold three entries titled with the same person's name
        # that differ only by the phone number in their username.
        self.assertIn("username:", self.src)
        self.assertIn("url:", self.src)

    def test_it_never_touches_the_notes(self):
        # Notes hold PINs, PUKs and recovery codes. They are searched by
        # keepassxc-cli and never fetched or rendered.
        self.assertNotIn("notes:", self.src.lower())
        self.assertNotIn('"Notes"', self.src)

    def test_a_locked_vault_prompts_without_an_extra_keystroke(self):
        # "Locked. Press Enter to unlock." was a keystroke carrying no
        # information: there is nothing else you can want from a locked vault.
        self.assertIn("unlockOffered", self.src)
        apply = self.src[self.src.index("function applyStatus"):]
        apply = apply[:apply.index("function applyTarget")]
        self.assertIn("root.unlock()", apply)

    def test_the_automatic_prompt_cannot_loop(self):
        # Cancelling pinentry returns with the vault still locked. Re-prompting
        # on that would be unclosable.
        apply = self.src[self.src.index("function applyStatus"):]
        apply = apply[:apply.index("function applyTarget")]
        self.assertIn("!root.unlockOffered", apply)
        self.assertIn("root.unlockOffered = true", apply)
        opened = self.src[self.src.index("function open("):]
        opened = opened[:opened.index("function close(")]
        self.assertIn("root.unlockOffered = false", opened)

    def test_it_steps_aside_for_pinentry(self):
        # This surface is layer-shell on the Overlay layer with EXCLUSIVE
        # keyboard focus, so pinentry -- a normal toplevel -- renders behind it
        # and receives no keystrokes. The unlock prompt was visible but
        # untypeable until the overlay learned to hide itself.
        unlock = self.src[self.src.index("function unlock()"):]
        unlock = unlock[:unlock.index("function reopenAfterUnlock")]
        self.assertIn("root.opened = false", unlock)
        # Not dismiss(): that would unload the component and the unlock
        # callback would have nowhere to land.
        self.assertNotIn("dismiss()", unlock)

    def test_it_comes_back_whether_the_unlock_worked_or_not(self):
        # Cancelling pinentry must not leave an invisible picker and a
        # keystroke that appeared to do nothing.
        self.assertEqual(self.src.count("root.reopenAfterUnlock()"), 2)

    def test_the_keybinding_cannot_re_cover_the_prompt(self):
        toggle = self.src[self.src.index("function toggle()"):]
        toggle = toggle[:toggle.index("}", toggle.index("root.open"))]
        self.assertIn("if (root.busy) return", toggle)

    def test_the_footer_is_the_same_in_every_window(self):
        # Enter used to mean fill in a browser and password in a terminal, and
        # the footer changed to explain itself. A key that changes meaning is
        # one you have to think about before pressing.
        footer = self.src[self.src.index("readonly property var footerHints"):]
        footer = footer[:footer.index("ListModel")]
        for banished in ("targetClass", "targetTitle", "targetIsTerminal",
                         "fillIsSafe", "terminal", "No fill"):
            with self.subTest(token=banished):
                self.assertNotIn(banished, footer)
        # One return, so there is nothing to branch on.
        self.assertEqual(footer.count("return "), 2)   # the empty case, and the line

    def test_the_window_never_steers_what_a_key_does(self):
        # The address survives, because the focus guard needs it. The title
        # survives too, but ONLY as something the pane prints -- see the test
        # below. The class and every is-it-a-terminal predicate stay gone: they
        # existed to vary Enter, which is the thing that made Enter
        # unpredictable and dragged "foot" into the UI to explain itself.
        self.assertIn("targetAddress", self.src)
        for banished in ("targetClass", "targetIsTerminal",
                         "fillIsSafe", "is_terminal"):
            with self.subTest(token=banished):
                self.assertNotIn(banished, self.src)

    def test_the_window_title_is_printed_and_never_branched_on(self):
        # The pane says where a paste will land. That is information; it must
        # not become behaviour. So targetTitle may appear in what the pane
        # draws and nowhere that decides anything.
        self.assertIn("targetTitle", self.src)

        def region(start, end):
            head = self.src.index(start)
            return self.src[head:self.src.index(end, head)]

        deciders = {
            "the key handler": region("Keys.onPressed", "Column {"),
            "activate()": region("function activate()",
                                 "readonly property string keyColor"),
            "deliver()": region("function deliver(mode, field)",
                                "function unlock()"),
            "the footer": region("readonly property var footerHints",
                                 "ListModel"),
        }
        for where, body in deciders.items():
            with self.subTest(region=where):
                self.assertNotIn("targetTitle", body)

    def test_the_pane_shows_no_secret_and_offers_no_reveal(self):
        # The pane exists to confirm an entry, not to display it. A reveal
        # would need the password to cross into QML, which is the boundary the
        # whole plugin is built around.
        self.assertIn("detailPane", self.src)
        for banished in ("reveal", "Notes", "notes"):
            with self.subTest(token=banished):
                self.assertNotIn(banished, self.src)
        # Ctrl+R specifically, and not Qt.Key_Return, which starts the same.
        self.assertNotRegex(self.src, r"Qt\.Key_R\b")
        # And no PASSWORD row among the labels it prints. A masked value would
        # either state a length we never measured or claim a field we never
        # checked; the footer already says what Enter will type.
        # The pane prints exactly these, in this order. PASSWORD is absent
        # because a mask would state a length nobody measured; FOLDER because
        # the group is already the tail of the path in the list.
        labels = re.findall(r'label: "([A-Z][A-Z ]*)"', self.src)
        self.assertEqual(labels,
                         ["TITLE", "WILL TYPE INTO", "USERNAME", "URL",
                          "LAST USED"])

    def test_the_ring_is_the_accent_even_when_the_theme_names_a_border(self):
        # Border.surfaceSpec's third argument is a FALLBACK, used only when the
        # theme leaves the token unset. Evergreen sets menu.border to
        # hyprland.active-border-foreground, so passing Color.accent there did
        # nothing and the ring came out grey. The colour has to be asserted.
        spec = self.src[self.src.index("property var borderSpec"):]
        spec = spec[:spec.index("readonly property color selectedBackground")]
        self.assertIn("color: Color.accent", spec)

    def test_the_card_is_a_step_off_the_desktop(self):
        # The theme sets menu.background to the same value as the desktop
        # background, so the card had no body -- it read as a hole. Tinted
        # toward the ink, which lifts a dark theme and settles a light one.
        body = self.src[self.src.index("property color background:"):]
        body = body[:body.index("property color scrim")]
        self.assertIn("Qt.tint(Color.menu.background", body)

    def test_the_target_is_captured_before_the_surface_exists(self):
        # It decides where a password lands. Asking after the layer surface is
        # up has been correct in practice, but practice is not the standard for
        # this particular value.
        body = self.src[self.src.index("function open(payloadJson)"):]
        body = body[:body.index("function close()")]
        self.assertLess(body.index("targetProc.running = true"),
                        body.index("root.opened = true"))

    def test_the_left_edge_cannot_go_ragged(self):
        # Vault titles carry leading spaces and dashes. Rendered verbatim they
        # started every row at a different x, which was the single most visible
        # flaw against the design.
        self.assertIn("function cleanTitle", self.src)
        self.assertIn("root.cleanTitle(model.title)", self.src)
        # And the marker sits in a fixed column with a constant gap, so the
        # title's x does not depend on the marker either.
        marker = self.src[self.src.index("id: rowMarker"):]
        marker = marker[:marker.index("id: whyGlyph")]
        self.assertIn("width: root.glyphColumn", marker)
        self.assertIn("anchors.leftMargin: root.markerInset", marker)

    def test_the_two_lines_of_a_row_share_one_block(self):
        # An explicit gap -- even 2px -- made each entry read as two items.
        # The line boxes touch and a shared line-height does the spacing.
        row = self.src[self.src.index("id: titleText"):]
        row = row[:row.index("MouseArea")]
        self.assertNotIn("anchors.topMargin", row)
        # And NO lineHeight. A monospace face already spaces its lines at about
        # 1.3x, so setting 1.35 multiplied an existing leading instead of
        # replacing it: the extra space landed between the two lines and the
        # selection band came out shorter than the content it was marking.
        self.assertNotIn("lineHeight", row)
        # The row is as tall as what it holds, measured in the real font.
        self.assertIn("titleMetrics.implicitHeight", self.src)
        self.assertIn("userMetrics.implicitHeight", self.src)
        # And a real step between them: title over bodySmall is three pixels on
        # Omarchy's scale. body over caption was two, and the username still
        # read as a second title.
        self.assertIn("font.pixelSize: Style.font.body", row)
        self.assertIn("font.pixelSize: Style.font.caption", row)

    def test_the_selected_row_is_one_object(self):
        # It read as a bar, a gap, a glyph and a highlighted box. The band is
        # the row's own background, the bar sits flush on its left edge at
        # exactly the band's height, and the row's padding is inside it.
        row = self.src[self.src.index("delegate: Rectangle"):]
        row = row[:row.index("id: rowMarker")]
        self.assertIn("width: resultList.width", row)       # the band is the row
        self.assertIn("anchors.top: parent.top", row)       # the bar matches it
        self.assertIn("anchors.bottom: parent.bottom", row)
        self.assertNotIn("verticalCenter", row)             # never inset

    def test_the_header_and_the_rows_share_two_columns(self):
        # The magnifier sits where the bullets sit; the placeholder sits where
        # the titles sit. The header used to set its own margins, so the two
        # were ten pixels apart in one direction and ten in the other.
        header = self.src[self.src.index("id: searchGlyph"):]
        header = header[:header.index("id: countLabel")]
        self.assertIn("anchors.leftMargin: root.markerInset", header)
        self.assertIn("width: root.glyphColumn", header)
        self.assertIn("anchors.leftMargin: root.glyphGap", header)
        # And the same two numbers define the row.
        self.assertIn("textInset: root.markerInset + root.glyphColumn", self.src)

    def test_the_row_marker_is_a_bullet_not_a_pictogram(self):
        # At 12px type a key outline is noisier than the text it labels, every
        # row carried the same one so it said nothing, and an icon at the head
        # of a row reads as something you could click.
        marker = self.src[self.src.index("id: rowMarker"):]
        marker = marker[:marker.index("id: whyGlyph")]
        self.assertIn("rotation: 45", marker)
        self.assertNotIn("text:", marker)

    def test_the_card_is_exactly_its_content(self):
        # The results area used to compute its own height by subtracting
        # everything around it, and that sum disagreed with the one cardHeight
        # used -- which is where the empty band above the footer came from.
        chrome = self.src[self.src.index("readonly property int chromeHeight"):]
        chrome = chrome[:chrome.index("readonly property int listHeight")]
        self.assertIn("topBlock.height", chrome)
        self.assertIn("bottomBlock.height", chrome)
        area = self.src[self.src.index("id: resultsArea"):]
        area = area[:area.index("readonly property bool paneVisible")]
        self.assertNotIn("parent.height -", area)

    def test_ten_rows_are_shown_and_the_card_can_hold_them(self):
        # Seven made a 2:1 strip. Ten sits near 5:3 and is still one glance.
        self.assertIn("readonly property int visibleRows: 10", self.src)
        self.assertIn("Math.min(resultModel.count, root.visibleRows)", self.src)
        # The height cap must leave room for them, or the last rows are cut.
        cap = re.search(r"cardHeight: Math\.min\(\s*Style\.space\((\d+)\)", self.src)
        self.assertIsNotNone(cap)
        self.assertGreaterEqual(int(cap.group(1)), 640)

    def test_a_web_app_window_is_named_by_its_host(self):
        # Chromium-family web apps carry the host in the class:
        # "chrome-mail.google.com__mail_u_0_-Profile_1". The last dotted
        # segment of that read "Com__mail_u_0_-Profile_1" in the pane.
        body = self.src[self.src.index("function prettyApp("):]
        body = body[:body.index("readonly property string targetLabel")]
        self.assertIn("__/i", body)          # the web-app pattern, matched first
        self.assertIn("webApp[1]", body)     # and the host is what is returned

    def test_the_list_shows_whole_rows_only(self):
        # Anchored to the bottom it showed six rows and the top half of a
        # seventh. A row cut through its own glyphs is worse than no row.
        view = self.src[self.src.index("id: resultList"):]
        view = view[:view.index("delegate:")]
        self.assertIn("Math.floor(parent.height / root.rowHeight)", view)
        self.assertIn("spacing: 0", view)

    def test_the_pane_keeps_its_shape_as_the_selection_moves(self):
        # A field that vanishes moves every label below it, and the eye has to
        # find each one again on every keystroke.
        block = self.src[self.src.index("readonly property var paneCredential"):]
        block = block[:block.index("readonly property string targetLabel")
                      if "readonly property string targetLabel" in block
                      else block.index("function ")]
        for label in ("USERNAME", "URL", "LAST USED"):
            self.assertIn(label, block)
        self.assertNotIn("if (r.url)", block)
        # The action row stays too, dimmed rather than removed.
        self.assertIn("paneAction.armed", self.src)

    def test_the_accent_marks_the_selection_and_not_the_row(self):
        # Color.menu.selectedBackground is the accent in most Omarchy themes.
        # Using it painted the whole cursor row orange, which spent the accent
        # on the largest area on screen and left nothing to mark the match.
        # Color.menu.selectedText is the ACCENT on the shipped themes, and
        # using it for a row's ink painted the selected title orange -- a
        # second signal for something the accent bar already carries, spent
        # where the match highlight needs it. The selection SURFACE is the
        # theme's own token; only the ink is ours to insist on.
        self.assertIn("Color.menu.selectedBackground", self.src)
        row = self.src[self.src.index("delegate: Rectangle"):]
        row = row[:row.index("MouseArea")]
        self.assertNotIn("selectedText", row)
        # The ink does not change with the selection either.
        row = self.src[self.src.index("readonly property bool current:"):]
        row = row[:row.index("id: rowMarker")]
        self.assertIn("primary: root.foreground", row)
        self.assertIn("secondary: root.dim", row)

    def test_a_title_is_escaped_before_it_is_styled(self):
        # The title becomes StyledText so the matched characters can carry the
        # accent. It is vault content, so an angle bracket in it must not be
        # markup.
        self.assertIn("function escapeHtml", self.src)
        body = self.src[self.src.index("function highlight("):]
        body = body[:body.index("function shortAge")]
        self.assertNotIn("+ plain.slice", body)          # never unescaped
        self.assertEqual(body.count("root.escapeHtml("), 5)

    def test_nothing_in_the_chrome_is_a_hard_coded_colour(self):
        # The card repaints with the active Omarchy theme. A literal hex would
        # look right on one theme and wrong on every other.
        self.assertNotRegex(self.src, r'"#[0-9a-fA-F]{3,8}"')

    def test_opening_a_url_refuses_every_scheme_but_http(self):
        # The URL comes out of the vault, and xdg-open will hand a file:// or a
        # custom scheme to whatever claims it.
        body = self.src[self.src.index("function openUrl()"):]
        body = body[:body.index("function shortUrl(")]
        self.assertIn("https?", body)
        self.assertIn("xdg-open", body)
        self.assertIn("return", body)

    def test_enter_delivers_and_the_modifier_picks_the_field(self):
        keys = self.src[self.src.index("Qt.Key_Return"):]
        keys = keys[:keys.index("Qt.Key_Tab")]
        self.assertIn('ControlModifier) root.deliver("fill")', keys)
        self.assertIn('ShiftModifier) root.deliver("insert", "UserName")', keys)
        self.assertIn("root.activate()", keys)

    def test_enter_alone_is_always_the_password(self):
        act = self.src[self.src.index("function activate()"):]
        act = act[:act.index("readonly property string keyColor")]
        self.assertIn('root.deliver("insert", "Password")', act)
        self.assertNotIn("fillIsSafe", act)

    def test_tab_moves_the_selection_rather_than_pasting(self):
        tab = self.src[self.src.index("Qt.Key_Tab"):]
        tab = tab[:tab.index("Qt.Key_L")]
        self.assertIn("root.select(", tab)
        self.assertNotIn("deliver", tab)

    def test_the_footer_is_separated_from_the_results(self):
        # It was caption-sized dim text butted against a row of caption-sized
        # dim text, and read as one more entry.
        self.assertIn("PanelSeparator", self.src)
        self.assertIn("footerRule", self.src)

    def test_key_names_are_visually_distinct_from_prose(self):
        # The accent is what separates a key name from the words around it,
        # in the footer strip and in the pane's action row alike.
        self.assertIn("keyColor", self.src)          # the matched substring
        self.assertIn("Text.StyledText", self.src)   # the title
        footer = self.src[self.src.index("id: footer"):]
        footer = footer[:footer.index("modelData.what")]
        self.assertIn("color: Color.accent", footer)

    def test_the_card_sizes_to_its_content(self):
        # A fixed card left seven results floating in empty space.
        self.assertIn("chromeHeight", self.src)
        self.assertIn("listHeight", self.src)
        self.assertNotRegex(self.src, r"cardHeight:\s*Math\.min\(Style\.space\(\d+\),\s*panel\.height[^,]*\)\s*$")

    def test_every_glyph_it_draws_was_checked_against_the_font(self):
        # An absent glyph renders as a blank box and nothing warns you. These
        # six were each confirmed present in JetBrainsMonoNerdFont-Regular.
        # chr(), not \u escapes: these are five-digit codepoints and \u takes
        # four, so "\uf0306" is the wrong character followed by a "6".
        checked = {chr(cp) for cp in (0xF0306, 0xF059F, 0xF0004,
                                      0xF082E, 0xF0349, 0xF033F)}
        drawn = {ch for ch in self.src if 0xF0000 <= ord(ch) <= 0xFFFFF}
        self.assertTrue(drawn <= checked,
                        f"unverified glyphs drawn: {[hex(ord(c)) for c in drawn - checked]}")

    def test_the_captured_window_travels_with_the_request(self):
        self.assertIn("targetAddress", self.src)
        self.assertIn('"fill"', self.src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
