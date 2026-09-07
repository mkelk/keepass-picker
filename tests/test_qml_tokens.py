"""Tier 1b: every Style/Color token our QML names must actually exist.

qmllint does not catch this. `Style.font.small` linted clean, installed clean,
and only announced itself at runtime as

    BarWidget.qml[59:5]: Unable to assign [undefined] to int

which is a warning in a log nobody reads, on a widget that then renders at the
default size. The real token is `bodySmall`. This test reads the singletons the
shell actually loads and fails on any name that is not in them.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import REPO                                          # noqa: E402

SHELL = os.path.join(os.environ.get("OMARCHY_PATH", "/usr/share/omarchy"), "shell")
COMMONS = os.path.join(SHELL, "Commons")

# Style.<group>.<token> and Color.<group>.<token>, e.g. Style.font.bodySmall.
REF_RE = re.compile(r"\b(Style|Color)\.([a-zA-Z][\w]*)\.([a-zA-Z][\w]*)\b")
# Style.<token> used directly, e.g. Style.cornerRadius, Style.gapsOut.
FLAT_RE = re.compile(r"\b(Style|Color)\.([a-z][\w]*)\b(?!\.)")


def singleton_source(name):
    path = os.path.join(COMMONS, f"{name}.qml")
    with open(path) as fh:
        return fh.read()


def group_body(source, group):
    """The text of `readonly property QtObject <group>: QtObject { ... }`."""
    marker = re.search(
        rf"property\s+QtObject\s+{re.escape(group)}\s*:\s*QtObject\s*\{{",
        source)
    if not marker:
        return None
    depth, i = 1, marker.end()
    while i < len(source) and depth:
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
        i += 1
    return source[marker.end():i]


def declares(body, token):
    return re.search(rf"\bproperty\s+\S+\s+{re.escape(token)}\s*:", body) is not None


def qml_files():
    return sorted(f for f in os.listdir(REPO) if f.endswith(".qml"))


class Tokens(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = {n: singleton_source(n) for n in ("Style", "Color")}
        cls.files = qml_files()
        if not cls.files:
            raise unittest.SkipTest("no QML files")

    def test_the_shell_singletons_are_where_we_expect(self):
        for name in ("Style", "Color"):
            self.assertTrue(os.path.exists(os.path.join(COMMONS, f"{name}.qml")),
                            f"{name}.qml not found under {COMMONS}")

    def test_every_grouped_token_exists(self):
        missing = []
        for filename in self.files:
            with open(os.path.join(REPO, filename)) as fh:
                text = fh.read()
            for singleton, group, token in set(REF_RE.findall(text)):
                body = group_body(self.sources[singleton], group)
                if body is None:
                    missing.append(f"{filename}: {singleton}.{group} is not a group")
                elif not declares(body, token):
                    missing.append(
                        f"{filename}: {singleton}.{group}.{token} does not exist")
        self.assertEqual(missing, [], "\n  " + "\n  ".join(missing))

    def test_every_flat_token_exists(self):
        missing = []
        for filename in self.files:
            with open(os.path.join(REPO, filename)) as fh:
                text = fh.read()
            for singleton, token in set(FLAT_RE.findall(text)):
                source = self.sources[singleton]
                if not re.search(rf"\bproperty\s+\S+\s+{re.escape(token)}\s*:", source) \
                   and not re.search(rf"\bfunction\s+{re.escape(token)}\s*\(", source):
                    missing.append(f"{filename}: {singleton}.{token} does not exist")
        self.assertEqual(missing, [], "\n  " + "\n  ".join(missing))

    def test_the_overlay_stays_loaded_so_its_callbacks_survive_hiding(self):
        # The overlay hides itself while pinentry is up. keepLoaded keeps the
        # component alive so the unlock reply has somewhere to land.
        import json
        with open(os.path.join(REPO, "manifest.json")) as fh:
            manifest = json.load(fh)
        self.assertTrue(manifest.get("keepLoaded"),
                        "the overlay must stay loaded while it hides for pinentry")

    def test_the_check_would_catch_the_bug_it_was_written_for(self):
        # Guard against the matcher silently going blind.
        body = group_body(self.sources["Style"], "font")
        self.assertIsNotNone(body)
        self.assertTrue(declares(body, "bodySmall"))
        self.assertFalse(declares(body, "small"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
