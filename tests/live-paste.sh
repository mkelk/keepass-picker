#!/bin/bash
# The one test that drives the real desktop -- ON REQUEST ONLY.
#
# run-all.sh deliberately does not call this. It types into whatever window has
# focus and takes ownership of your clipboard, so ASK THE HUMAN FIRST, run it
# alone, and give it a scratch window to paste into.
#
# It proves the two things the unattended suite cannot:
#   1. the keystroke actually lands in the focused window
#   2. --sensitive really does keep the secret out of the clipboard history
#
# Everything else is faked or asserted from the outside. This is the venue for
# the parts that need a compositor.

set -uo pipefail

REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SECRET="live-paste-probe-$$-not-a-real-secret"
HISTORY="$HOME/.local/state/omarchy/clipboard-history.json"

command -v wl-copy >/dev/null || { echo "wl-copy is not installed"; exit 1; }
command -v wtype   >/dev/null || { echo "wtype is not installed"; exit 1; }
[[ -n ${WAYLAND_DISPLAY:-} ]] || { echo "no Wayland session"; exit 1; }

echo "This test types into the FOCUSED WINDOW and takes over your clipboard."
echo "Secret it will paste: $SECRET"
echo
read -rp "Focus a scratch window (a text editor, an empty terminal line), then press Enter: "
echo "Pasting in 3 seconds -- focus the target window now..."
sleep 3

before_size=$(stat -c %s "$HISTORY" 2>/dev/null || echo missing)
before_hash=$(sha256sum "$HISTORY" 2>/dev/null | cut -d' ' -f1 || echo missing)

printf '%s' "$SECRET" | "$REPO/bin/keepass-picker-insert"
rc=$?

sleep 1
after_size=$(stat -c %s "$HISTORY" 2>/dev/null || echo missing)
after_hash=$(sha256sum "$HISTORY" 2>/dev/null | cut -d' ' -f1 || echo missing)

fail=0
echo
echo "--- results ---"

if (( rc == 0 )); then
  echo "  [ok]   the helper exited 0"
else
  echo "  [FAIL] the helper exited $rc"; fail=1
fi

# Authoritative: nothing you do at your desk writes your secret into this file.
if [[ -f $HISTORY ]] && grep -qF "$SECRET" "$HISTORY" 2>/dev/null; then
  echo "  [FAIL] the secret is in $HISTORY -- --sensitive did not take effect"
  fail=1
else
  echo "  [ok]   the secret is not in the clipboard history"
fi

if [[ $before_hash == "$after_hash" ]]; then
  echo "  [ok]   the clipboard history is byte-identical ($before_size -> $after_size)"
else
  echo "  [warn] the clipboard history changed -- ambiguous, you may have copied"
  echo "         something yourself during the run. Rerun on an idle desk."
fi

# The clipboard owner is killed, so the secret should not still be offered.
if wl-paste --no-newline 2>/dev/null | grep -qF "$SECRET"; then
  echo "  [FAIL] the secret is still on the clipboard -- the owner did not die"
  fail=1
else
  echo "  [ok]   the secret is no longer on the clipboard"
fi

echo
echo "  [manual] Look at the window you focused. It should contain:"
echo "           $SECRET"
echo "           If it is empty, the keystroke did not land: try a different"
echo "           paste_key (terminals usually want ctrl+shift+v) or a longer"
echo "           pre_type_delay."
echo
if (( fail )); then
  echo "live-paste: FAIL"
else
  echo "live-paste: PASS (subject to the manual check above)"
fi
exit $fail
