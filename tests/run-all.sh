#!/bin/bash
# The whole stack, cheapest tier first.
#
# EVERY STEP RUNS EVEN AFTER ONE FAILS: the point of a pre-release pass is to
# learn everything that is wrong in one sitting, not one thing per run. Prints
# a table and exits nonzero if anything did.
#
#   KP_RUN_ALL_LOG_DIR   where per-step logs land (default: a mktemp dir)
#   KP_RUN_ALL_SKIP      space-separated step numbers to skip, e.g. "4 5"
#
# What it deliberately does NOT run is tests/live-paste.sh, which drives the
# real clipboard and sends a keystroke to whatever window has focus. The live
# session is a venue to ask a human for, never a step in an unattended gate.

set -uo pipefail

REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO" || exit 1

LOG_DIR="${KP_RUN_ALL_LOG_DIR:-$(mktemp -d -t kp-run-all-XXXXXX)}"
mkdir -p "$LOG_DIR"
SKIP=" ${KP_RUN_ALL_SKIP:-} "

names=(); results=(); seconds=()
overall=0
step=0

run_step() {
  local label="$1"; shift
  step=$((step + 1))
  names+=("$label")

  if [[ $SKIP == *" $step "* ]]; then
    results+=("SKIP"); seconds+=(0)
    printf '  [%d] SKIP  %s\n' "$step" "$label"
    return
  fi

  local log="$LOG_DIR/step-$step.log"
  local start=$SECONDS
  printf '  [%d] ....  %s\n' "$step" "$label"
  if "$@" >"$log" 2>&1; then
    results+=("PASS")
  else
    results+=("FAIL")
    overall=1
  fi
  seconds+=($((SECONDS - start)))
  printf '\033[1A\033[2K  [%d] %s  %s\n' "$step" "${results[-1]}" "$label"
}

echo "keepass-picker full stack"
echo "logs: $LOG_DIR"
echo

run_step "python3 tests/test_parsing.py  (pure logic)"      python3 tests/test_parsing.py
run_step "python3 tests/test_rank.py       (ranking, pure)"  python3 tests/test_rank.py
run_step "python3 tests/test_qml_tokens.py (Style/Color names)" python3 tests/test_qml_tokens.py
run_step "python3 tests/test_vault.py    (real .kdbx)"      python3 tests/test_vault.py
run_step "python3 tests/test_agent.py    (agent + security)" python3 tests/test_agent.py
run_step "omarchy plugin validate ."                        omarchy plugin validate .
run_step "qmllint (every QML file, from a glob)"            bash -c \
  'qmllint -I "${OMARCHY_PATH:-/usr/share/omarchy}/shell" ./*.qml'
run_step "shellcheck-free syntax check on bin/"             bash -c \
  'for f in bin/keepass-picker-ctl bin/keepass-picker-insert; do bash -n "$f" || exit 1; done
   python3 -c "import ast,sys; [ast.parse(open(f).read()) for f in sys.argv[1:]]" \
     bin/keepass_agent.py bin/keepass-agent'

printf '\n%-4s %-48s %-8s %s\n' "#" "STEP" "RESULT" "SECONDS"
printf -- '%.0s-' {1..74}; echo
total=0
for i in "${!names[@]}"; do
  printf '%-4s %-48s %-8s %s\n' "$((i + 1))" "${names[$i]}" "${results[$i]}" "${seconds[$i]}"
  total=$((total + seconds[i]))
done
printf -- '%.0s-' {1..74}; echo
printf '%-4s %-48s %-8s %s\n' "" "TOTAL" "$( ((overall == 0)) && echo PASS || echo FAIL)" "$total"

# Read the suites' own footers rather than trusting a number written by hand.
passed=$(grep -ho '^Ran [0-9]* test' "$LOG_DIR"/step-{1,2,3,4,5}.log 2>/dev/null \
         | awk '{s += $2} END {print s + 0}')
failed=$(grep -hoE '(failures|errors)=[0-9]+' "$LOG_DIR"/step-{1,2,3,4,5}.log 2>/dev/null \
         | awk -F= '{s += $2} END {print s + 0}')
echo
echo "python suites: $passed tests ran, $failed failed"
echo "keepass-picker full stack: $( ((overall == 0)) && echo PASS || echo FAIL)"
exit $overall
