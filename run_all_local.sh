#!/usr/bin/env bash
# =============================================================================
# run_all_local.sh — Run the paper's reproducibility tests locally.
#
# Default: ALL ready tests, INCLUDING NIST SP 800-22 (the full paper).
#
# Usage:
#   ./run_all_local.sh                    # ~3h, all tests (paper + NIST)
#   ./run_all_local.sh --no-nist          # ~30min, everything except NIST
#   ./run_all_local.sh --fast             # alias of --no-nist
#   ./run_all_local.sh --quick            # ~5min, group=basic only
#   ./run_all_local.sh --group linear     # one group
#   ./run_all_local.sh --test dmitm_v02   # one test
#   ./run_all_local.sh --new              # the 7 v0.2 additions
#   ./run_all_local.sh --all+pending      # include PENDING (expected to fail)
#   ./run_all_local.sh --skip-install     # skip pip / npm
#   ./run_all_local.sh --list             # list available tests
#   ./run_all_local.sh --out results/X    # output dir (default: results/local_TS)
#
# Requires: python3, node, npm, git.
# NIST needs sts-2.1.2/assess (see --no-nist if not available).
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

QUICK=0
GROUP=""
TEST_ID=""
NEW_ONLY=0
NO_NIST=0
SKIP_INSTALL=0
LIST_ONLY=0
SELECTION_OVERRIDE=""
OUT="results/local_$(date +%Y%m%d_%H%M%S)"

NEW_TESTS="trunc_v1,trunc_v02,lin_hull_v02,lin_beam_v02_R128,diff_milp_v02_R6_R14,diff_offset_sweep_v02,integral_sweep_v02"

usage() {
  sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --quick) QUICK=1; shift ;;
    --group) GROUP="$2"; shift 2 ;;
    --group=*) GROUP="${1#--group=}"; shift ;;
    --test) TEST_ID="$2"; shift 2 ;;
    --test=*) TEST_ID="${1#--test=}"; shift ;;
    --new) NEW_ONLY=1; shift ;;
    --no-nist|--fast) NO_NIST=1; shift ;;
    --include-nist) NO_NIST=0; shift ;;     # back-compat: now the default
    --all+pending) SELECTION_OVERRIDE="all+pending"; shift ;;
    --skip-install) SKIP_INSTALL=1; shift ;;
    --list) LIST_ONLY=1; shift ;;
    --out) OUT="$2"; shift 2 ;;
    --out=*) OUT="${1#--out=}"; shift ;;
    -h|--help) usage ;;
    *) echo "Unknown arg: $1"; echo; usage ;;
  esac
done

# --- Sanity ---
[ -f tests/manifest.json ] || { echo "ERROR: tests/manifest.json not found"; exit 2; }
[ -f tests/run_test.py ] || { echo "ERROR: tests/run_test.py not found"; exit 2; }

if [ "$LIST_ONLY" = 1 ]; then
  python3 tests/run_test.py --list
  exit 0
fi

# --- Missing-file warnings (informational) ---
MISSING=""
for f in \
  cryptanalysis/DMITM/dmitm_trunc_v2.py \
  tests/run_hull_v02.py \
  tests/run_diff_sweep_v02.py \
  tests/run_diff_milp_v02.py \
  tests/run_nist.py \
  .github/workflows/nist.yml ; do
  [ -f "$f" ] || MISSING="$MISSING $f"
done
if [ -n "$MISSING" ]; then
  echo "WARNING: missing files (some tests will fail or be skipped):"
  for f in $MISSING; do echo "  - $f"; done
  echo
fi

# --- Do NOT inherit a stale MYSX_ROT_CAL from the user's shell ---
unset MYSX_ROT_CAL 2>/dev/null || true

# --- Install deps ---
if [ "$SKIP_INSTALL" = 0 ]; then
  echo "==> Installing Python deps (pulp, highspy, pexpect)..."
  python3 -m pip install -q --user pulp highspy pexpect 2>&1 | tail -2 || \
    python3 -m pip install -q --break-system-packages pulp highspy pexpect 2>&1 | tail -2 || true
  if [ -f package.json ]; then
    echo "==> Installing npm deps..."
    npm ci --silent 2>/dev/null || npm install --silent 2>/dev/null || true
  fi
  echo
fi

# --- Build selection ---
SELECTION="$(python3 - "$QUICK" "$GROUP" "$TEST_ID" "$NEW_ONLY" "$NO_NIST" \
                     "$SELECTION_OVERRIDE" "$NEW_TESTS" <<'PYEOF'
import json, sys
quick, group, test_id, new_only, no_nist, override, new_csv = sys.argv[1:8]
quick = (quick == "1")
new_only = (new_only == "1")
no_nist = (no_nist == "1")

m = json.load(open("tests/manifest.json"))
tests = m["tests"]

def ready(tid):
    return tests[tid].get("status", "ready") == "ready"

if override == "all+pending":
    ids = list(tests.keys())
elif test_id:
    if test_id not in tests:
        sys.exit(f"ERROR: unknown test id: {test_id}")
    ids = [test_id]
elif group:
    ids = [k for k, v in tests.items() if v.get("group") == group and ready(k)]
elif quick:
    ids = [k for k, v in tests.items() if v.get("group") == "basic" and ready(k)]
elif new_only:
    ids = [t.strip() for t in new_csv.split(",") if ready(t.strip())]
elif no_nist:
    ids = [k for k, v in tests.items()
           if ready(k) and v.get("group") != "nist"]
else:
    # DEFAULT: everything ready, INCLUDING NIST
    ids = [k for k, v in tests.items() if ready(k)]

if not ids:
    sys.exit("ERROR: no tests selected")
print(",".join(ids))
PYEOF
)" || { echo "ERROR: could not build selection"; exit 2; }

# --- NIST pre-flight (only if NIST is actually in the selection) ---
HAS_NIST=$(echo "$SELECTION" | tr ',' '\n' | grep -c '^nist_' || true)
if [ "$HAS_NIST" -gt 0 ]; then
  if [ ! -x sts-2.1.2/assess ]; then
    echo "WARNING: NIST tests are in the selection but sts-2.1.2/assess is missing."
    echo "  Download: https://csrc.nist.gov/CSRC/media/Projects/Random-Bit-Generation/documents/sts-2_1_2.zip"
    echo "  Unzip, then: cd sts-2.1.2 && make"
    echo "  Removing NIST from this run. Use --no-nist to silence this warning."
    echo
    SELECTION=$(echo "$SELECTION" | tr ',' '\n' | grep -v '^nist_' | paste -sd, -)
    HAS_NIST=0
  fi
fi

N_TEST=$(echo "$SELECTION" | tr ',' '\n' | wc -l)
if [ "$HAS_NIST" -gt 0 ]; then
  NIST_TAG=" (including NIST)"
else
  NIST_TAG=" (no NIST)"
fi
echo "==> Selected $N_TEST test(s)${NIST_TAG}: $SELECTION"
echo

mkdir -p "$OUT"

# --- Run ---
START=$(date +%s)
LOG="$OUT/run.log"
set +e
python3 tests/run_test.py \
  --manifest tests/manifest.json \
  --selection "$SELECTION" \
  --out "$OUT/results.json" \
  --repo-root . 2>&1 | tee "$LOG"
RC=$?
set -e

END=$(date +%s)
ELAPSED=$((END - START))

# --- Summary ---
echo
echo "==================================================================="
echo " Local run summary"
echo "==================================================================="
if [ -f "$OUT/results.json" ]; then
  python3 - "$OUT/results.json" <<'PYEOF'
import json, sys
r = json.load(open(sys.argv[1]))
n_pass  = sum(1 for t in r['results'] if t['status'] == 'pass')
n_fail  = sum(1 for t in r['results'] if t['status'] == 'fail')
n_skip  = sum(1 for t in r['results'] if t['status'] == 'skipped')
n_other = r['n_tests'] - n_pass - n_fail - n_skip
print(f"  Pass:    {n_pass}")
print(f"  Fail:    {n_fail}")
print(f"  Skipped: {n_skip}")
print(f"  Other:   {n_other}")
print()
if n_fail > 0:
    print("  FAILED:")
    for t in r['results']:
        if t['status'] == 'fail':
            print(f"    - {t['id']}: {t.get('name','')}")
            for a in t.get('assertions', []):
                if not a.get('passed'):
                    print(f"        {a['type']}: {a.get('spec','')}")
    print()
if n_skip > 0:
    print("  SKIPPED (PENDING or missing setup):")
    for t in r['results']:
        if t['status'] == 'skipped':
            print(f"    - {t['id']}")
PYEOF
else
  echo "  (no results.json produced)"
fi
echo
echo "  Results: $OUT/results.json"
echo "  Log:     $LOG"
echo "  Elapsed: ${ELAPSED}s"
echo "==================================================================="

exit "$RC"
