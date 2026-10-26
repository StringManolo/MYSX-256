#!/usr/bin/env bash
# =============================================================================
# run_all_gh_actions.sh — Trigger the paper reproducibility workflows on
# GitHub Actions, wait, and download the consolidated results.
#
# Default: paper.yml (all ready tests) + nist.yml (v1 and v02).
#
# Usage:
#   ./run_all_gh_actions.sh                  # ~2-3h wall, paper + NIST
#   ./run_all_gh_actions.sh --no-nist        # ~30-60min, paper only
#   ./run_all_gh_actions.sh --fast           # alias of --no-nist
#   ./run_all_gh_actions.sh --quick          # group=basic only
#   ./run_all_gh_actions.sh --group linear
#   ./run_all_gh_actions.sh --test dmitm_v02
#   ./run_all_gh_actions.sh --test "trunc_v1,trunc_v02"
#   ./run_all_gh_actions.sh --no-wait        # trigger, don't wait
#   ./run_all_gh_actions.sh --no-download    # don't download artifacts
#   ./run_all_gh_actions.sh --repo owner/name
#   ./run_all_gh_actions.sh --run-id <id>    # download from existing run
#   ./run_all_gh_actions.sh --out /tmp/X     # download dir
#
# Requires: gh CLI authenticated (gh auth status), workflows on default branch.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

REPO=""
SELECTION="all"
WAIT=1
DOWNLOAD=1
NO_NIST=0
RUN_ID=""
OUT_DIR="/tmp/mysx_paper_results"

usage() {
  sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --quick) SELECTION="quick"; shift ;;
    --group) SELECTION="group=$2"; shift 2 ;;
    --group=*) SELECTION="group=${1#--group=}"; shift ;;
    --test) SELECTION="$2"; shift 2 ;;
    --test=*) SELECTION="${1#--test=}"; shift ;;
    --all+pending) SELECTION="all+pending"; shift ;;
    --no-nist|--fast) NO_NIST=1; shift ;;
    --include-nist) NO_NIST=0; shift ;;     # back-compat: now the default
    --no-wait) WAIT=0; shift ;;
    --no-download) DOWNLOAD=0; shift ;;
    --repo) REPO="$2"; shift 2 ;;
    --repo=*) REPO="${1#--repo=}"; shift ;;
    --run-id) RUN_ID="$2"; shift 2 ;;
    --run-id=*) RUN_ID="${1#--run-id=}"; shift ;;
    --out) OUT_DIR="$2"; shift 2 ;;
    --out=*) OUT_DIR="${1#--out=}"; shift ;;
    -h|--help) usage ;;
    *) echo "Unknown arg: $1"; echo; usage ;;
  esac
done

# --- Sanity ---
command -v gh >/dev/null || { echo "ERROR: gh CLI not found"; exit 2; }
gh auth status >/dev/null 2>&1 || { echo "ERROR: gh not authenticated (run: gh auth login)"; exit 2; }

# --- Determine repo ---
if [ -z "$REPO" ]; then
  if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "ERROR: not in a git repo; pass --repo owner/name"
    exit 2
  fi
  REMOTE=$(git remote get-url origin 2>/dev/null || true)
  if [ -z "$REMOTE" ]; then
    echo "ERROR: no 'origin' remote; pass --repo owner/name"
    exit 2
  fi
  REPO=$(echo "$REMOTE" | sed -E 's|^git@[^:]+:||; s|^https?://[^/]+/||; s|\.git$||')
fi
echo "==> Repo: $REPO"

BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
if [ "$BRANCH" != "main" ] && [ "$BRANCH" != "master" ]; then
  echo "WARNING: on branch '$BRANCH'. GitHub Actions uses workflows from"
  echo "  the default branch (main). Merge your changes first."
  echo
fi
if [ -n "$(git status --porcelain 2>/dev/null | head -1)" ]; then
  echo "WARNING: uncommitted changes. The runner will not see them."
  echo
fi

# --- paper.yml ---
if [ -z "$RUN_ID" ]; then
  echo "==> Triggering paper.yml with selection: $SELECTION"
  gh workflow run paper.yml --repo "$REPO" -f "tests=$SELECTION"
  echo

  echo "==> Waiting for run to be registered..."
  sleep 5
  for i in $(seq 1 12); do
    RUN_ID=$(gh run list --workflow=paper.yml --repo "$REPO" --limit 1 \
      --json databaseId --jq '.[0].databaseId' 2>/dev/null || echo "")
    if [ -n "$RUN_ID" ] && [ "$RUN_ID" != "null" ]; then break; fi
    echo "  retry $i..."; sleep 5
  done
  if [ -z "$RUN_ID" ] || [ "$RUN_ID" = "null" ]; then
    echo "ERROR: could not find the triggered paper.yml run"
    exit 1
  fi
  echo "==> paper.yml run: $RUN_ID"
  echo "    https://github.com/$REPO/actions/runs/$RUN_ID"
  echo
fi

PAPER_RC=0
if [ "$WAIT" = 1 ]; then
  echo "==> Waiting for paper.yml to finish..."
  WATCH_OK=0
  for attempt in 1 2 3; do
    if gh run watch "$RUN_ID" --repo "$REPO"; then
      WATCH_OK=1; break
    fi
    sleep 15
  done

  if [ "$WATCH_OK" = 0 ]; then
    # Could be HTTP 500 transient; ask GH for the real conclusion
    echo
    echo "WARNING: 'gh run watch' failed 3x (likely HTTP 500 on /jobs)."
    echo "         Querying the run status directly..."
    CONCLUSION=$(gh run view "$RUN_ID" --repo "$REPO" --json conclusion --jq '.conclusion' 2>/dev/null || echo "unknown")
    echo "         conclusion: $CONCLUSION"
    if [ "$CONCLUSION" = "success" ]; then
      echo "         OK (the watch failed but the run succeeded)."
    else
      PAPER_RC=1
      echo "         FAILED. Failed logs (last 200 lines):"
      echo "---"
      gh run view "$RUN_ID" --repo "$REPO" --log-failed 2>/dev/null | tail -200 || \
        echo "(could not fetch failed logs)"
      echo "---"
    fi
  fi
fi

# --- Download paper results ---
mkdir -p "$OUT_DIR"
PAPER_RESULTS="$OUT_DIR/paper_results.json"
if [ "$DOWNLOAD" = 1 ]; then
  echo
  echo "==> Downloading paper-results artifact..."
  if gh run download "$RUN_ID" --repo "$REPO" --name paper-results -D "$OUT_DIR" 2>/dev/null; then
    # The artifact contains results.json; rename to avoid confusion with NIST
    if [ -f "$OUT_DIR/results.json" ]; then
      mv "$OUT_DIR/results.json" "$PAPER_RESULTS"
    fi
    if [ -f "$PAPER_RESULTS" ]; then
      echo
      echo "==================================================================="
      echo " paper.yml summary"
      echo "==================================================================="
      python3 - "$PAPER_RESULTS" <<'PYEOF'
import json, sys
r = json.load(open(sys.argv[1]))
n_pass  = sum(1 for t in r['tests'] if t.get('status') == 'pass')
n_fail  = sum(1 for t in r['tests'] if t.get('status') == 'fail')
n_skip  = sum(1 for t in r['tests'] if t.get('status') == 'skipped')
n_other = r['n_tests'] - n_pass - n_fail - n_skip
print(f"  Total:   {r['n_tests']}")
print(f"  Pass:    {n_pass}")
print(f"  Fail:    {n_fail}")
print(f"  Skipped: {n_skip}")
print(f"  Other:   {n_other}")
print()
if n_fail > 0:
    print("  FAILED:")
    for t in r['tests']:
        if t.get('status') == 'fail':
            print(f"    - {t.get('id','')}: {t.get('name','')}")
    print()
PYEOF
      echo "==================================================================="
    fi
  else
    echo "WARNING: could not download 'paper-results' artifact"
  fi
fi

# --- nist.yml (unless --no-nist) ---
NIST_RC=0
if [ "$NO_NIST" = 0 ]; then
  echo
  echo "==> Triggering nist.yml for v1 and v02 ..."

  NIST_IDS=()
  for v in v1 v02; do
    gh workflow run nist.yml --repo "$REPO" -f "version=$v"
    sleep 2
    NRUN=$(gh run list --workflow=nist.yml --repo "$REPO" --limit 1 \
      --json databaseId,displayTitle --jq ".[0] | select(.displayTitle | contains(\"$v\")) | .databaseId" 2>/dev/null || echo "")
    if [ -z "$NRUN" ] || [ "$NRUN" = "null" ]; then
      # Fallback: take the most recent nist.yml run
      NRUN=$(gh run list --workflow=nist.yml --repo "$REPO" --limit 1 \
        --json databaseId --jq '.[0].databaseId' 2>/dev/null || echo "")
    fi
    if [ -n "$NRUN" ] && [ "$NRUN" != "null" ]; then
      echo "  nist $v: run $NRUN"
      NIST_IDS+=("$v:$NRUN")
    else
      echo "  WARNING: could not find nist.yml run for $v"
    fi
  done

  if [ "$WAIT" = 1 ] && [ "${#NIST_IDS[@]}" -gt 0 ]; then
    echo
    echo "==> Waiting for NIST runs (1-2h each)..."
    for entry in "${NIST_IDS[@]}"; do
      v="${entry%%:*}"; nrun="${entry##*:}"
      echo "  nist $v: watching run $nrun..."
      gh run watch "$nrun" --repo "$REPO" || NIST_RC=1
    done
  fi

  if [ "$DOWNLOAD" = 1 ] && [ "${#NIST_IDS[@]}" -gt 0 ]; then
    echo
    echo "==> Downloading NIST reports..."
    for entry in "${NIST_IDS[@]}"; do
      v="${entry%%:*}"; nrun="${entry##*:}"
      dest="$OUT_DIR/nist_$v"
      mkdir -p "$dest"
      gh run download "$nrun" --repo "$REPO" \
        --name "nist-report-$v" -D "$dest" 2>/dev/null || \
        echo "  WARNING: could not download nist-report-$v (run may have failed)"
    done
  fi
else
  echo
  echo "==> Skipping NIST (--no-nist)"
fi

# --- Final summary ---
echo
echo "==================================================================="
echo " Final summary"
echo "==================================================================="
echo "  Output dir: $OUT_DIR"
if [ -f "$PAPER_RESULTS" ]; then
  echo "  paper.yml:  $PAPER_RESULTS"
fi
for entry in "${NIST_IDS[@]:-}"; do
  v="${entry%%:*}"; nrun="${entry##*:}"
  echo "  nist $v:    $OUT_DIR/nist_$v (run $nrun)"
done
echo "==================================================================="

if [ "$PAPER_RC" != 0 ]; then exit 1; fi
if [ "$NIST_RC" != 0 ]; then exit 1; fi
exit 0
