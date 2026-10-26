# `tests/` — Paper reproducibility suite

This directory contains the reproducibility harness for **MYSX-256/512 v0.2-draft**.
Every measured value in `PAPER.md` and `SECURITY.md` is backed by a test here.
Run the suite to verify that the code in this repository produces the numbers
the paper claims.

The suite is a thin wrapper around a JSON manifest. The manifest names each
test, its group, the command it runs, and the assertions that must hold for
the test to pass. Adding, removing, or changing a test is a manifest edit;
the runner itself does not need to change.

---

## Quick start

```bash
# From the repository root
./run_all_local.sh --list              # show all tests
./run_all_local.sh --quick             # group=basic only (~5 min)
./run_all_local.sh --new               # the 7 v0.2 additions
./run_all_local.sh --no-nist           # everything except NIST (~30 min)
./run_all_local.sh                     # everything, including NIST (~3 h)
```

For CI:

```bash
./run_all_gh_actions.sh                # paper.yml + nist.yml
./run_all_gh_actions.sh --no-nist      # paper.yml only (~30-60 min)
./run_all_gh_actions.sh --test trunc_v1,trunc_v02
```

---

## Layout

```
tests/
├── README.md              # this file
├── manifest.json          # the single source of truth (28 tests, 7 groups)
├── run_test.py            # universal runner (filter by id/group/selection)
├── merge_results.py       # consolidate per-test result JSONs
├── run_hull_v02.py        # support script for lin_hull_v02
├── run_diff_sweep_v02.py  # support script for diff_offset_sweep_v02
├── run_diff_milp_v02.py   # support script for diff_milp_v02_R6_R14
└── run_nist.py            # support script for nist_v1 / nist_v02 (pexpect)
```

Top-level helpers (in the repository root):

| File | Purpose |
|---|---|
| `run_all_local.sh` | Local orchestration (deps, pre-flight, execution, summary) |
| `run_all_gh_actions.sh` | Trigger/wait/download on GitHub Actions |
| `.github/workflows/paper.yml` | CI matrix for all non-NIST tests |
| `.github/workflows/nist.yml` | CI matrix for NIST STS (v1, v02) |

External prerequisite for the NIST tests:

| Path | Source |
|---|---|
| `sts-2.1.2/assess` | [NIST STS 2.1.2](https://csrc.nist.gov/CSRC/media/Projects/Random-Bit-Generation/documents/sts-2_1_2.zip) — unzip and `make` |

---

## The manifest

`tests/manifest.json` has this shape:

```json
{
  "version": 1,
  "v02_cal": "22,5,8,7,17,10,30,1,11,26,6,3,12,23,25,13,28,20,21,19,24,2,18,9,4,15,29,27,16,14,31",
  "groups": { "basic": "...", "linear": "...", ... },
  "tests": {
    "<test_id>": {
      "name": "human-readable name",
      "group": "basic|impossible|differential|linear|integral|related_key|nist",
      "status": "ready|pending",
      "script": "shell command to run",
      "env": { "MYSX_ROT_CAL": "${v02_cal}" },
      "setup": ["pip install -q pulp highspy"],
      "timeout_minutes": 30,
      "deterministic": true,
      "assertions": [ ... ],
      "notes": "optional free text",
      "reason": "why this is pending (only if status=pending)",
      "command": "manual command to reproduce (only if status=pending)"
    }
  }
}
```

### Fields

| Field | Required | Notes |
|---|---|---|
| `name` | yes | Shown in `--list` and in results. |
| `group` | yes | One of the seven groups below. |
| `status` | no | Default `ready`. `pending` means "documented but not implemented". A `pending` test is **skipped** unless `--include-pending` is passed. |
| `script` | yes (if ready) | The command that runs the test. Shell-interpreted. |
| `env` | no | Environment variables. `${v02_cal}` is substituted from the top-level field. An empty value **unsets** the variable (useful to test the v0.1 path explicitly). |
| `setup` | no | Shell commands run **before** `script`. Non-zero return code marks the test as `setup_failed`. |
| `timeout_minutes` | no | Default 30. On timeout the test result is `timeout`. |
| `deterministic` | no | Informational. `true` means two runs produce the same output. |
| `assertions` | yes (if ready) | List of checks on `(stdout+stderr, returncode)`. If all pass and return code is 0, the test is `pass`. |
| `notes`, `reason`, `command` | no | Documentation. `reason` is shown for pending tests. |

### The `v02_cal` substitution

`${v02_cal}` is replaced with the top-level `v02_cal` string. This lets a test
declare `env: {"MYSX_ROT_CAL": "${v02_cal}"}` without duplicating the 31-value
schedule. If a test needs the v0.1 consecutive schedule, it simply omits the
`env` field (the runner does not set `MYSX_ROT_CAL`, and `mysx.prod.js` and the
analysis tools default to consecutive).

### Groups

| Group | Purpose | Typical wall time (P40 / CI) |
|---|---|---|
| `basic` | KAT, functional tests, API smoke | ~5 s / ~1 min |
| `impossible` | Exact DMITM, truncated impossible | ~10 min / ~5 min |
| `differential` | Free chains, MILP, offset sweep, r=4 | ~2 h / ~20 min |
| `linear` | Exact LAT, beam, hulls | ~3 h / ~45 min |
| `integral` | DP at R=5/6, 31-offset sweep | ~2 h / ~30 min |
| `related_key` | Key schedule audit (basic + 22 tests) | ~3 min / ~3 min |
| `nist` | NIST SP 800-22 (separate workflow) | ~2 h / ~2 h |

Times assume no compilation; the `nist` group requires `sts-2.1.2/assess`
built.

---

## The 28 tests

| # | ID | Group | Timeout | Covers |
|---|---|---|---|---|
| 1 | `v2_smoke` | basic | 3 min | v2 API: 12 checks (calendar, version, cal, kdf, round-trip, v1 compat) |
| 2 | `functional` | basic | 5 min | `mysx.test.js` 17 tests |
| 3 | `kat_v1` | basic | 2 min | `LEGACY_V1/KAT.json` public digest `5c9ca63d...` |
| 4 | `kat_v2` | basic | 2 min | `KAT_v2.json`: `block_digest_cal0 == KNOWN_KAT_DIGEST`, 8 cal1 blocks |
| 5 | `dmitm_v1` | impossible | 15 min | Exact DMITM, v0.1: `total=17`, `max=13` |
| 6 | `dmitm_v02` | impossible | 15 min | Exact DMITM, v0.2: `total=9`, `max=5` |
| 7 | `trunc_v1` | impossible | 60 min | Truncated impossible, v0.1: `BEST: 39 rounds` |
| 8 | `trunc_v02` | impossible | 60 min | Truncated impossible, v0.2: `BEST: ~30–31 rounds` |
| 9 | `diff_free_chain_v1` | differential | 5 min | v0.1 free chain: `r0=10 → 13` |
| 10 | `diff_free_chain_v02` | differential | 5 min | v0.2 free chain: `max=5`, no `13` |
| 11 | `diff_r4_v1` | differential | 20 min | r=4 empirical trail (clustering 2.00×) |
| 12 | `diff_milp_v02_R6_R14` | differential | 90 min | MILP R=6–14, r0 ∈ {0,10,20}, v0.2 |
| 13 | `diff_offset_sweep_v02` | differential | 90 min | 31-offset sweep at R=14, v0.2 |
| 14 | `lin_model_selftest` | linear | 20 min | Exact LAT of F, mask propagation, key sign |
| 15 | `lin_beam_v1_reproduce` | linear | 30 min | `mysx_linear_beam.py reproduce` (paper §4.5) |
| 16 | `lin_beam_v02_R10_fwd` | linear | 30 min | R=10 forward, v0.2: `ub[R=10]=1` |
| 17 | `lin_beam_v02_R14_fwd` | linear | 45 min | R=14 forward, v0.2: `ub[R=14]=8` |
| 18 | `lin_beam_v02_R14_bwd` | linear | 45 min | R=14 backward, v0.2: `ub[R=14]=11` |
| 19 | `lin_hull_v02` | linear | 30 min | Exact hulls at r=10–12, v0.2 |
| 20 | `lin_beam_v02_R128` | linear | 300 min | Full beam to R=128 (all offsets, forward) |
| 21 | `integral_v1_R6` | integral | 45 min | DP R=6, v0.1: `4/256 balanced` |
| 22 | `integral_v02_R5` | integral | 45 min | DP R=5, v0.2: `9/256 balanced` |
| 23 | `integral_v02_R6` | integral | 60 min | DP R=6, v0.2: `4/256 balanced` |
| 24 | `integral_sweep_v02` | integral | 180 min | 31-offset sweep, R=5–10, v0.2 |
| 25 | `rk_basic` | related_key | 10 min | `misc/keyschedule_test.js` |
| 26 | `rk_extended` | related_key | 45 min | `misc/keyschedule_test_extended.js --thorough` |
| 27 | `nist_v1` | nist | 180 min | NIST SP 800-22, consecutive calendar |
| 28 | `nist_v02` | nist | 180 min | NIST SP 800-22, v0.2 calendar |

Tests 7, 8, 12, 13, 19, 20, 24 are the v0.2 additions; all others were present in
v0.1 and are re-runnable as regression.

### Dependencies between tests

- `trunc_v02` requires `trunc_v1` to be correct. Run both.
- `lin_hull_v02` requires `beam_v02_r12.json` (the wrapper generates it if
  absent).
- `nist_v1` and `nist_v02` require `sts-2.1.2/assess`. The CI workflow
  `nist.yml` downloads and builds it; local runs need manual setup.

---

## The runner: `run_test.py`

Low-level interface used by the top-level scripts and the CI matrix.

```bash
# Discover
python3 tests/run_test.py --list
python3 tests/run_test.py --list --group linear

# Run one test
python3 tests/run_test.py --id dmitm_v02 --out results/r.json

# Run a selection
python3 tests/run_test.py --selection all                    # all ready, incl. NIST
python3 tests/run_test.py --selection quick                  # group=basic
python3 tests/run_test.py --selection group=linear
python3 tests/run_test.py --selection "dmitm_v1,dmitm_v02"
python3 tests/run_test.py --selection all --include-pending  # includes PENDING (expected to fail)
```

### Selection syntax

| Selection | Meaning |
|---|---|
| `quick` | `group=basic` |
| `all` | all `status=ready` (including NIST) |
| `all+pending` | every test in the manifest (pending will be `skipped`) |
| `group=<g>` | every ready test in `<g>` |
| `<id>,<id>,...` | explicit list |

### Output

One JSON file per run:

```json
{
  "n_tests": 3,
  "results": [
    {
      "id": "dmitm_v02",
      "name": "Exact DMITM, v0.2 (expect total=9, max=5)",
      "group": "impossible",
      "spec_status": "ready",
      "status": "pass",
      "returncode": 0,
      "elapsed_s": 3.4,
      "assertions": [
        {"type": "returncode_zero", "spec": {...}, "passed": true},
        {"type": "regex", "spec": {...}, "passed": true}
      ],
      "setup": [],
      "stdout_tail": "...",
      "stderr_tail": "..."
    }
  ]
}
```

Status values:

| Status | Meaning |
|---|---|
| `pass` | All assertions passed and return code was 0 |
| `fail` | At least one assertion failed, or return code was non-zero |
| `timeout` | The script exceeded `timeout_minutes` |
| `setup_failed` | One of the `setup` commands returned non-zero |
| `skipped` | Test is `pending` and `--include-pending` was not passed |

### Assertion types

| Type | Checks |
|---|---|
| `returncode_zero` | `returncode == 0` |
| `output_contains` | `value` is a substring of `stdout + "\n" + stderr` |
| `output_not_contains` | `value` is **not** a substring |
| `regex` | `pattern` matches; optional `flags` = `"MULTILINE|IGNORECASE|DOTALL"` |

Every test must have `returncode_zero` plus at least one semantic check
(`output_contains`, `output_not_contains`, or `regex`) — otherwise a script
that exits 0 without doing anything would pass.

---

## Top-level scripts

### `run_all_local.sh`

Orchestrator for local runs. Handles: missing-file warnings, dependency
install (unless `--skip-install`), NIST pre-flight, execution, summary.

```bash
./run_all_local.sh --list
./run_all_local.sh --quick
./run_all_local.sh --new
./run_all_local.sh --no-nist
./run_all_local.sh                            # default: everything incl. NIST
./run_all_local.sh --group linear
./run_all_local.sh --test dmitm_v02
./run_all_local.sh --test "trunc_v1,trunc_v02"
./run_all_local.sh --all+pending
./run_all_local.sh --skip-install
./run_all_local.sh --out results/my_run
```

If NIST is selected but `sts-2.1.2/assess` is missing, the script warns and
**removes NIST from the selection**, then runs the rest. To make NIST a hard
failure instead, set `NIST_STRICT=1` in the environment (see the script).

Results go to `results/local_<TS>/` by default: `results.json`, `run.log`.

### `run_all_gh_actions.sh`

Triggers workflows, waits, downloads artifacts. Requires `gh auth status` to
succeed. Uses `paper.yml` (all non-NIST) and `nist.yml` (v1 and v02).

```bash
./run_all_gh_actions.sh                       # default: paper + nist
./run_all_gh_actions.sh --no-nist
./run_all_gh_actions.sh --quick
./run_all_gh_actions.sh --test dmitm_v02
./run_all_gh_actions.sh --no-wait             # trigger, don't block
./run_all_gh_actions.sh --no-download
./run_all_gh_actions.sh --run-id 12345678     # download an existing run
./run_all_gh_actions.sh --repo owner/name
```

Results are placed in `/tmp/mysx_paper_results/`:

```
/tmp/mysx_paper_results/
├── paper_results.json          # consolidated from paper.yml
├── nist_v1/
│   └── finalAnalysisReport.txt
└── nist_v02/
    └── finalAnalysisReport.txt
```

---

## CI workflows

### `paper.yml`

Manual trigger. Inputs:

| Input | Type | Default | Values |
|---|---|---|---|
| `tests` | string | `quick` | `quick`, `all`, `all+pending`, `group=<g>`, or comma-separated IDs |
| `include_pending` | boolean | `false` | Run pending tests (expected to fail) |

How it works:

1. **`discover`** job reads `tests/manifest.json`, applies the selection, and
   exports a `matrix` with one entry per test ID.
2. **`test`** job runs in a matrix (`max-parallel: 20`). Each job runs
   `tests/run_test.py --id <matrix.test_id>` and uploads `result_<id>.json`.
3. **`merge`** job downloads all result artifacts, calls
   `tests/merge_results.py`, and uploads a single `paper-results` artifact
   containing `results.json`.

If any test fails, the `merge` job's exit code is non-zero and the run is
marked failed. The artifact is still uploaded (`if: always()`), so you can
inspect the results either way.

### `nist.yml`

Manual trigger. Inputs:

| Input | Type | Default | Values |
|---|---|---|---|
| `version` | choice | `v02` | `v1`, `v02` |

Steps:

1. Download [STS 2.1.2](https://csrc.nist.gov/CSRC/media/Projects/Random-Bit-Generation/documents/sts-2_1_2.zip).
2. Unzip, `cd sts-2.1.2 && make`.
3. Generate `misc/nist_input/all_data.bin` with the selected calendar
   (`MYSX_ROT_CAL` set for `v02`).
4. Run `tests/run_nist.py`, which drives `./assess` non-interactively with
   `pexpect`.
5. Upload the NIST report as `nist-report-<version>`.

NIST is non-deterministic (fresh random keys and nonces per sequence), so
the report text changes between runs. The assertion is "zero FAIL/* rows",
which is stable in practice.

---

## Adding a new test

1. **Pick an ID.** Convention: `<family>_<variant>_<detail>`, all lowercase,
   underscores. Groups of related tests share a prefix (`dmitm_v1`,
   `dmitm_v02`).

2. **Write the command.** It must exit 0 on success and print something the
   assertions can match. If the underlying tool has non-deterministic output
   (e.g., NIST), assert on a stable substring.

3. **Add the entry** to `tests/manifest.json` under `tests.<your_id>`. Example:

   ```json
   "dmitm_v02": {
     "name": "Exact DMITM, v0.2 (expect total=9, max=5)",
     "group": "impossible",
     "status": "ready",
     "setup": ["pip install -q pulp highspy"],
     "script": "python3 cryptanalysis/DMITM/dmitm_verify.py exact",
     "env": {"MYSX_ROT_CAL": "${v02_cal}"},
     "timeout_minutes": 15,
     "deterministic": true,
     "assertions": [
       {"type": "returncode_zero"},
       {"type": "regex", "pattern": "maximo global =\\s+5\\b"},
       {"type": "regex", "pattern": "total=9\\b"}
     ]
   }
   ```

4. **Test locally**:

   ```bash
   python3 tests/run_test.py --id dmitm_v02 --out /tmp/r.json
   cat /tmp/r.json | python3 -m json.tool
   ```

   Check `status == "pass"` and every assertion `passed: true`.

5. **Add to CI.** If the new test depends on a new tool (like `pexpect`),
   add the dependency to the `pip install` in `paper.yml` or create a
   dedicated workflow (like `nist.yml`).

6. **If the test requires a script that isn't in the repo**, put the script
   under `tests/` (like `run_hull_v02.py`) and reference it from the
   `script` field.

### Adding a pending test

Set `"status": "pending"`, add `"reason"` (why it can't run yet) and
`"command"` (how to run it manually until it's ready). It will be skipped
by default; `--include-pending` will run it and it will likely fail. This
is the intended pattern for tracked-but-not-implemented tests.

---

## Typical workflows

### First-time setup

```bash
cd /path/to/MYSX-256
chmod +x run_all_local.sh run_all_gh_actions.sh
pip install --user pulp highspy pexpect
(cd sts-2.1.2 && make)   # only if you want NIST locally
```

### Fast iteration (you changed a script, want to know if it still works)

```bash
./run_all_local.sh --quick                # ~5 s
# or a specific test
./run_all_local.sh --test dmitm_v02
```

### Full local verification

```bash
./run_all_local.sh                        # ~3 h on P40, ~1-2 h on a laptop
```

### Full CI verification

```bash
git push
./run_all_gh_actions.sh                   # ~2-3 h
```

### Just the v0.2 additions

```bash
./run_all_local.sh --new
# or
./run_all_gh_actions.sh --test "trunc_v1,trunc_v02,lin_hull_v02,lin_beam_v02_R128,diff_milp_v02_R6_R14,diff_offset_sweep_v02,integral_sweep_v02"
```

### Reproducing a single number from the paper

1. Find the corresponding test ID in the table above.
2. `./run_all_local.sh --test <id>`
3. Read `<out>/results.json`: `results[0].stdout_tail` contains the raw
   output; `results[0].assertions` shows what matched.

### After a code change

Re-run the full suite (local or CI). Any test whose assertion fails
indicates a regression against a paper claim. Fix the code or, if the
paper claim changes intentionally, update both the paper and the
assertion in the manifest together.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `tests/manifest.json not found` | Ran from wrong directory | `cd` to repo root, or pass `--repo-root` |
| `unknown test ID` | Typo in `--test` | `python3 tests/run_test.py --list` |
| All tests `fail` with `returncode_zero` false | Missing deps | `pip install pulp highspy pexpect && npm install` |
| `dmitm_v1` passes but `dmitm_v02` fails | `MYSX_ROT_CAL` leaked from shell | `unset MYSX_ROT_CAL` (the script does this; a manual `python3 tests/run_test.py` does not) |
| `lin_hull_v02` fails with "beam_v02_r12.json not found" | Wrapper couldn't generate it | Run `MYSX_ROT_CAL=<v02_cal> python3 misc/mysx_linear_beam.py run --offsets 12 --rounds 12 --beam 2000 --out beam_v02_r12.json` first |
| NIST: "sts-2.1.2/assess not found" | STS not built | Download [sts-2_1_2.zip](https://csrc.nist.gov/CSRC/media/Projects/Random-Bit-Generation/documents/sts-2_1_2.zip), unzip, `make` |
| NIST: `pexpect` timeout | STS asked an unexpected question | Check STS version matches 2.1.2 (not 2.1.1) |
| `gh workflow run` returns "not found" | Workflow is on `main` only | `git checkout main && git push` the `.github/workflows/*.yml` files |
| `gh run watch` shows a `merge` failure but every test passed | One test was `skipped` because `sts-2.1.2/assess` missing | Run with `--no-nist` on the selection, or make sure NIST is set up |
| A `pending` test fails under `--include-pending` | That's expected | Pending tests are documented but not implemented; see `reason` in the manifest |

---

## Interpreting the results

Every run produces a JSON with a `status` per test. The paper is only
considered "reproduced" when **all** `status: "ready"` tests report `pass`.
A `skipped` pending test is not a failure; it just means the analysis is
documented but not measured.

The `results.json` from a full run is the artifact to attach to the paper
(when it is ready) or to keep alongside a release tag:

```bash
# After a full CI run
cp /tmp/mysx_paper_results/paper_results.json \
   cryptanalysis/DMITM/paper_results_v0.2-draft.json
git add cryptanalysis/DMITM/paper_results_v0.2-draft.json
git commit -m "release: reproducible paper results for v0.2-draft"
```

---

## See also

- `PAPER.md` — the full v0.2-draft paper; every claim here maps to a
  section there.
- `SECURITY.md` — the security status summary; states explicitly which
  sections are measured for v0.2 and which are PENDING.
- `SPEC.md` — the formal specification; the CAL / KDF / rotation-schedule
  definitions the tests exercise.
- `LEGACY_V1/` — the v0.1 paper and reference implementation; the v0.1
  tests in this suite reproduce its numbers.
- `calendar/` — the rotation-schedule selection artifacts
  (`CALENDAR_v02.txt`, `top50_fixed.json`, `wf2_deep_summary.json`).
