#!/usr/bin/env python3
"""
run_test.py — Universal runner for the paper's reproducibility tests.

Reads tests/manifest.json, filters by selection, runs each test, captures
output, applies assertions, writes a per-test JSON result.

Usage:
    python3 tests/run_test.py --list
    python3 tests/run_test.py --list --group linear
    python3 tests/run_test.py --id dmitm_v02
    python3 tests/run_test.py --selection all
    python3 tests/run_test.py --selection all --include-pending
    python3 tests/run_test.py --selection group=linear
    python3 tests/run_test.py --selection "kat_v1,dmitm_v1,trunc_v1"
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time


def load_manifest(path):
    with open(path) as f:
        m = json.load(f)
    if not isinstance(m.get("tests"), dict):
        sys.exit(f"ERROR: {path} has no 'tests' dict")
    m.setdefault("groups", {})
    m.setdefault("v02_cal", "")
    return m


def expand_env(spec_env, manifest):
    """Replace ${v02_cal} with manifest['v02_cal']."""
    out = {}
    for k, v in (spec_env or {}).items():
        if isinstance(v, str):
            v = v.replace("${v02_cal}", manifest.get("v02_cal", ""))
        out[k] = v
    return out


def filter_tests(manifest, selection, include_pending):
    tests = manifest["tests"]
    sel = (selection or "").strip()

    if sel == "" or sel == "quick":
        sel = "group=basic"

    if sel == "all":
        return [k for k, v in tests.items()
                if v.get("status", "ready") == "ready"]
    if sel == "all+pending":
        return list(tests.keys())

    if sel.startswith("group="):
        g = sel[len("group="):]
        ids = [k for k, v in tests.items() if v.get("group") == g
               and v.get("status", "ready") == "ready"]
        if include_pending:
            ids = [k for k, v in tests.items() if v.get("group") == g]
        return ids

    # Comma-separated IDs
    ids = [s.strip() for s in sel.split(",") if s.strip()]
    known = set(tests.keys())
    unknown = [i for i in ids if i not in known]
    if unknown:
        sys.exit(f"ERROR: unknown test IDs: {unknown}\n"
                 f"  Known IDs: {sorted(known)}")
    return ids


def apply_assertion(a, output, returncode):
    t = a["type"]
    if t == "returncode_zero":
        return returncode == 0
    if t == "output_contains":
        return a["value"] in output
    if t == "output_not_contains":
        return a["value"] not in output
    if t == "regex":
        flags = 0
        for f in (a.get("flags") or "").split("|"):
            f = f.strip()
            if f == "MULTILINE":
                flags |= re.MULTILINE
            elif f == "IGNORECASE":
                flags |= re.IGNORECASE
            elif f == "DOTALL":
                flags |= re.DOTALL
        return re.search(a["pattern"], output, flags) is not None
    return False


def run_test(test_id, spec, manifest, repo_root):
    t0 = time.time()
    result = {"id": test_id, "name": spec.get("name", test_id),
              "group": spec.get("group", ""), "spec_status": spec.get("status", "ready")}

    # Fail fast if pending and not allowed
    if spec.get("status", "ready") == "pending" and not spec.get("_allow_pending"):
        result["status"] = "skipped"
        result["reason"] = spec.get("reason", "pending")
        result["expected"] = spec.get("expected", "")
        result["command"] = spec.get("command", "")
        result["elapsed_s"] = 0
        return result

    # requires_file: skip gracefully if the required file is absent
    req = spec.get("requires_file")
    if req:
        import os as _os
        if not _os.path.exists(_os.path.join(repo_root, req)):
            result["status"] = "skipped"
            result["reason"] = f"requires_file not present: {req}"
            result["elapsed_s"] = 0
            return result

    env = os.environ.copy()
    for k, v in expand_env(spec.get("env"), manifest).items():
        if v == "":
            env.pop(k, None)
        else:
            env[k] = v

    # Per-test setup
    setup_log = []
    for cmd in spec.get("setup", []):
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=300, cwd=repo_root)
        setup_log.append({"cmd": cmd, "returncode": r.returncode,
                          "stderr": r.stderr[-500:] if r.stderr else ""})
        if r.returncode != 0:
            result["status"] = "setup_failed"
            result["setup"] = setup_log
            result["elapsed_s"] = round(time.time() - t0, 1)
            return result

    # Run the script
    timeout = spec.get("timeout_minutes", 30) * 60
    try:
        r = subprocess.run(spec["script"], shell=True, capture_output=True,
                           text=True, timeout=timeout, env=env, cwd=repo_root)
    except subprocess.TimeoutExpired as e:
        result["status"] = "timeout"
        result["elapsed_s"] = round(time.time() - t0, 1)
        result["setup"] = setup_log
        result["stdout_tail"] = (e.stdout or "")[-3000:] if e.stdout else ""
        result["stderr_tail"] = (e.stderr or "")[-3000:] if e.stderr else ""
        return result

    output = (r.stdout or "") + "\n" + (r.stderr or "")

    # Assertions
    assertions_log = []
    all_pass = True
    for a in spec.get("assertions", []):
        ok = apply_assertion(a, output, r.returncode)
        assertions_log.append({"type": a["type"], "spec": a, "passed": ok})
        if not ok:
            all_pass = False

    result["status"] = "pass" if (all_pass and r.returncode == 0) else "fail"
    result["returncode"] = r.returncode
    result["elapsed_s"] = round(time.time() - t0, 1)
    result["assertions"] = assertions_log
    result["setup"] = setup_log
    result["stdout_tail"] = (r.stdout or "")[-3000:]
    result["stderr_tail"] = (r.stderr or "")[-2000:]
    if spec.get("status", "ready") == "pending":
        result["note"] = "This test is PENDING; a 'fail' here is expected."
        result["command"] = spec.get("command", "")
        result["expected"] = spec.get("expected", "")
    return result


def cmd_list(manifest, group):
    print(f"{'ID':30s} {'GROUP':14s} {'STATUS':8s} {'TIMEOUT':>8s}  NAME")
    print("-" * 100)
    for test_id, spec in sorted(manifest["tests"].items()):
        if group and spec.get("group") != group:
            continue
        status = spec.get("status", "ready")
        tm = spec.get("timeout_minutes", "?")
        print(f"{test_id:30s} {spec.get('group',''):14s} {status:8s} {str(tm):>8s}  {spec.get('name', '')}")
    print()
    print("Groups:", ", ".join(sorted(manifest.get("groups", {}).keys())))
    print("Pending tests (with `--include-pending`):",
          [k for k, v in manifest["tests"].items() if v.get("status") == "pending"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default="tests/manifest.json")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--group", default="")
    ap.add_argument("--id", default="")
    ap.add_argument("--selection", default="")
    ap.add_argument("--include-pending", action="store_true")
    ap.add_argument("--out", default="")
    ap.add_argument("--repo-root", default=".")
    a = ap.parse_args()

    if not os.path.exists(a.manifest):
        sys.exit(f"ERROR: {a.manifest} not found. Run from repo root.")

    manifest = load_manifest(a.manifest)

    if a.list:
        cmd_list(manifest, a.group)
        return 0

    if a.id:
        ids = [a.id]
        if a.id not in manifest["tests"]:
            sys.exit(f"ERROR: unknown test ID: {a.id}")
    else:
        ids = filter_tests(manifest, a.selection, a.include_pending)
        if not ids:
            sys.exit(f"ERROR: no tests matched selection '{a.selection}'")

    print(f"Selected {len(ids)} test(s): {ids}")
    print()

    results = []
    for test_id in ids:
        spec = dict(manifest["tests"][test_id])
        if a.include_pending:
            spec["_allow_pending"] = True
        print(f"=== {test_id} ({spec.get('name', '')}) ===")
        res = run_test(test_id, spec, manifest, a.repo_root)
        results.append(res)
        print(f"  status: {res['status']}  ({res.get('elapsed_s', 0)}s)")
        for a_log in res.get("assertions", []):
            mark = "OK" if a_log["passed"] else "FAIL"
            print(f"    [{mark}] {a_log['type']}: {a_log['spec']}")
        if res["status"] == "skipped":
            print(f"    reason: {res.get('reason', '')}")
            print(f"    command: {res.get('command', '')}")
        print()

    if a.out:
        os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
        with open(a.out, "w") as f:
            json.dump({"n_tests": len(results), "results": results}, f, indent=2)
        print(f"Wrote {a.out}")

    # Exit 0 if all pass (or skipped); 1 if any fail
    n_fail = sum(1 for r in results if r["status"] in ("fail", "timeout", "setup_failed"))
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())