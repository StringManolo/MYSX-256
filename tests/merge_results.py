#!/usr/bin/env python3
"""merge_results.py — Consolidate per-test result JSONs into results.json."""
import json
import glob
import os
import sys


def extract_tests(d):
    """Return a list of test-result dicts from a parsed JSON file.

    Handles three formats:
      1. {"n_tests": N, "results": [test_dict, ...]}  (run_test.py output)
      2. [test_dict, ...]                              (bare list)
      3. {test_dict} with "status" field               (single test)
    """
    if isinstance(d, list):
        return [t for t in d if isinstance(t, dict)]
    if isinstance(d, dict):
        if "results" in d and isinstance(d["results"], list):
            return [t for t in d["results"] if isinstance(t, dict)]
        if "status" in d:
            return [d]
    return []


def main(artifacts_dir, output):
    results = []
    pattern = os.path.join(artifacts_dir, "**", "result_*.json")
    files = sorted(glob.glob(pattern, recursive=True))
    print(f"Found {len(files)} result files under {artifacts_dir}", file=sys.stderr)

    for f in files:
        try:
            with open(f) as fh:
                d = json.load(fh)
            tests = extract_tests(d)
            if not tests:
                results.append({"id": os.path.basename(f).replace("result_", "").replace(".json", ""),
                                "status": "parse_error",
                                "error": "no test objects extracted",
                                "file": f})
            else:
                for t in tests:
                    if "id" not in t:
                        t["id"] = os.path.basename(f).replace("result_", "").replace(".json", "")
                    results.append(t)
        except Exception as e:
            results.append({"id": os.path.basename(f), "status": "parse_error",
                            "error": str(e), "file": f})

    results.sort(key=lambda r: r.get("id", ""))

    n_pass  = sum(1 for r in results if r.get("status") == "pass")
    n_fail  = sum(1 for r in results if r.get("status") in ("fail", "error", "timeout", "setup_failed"))
    n_skip  = sum(1 for r in results if r.get("status") == "skipped")
    n_other = len(results) - n_pass - n_fail - n_skip

    out = {
        "manifest_version": 1,
        "n_tests": len(results),
        "n_pass": n_pass,
        "n_fail": n_fail,
        "n_skipped": n_skip,
        "n_other": n_other,
        "tests": results,
    }
    with open(output, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"Wrote {output}: {n_pass} pass, {n_fail} fail, {n_skip} skipped, {n_other} other")
    return 0 if n_fail == 0 and n_other == 0 else 1


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("Usage: merge_results.py <artifacts_dir> <output.json>")
    sys.exit(main(sys.argv[1], sys.argv[2]))
