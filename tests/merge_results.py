#!/usr/bin/env python3
"""merge_results.py — Consolidate per-test result JSONs into results.json."""
import json
import glob
import os
import sys


def main(artifacts_dir, output):
    results = []
    for f in sorted(glob.glob(os.path.join(artifacts_dir, "**", "result_*.json"), recursive=True)):
        try:
            with open(f) as fh:
                d = json.load(fh)
            results.extend(d.get("results", [d]))
        except Exception as e:
            results.append({"id": os.path.basename(f), "status": "parse_error",
                            "error": str(e), "file": f})

    results.sort(key=lambda r: r.get("id", ""))

    n_pass = sum(1 for r in results if r.get("status") == "pass")
    n_fail = sum(1 for r in results if r.get("status") == "fail")
    n_skip = sum(1 for r in results if r.get("status") == "skipped")
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
    with open(output, "w") as f:
        json.dump(out, f, indent=2)
    print(f"Wrote {output}: {n_pass} pass, {n_fail} fail, {n_skip} skipped, {n_other} other")
    return 0 if n_fail == 0 and n_other == 0 else 1


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("Usage: merge_results.py <artifacts_dir> <output.json>")
    sys.exit(main(sys.argv[1], sys.argv[2]))
