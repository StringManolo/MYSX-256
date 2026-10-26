#!/usr/bin/env python3
"""run_diff_sweep_full_v1.py — Full 31-offset differential sweep at R=14 (v0.1).

Paper claim: r0=10 is the best (weight 2); r0=1 is the worst (~121).
"""
import subprocess, re, sys

INPUT_BIT = 63
results = {}
for r0 in range(31):
    r = subprocess.run(
        ["python3", "misc/mysx_milp2.py",
         "--rounds", "14", "--input-bit", str(INPUT_BIT),
         "--r0", str(r0), "--solver", "cbc",
         "--gap-rel", "0.2", "--time-limit", "60"],
        capture_output=True, text=True
    )
    m = re.search(r"peso mínimo=\s*(\d+)", r.stdout)
    results[r0] = int(m.group(1)) if m else None
    print(f"r0={r0:2d}  weight={results[r0]}")

valid = {r0: w for r0, w in results.items() if w is not None}
if len(valid) < 15:
    print(f"FAIL: only {len(valid)}/31 offsets measured", file=sys.stderr)
    sys.exit(1)

best_r0 = min(valid, key=valid.get)
best_w = valid[best_r0]
worst_r0 = max(valid, key=valid.get)
worst_w = valid[worst_r0]
print(f"\nBest: r0={best_r0} weight={best_w}")
print(f"Worst: r0={worst_r0} weight={worst_w}")

# Assertions from the paper
if best_r0 != 10:
    print(f"FAIL: expected best at r0=10, got r0={best_r0}", file=sys.stderr)
    sys.exit(1)
if best_w > 5:
    print(f"FAIL: expected best weight <=5, got {best_w}", file=sys.stderr)
    sys.exit(1)
if worst_w < 80:
    print(f"FAIL: expected worst weight >=80, got {worst_w}", file=sys.stderr)
    sys.exit(1)

print(f"\nOK: best r0=10 (w={best_w}), worst r0={worst_r0} (w={worst_w})")
print(f"Best: r0={best_r0} weight={best_w}")
