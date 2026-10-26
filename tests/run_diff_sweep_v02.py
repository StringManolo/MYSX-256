#!/usr/bin/env python3
"""run_diff_sweep_v02.py — Differential offset sweep (31 offsets) for v0.2."""
import os, sys, subprocess, json

V02_CAL = "22,5,8,7,17,10,30,1,11,26,6,3,12,23,25,13,28,20,21,19,24,2,18,9,4,15,29,27,16,14,31"
os.environ['MYSX_ROT_CAL'] = V02_CAL

results = {}
for r0 in range(31):
    cmd = f"python3 misc/mysx_milp2.py --rounds 14 --input-bit 63 --r0 {r0} --solver highs --time-limit 120"
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    # Parse "peso mínimo= X"
    import re
    m = re.search(r"peso mínimo=\s*(\d+)", p.stdout)
    w = int(m.group(1)) if m else None
    results[r0] = w
    print(f"r0={r0:2d}  weight={w}")

print("\n=== Summary ===")
for r0, w in sorted(results.items()):
    print(f"r0={r0:2d}: {w}")
print(f"\nBest: r0={min(results, key=results.get)} weight={min(results.values())}")
