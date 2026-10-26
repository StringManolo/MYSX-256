#!/usr/bin/env python3
"""run_diff_milp_v02_R5.py — MILP differential R=5 (v0.2).

The paper's §4.13 says milp5 = 4. This came from run_5round_test.py taking
min over r0 ∈ {0, 10, 20}. We reproduce that here.
"""
import os, sys, subprocess, re

V02_CAL = "22,5,8,7,17,10,30,1,11,26,6,3,12,23,25,13,28,20,21,19,24,2,18,9,4,15,29,27,16,14,31"
os.environ['MYSX_ROT_CAL'] = V02_CAL

results = {}
for r0 in (0, 10, 20):
    print(f"--- r0={r0} ---", file=sys.stderr)
    r = subprocess.run(
        ["python3", "misc/mysx_milp2.py",
         "--rounds", "5", "--input-bit", "63",
         "--r0", str(r0), "--solver", "cbc",
         "--gap-rel", "0.2", "--time-limit", "60"],
        capture_output=True, text=True
    )
    m = re.search(r"peso mínimo=\s*(\d+)", r.stdout)
    results[r0] = int(m.group(1)) if m else None
    print(f"r0={r0}: weight={results[r0]}")

valid = {r0: w for r0, w in results.items() if w is not None}
if not valid:
    print("FAIL: no MILP result obtained", file=sys.stderr); sys.exit(1)

best = min(valid.values())
print(f"\nmin_weight={best}")

if best != 4:
    print(f"FAIL: expected milp5=4, got {best}", file=sys.stderr); sys.exit(1)
print("OK: milp5 = 4 (matches §4.13)")
