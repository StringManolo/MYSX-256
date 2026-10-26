#!/usr/bin/env python3
"""run_diff_milp_v02.py — MILP differential R=6-14 at r0=0,10,20 for v0.2."""
import os, sys, subprocess

V02_CAL = "22,5,8,7,17,10,30,1,11,26,6,3,12,23,25,13,28,20,21,19,24,2,18,9,4,15,29,27,16,14,31"
os.environ['MYSX_ROT_CAL'] = V02_CAL

successes = 0
for R in range(6, 15):
    for r0 in (0, 10, 20):
        print(f"=== R={R} r0={r0} ===")
        p = subprocess.run(
            ["python3", "misc/mysx_milp2.py",
             "--rounds", str(R), "--input-bit", "63", "--r0", str(r0),
             "--solver", "cbc", "--time-limit", "180", "--gap-rel", "0.2"],
            capture_output=True, text=True
        )
        print(p.stdout)
        if p.returncode != 0:
            print(f"  stderr: {p.stderr[-300:]}", file=sys.stderr)
        if "peso mínimo" in p.stdout:
            successes += 1

print(f"\n=== Summary: {successes}/27 (R=6..14 × r0=0,10,20) ===")
if successes < 10:
    print("ERROR: too few successful MILP runs (<10/27)", file=sys.stderr)
    sys.exit(1)
