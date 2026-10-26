#!/usr/bin/env python3
"""run_diff_sweep_v1.py — Differential offset spot check (v0.1).

Verifies the paper's claim that the rotation offset matters a great deal:
at R=14, r0=10 gives weight ~2, while other offsets give ~100+.
"""
import subprocess, re, sys

INPUT_BIT = 63  # w1b31 (free-chain-optimal at r0=10)
r0s = (0, 1, 10, 15, 30)
results = {}

for r0 in r0s:
    print(f"--- r0={r0:2d} ---", file=sys.stderr)
    r = subprocess.run(
        ["python3", "misc/mysx_milp2.py",
         "--rounds", "14", "--input-bit", str(INPUT_BIT),
         "--r0", str(r0), "--solver", "cbc",
         "--gap-rel", "0.2", "--time-limit", "120"],
        capture_output=True, text=True
    )
    m = re.search(r"peso mínimo=\s*(\d+)", r.stdout)
    results[r0] = int(m.group(1)) if m else None
    print(f"r0={r0:2d}: weight={results[r0]}")

valid = {r0: w for r0, w in results.items() if w is not None}

if 10 not in valid:
    print(f"FAIL: r0=10 not measured", file=sys.stderr); sys.exit(1)
if valid[10] > 10:
    print(f"FAIL: r0=10 weight {valid[10]} > 10 (expected ~2)", file=sys.stderr); sys.exit(1)

others = [w for r0, w in valid.items() if r0 != 10]
if not others or max(others) < 50:
    print(f"FAIL: no other offset gives large weight (max={max(others) if others else 'none'})",
          file=sys.stderr); sys.exit(1)

print(f"\nOK: r0=10 gives {valid[10]}, max across others is {max(others)}")
print(f"Best: r0={min(valid, key=valid.get)} weight={min(valid.values())}")
