#!/usr/bin/env python3
"""run_diff_growth_v1.py — Differential growth at r0=10, R=14..24 (v0.1).

Paper claim: 2,4,6,10,15,22,34,49,78,100,133 (from beam).
MILP gives upper bounds, so MILP[R] >= paper[R]; growth monotonic.
"""
import subprocess, re, sys

INPUT_BIT = 63
R_RANGE = list(range(14, 25))
PAPER = {14:2, 15:4, 16:6, 17:10, 18:15, 19:22, 20:34,
         21:49, 22:78, 23:100, 24:133}
weights = {}

for R in R_RANGE:
    r = subprocess.run(
        ["python3", "misc/mysx_milp2.py",
         "--rounds", str(R), "--input-bit", str(INPUT_BIT),
         "--r0", "10", "--solver", "cbc",
         "--gap-rel", "0.2", "--time-limit", "120"],
        capture_output=True, text=True
    )
    m = re.search(r"peso mínimo=\s*(\d+)", r.stdout)
    weights[R] = int(m.group(1)) if m else None
    print(f"R={R:2d}  MILP={weights[R]}  paper={PAPER[R]}")

valid = [w for w in weights.values() if w is not None]
if len(valid) < 8:
    print(f"FAIL: only {len(valid)}/{len(R_RANGE)} rounds measured", file=sys.stderr)
    sys.exit(1)

# Monotonic
prev = 0
for R in R_RANGE:
    w = weights[R]
    if w is not None and w < prev:
        print(f"FAIL: weight decreased at R={R} ({w} < {prev})", file=sys.stderr)
        sys.exit(1)
    prev = w or prev

# Paper is beam (tighter), MILP is upper bound
for R in R_RANGE:
    w = weights[R]
    p = PAPER[R]
    if w is None:
        continue
    if w < p:
        print(f"FAIL: MILP < paper at R={R} ({w} < {p})", file=sys.stderr)
        sys.exit(1)
    if w > 2 * p + 10:
        print(f"FAIL: MILP too loose at R={R} ({w} > 2*{p}+10)", file=sys.stderr)
        sys.exit(1)

# Growth factor
w14, w24 = weights.get(14), weights.get(24)
if w14 and w24 and w24 / w14 < 10:
    print(f"FAIL: growth factor {w24/w14:.1f} < 10", file=sys.stderr)
    sys.exit(1)

print(f"\nOK: monotonic, paper <= MILP <= 2*paper+10, growth {w24/w14:.1f}x")
