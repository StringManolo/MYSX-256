#!/usr/bin/env python3
"""run_hull_v1.py — Exact signed hulls at r=10,11,12 (v0.1, r0=12).

Reproduces PAPER.md §4.6 table: 3 trails, 3 exact hulls, |z|<0.4.
"""
import sys, os
sys.path.insert(0, 'cryptanalysis/models/linear')
os.environ.pop('MYSX_ROT_CAL', None)  # force v0.1 consecutive calendar

from mysx_linear_model import (
    propagate, key_schedule, rand_key, to_float,
    empirical_corr, beam_trails, low_hw_masks
)

print("Building beam trails for r0=12...", file=sys.stderr)
starts = low_hw_masks(1)
best = beam_trails(12, starts, beam=1200, hexp=2, r0=12)

rks = key_schedule(rand_key(1))[0]
print(f"\n{'R':>3}  {'w':>3}  {'hull':>5}  {'predicted':>10}  {'empirical':>10}  {'sigma':>10}  {'z':>6}")
print("-" * 70)

all_ok = True
for R in (10, 11, 12):
    w, path = best[R]
    hull = propagate(path[0], R, rks=rks, T=w + 4, cap=20000, r0=12)
    pred = hull.get(path[-1], 0)
    emp, sig = empirical_corr(path[0], path[-1], rks, R, N=1 << 22, seed=21, r0=12)
    z = (emp - to_float(pred)) / sig if sig > 0 else 0.0
    print(f"{R:>3}  {w:>3}  {len(hull):>5}  {to_float(pred):>+10.6f}  "
          f"{emp:>+10.6f}  {sig:>10.2e}  {z:>+6.2f}")
    if abs(z) >= 0.4:
        all_ok = False

if not all_ok:
    print("\nFAIL: at least one |z| >= 0.4", file=sys.stderr); sys.exit(1)

print("\nOK: all |z| < 0.4 (exact hulls match the real cipher)")
