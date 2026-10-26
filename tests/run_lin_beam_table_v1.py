#!/usr/bin/env python3
"""run_lin_beam_table_v1.py — Verify the paper's beam table (v0.1).

Reads misc/beam_full.json + misc/beam_bwd.json, merges, checks each
paper checkpoint (R, expected weight, expected offset, expected direction).
"""
import json, sys, os

FULL = 'misc/beam_full.json'
BWD  = 'misc/beam_bwd.json'
for f in (FULL, BWD):
    if not os.path.exists(f):
        print(f"ERROR: {f} missing (should be committed with the paper)", file=sys.stderr)
        sys.exit(1)

# Paper table §4.10.2
PAPER = [
    (9,   0,    4,  'backward'),
    (10,  1,    4,  'backward'),
    (12,  2,   20,  'backward'),
    (14,  5,   20,  'backward'),
    (16,  8,   23,  'forward'),
    (18, 24,   20,  'backward'),
    (20, 38,   20,  'backward'),
    (22, 63,   23,  'forward'),
    (24, 88,    3,  'backward'),
    (32, 204,   3,  'backward'),
    (40, 361,  20,  'backward'),
    (48, 485,  20,  'backward'),
    (56, 630,  27,  'forward'),
    (64, 786,  27,  'forward'),
    (80, 1081,  9,  'forward'),
    (96, 1336, 21,  'backward'),
    (112, 1671, 21, 'backward'),
    (128, 2248, 3,  'backward'),
]

def load(path):
    return json.load(open(path))['results']

full, bwd = load(FULL), load(BWD)
by_off = {}
for r in full:
    by_off[(r['offset'], 'forward')] = r
for r in bwd:
    by_off[(r['offset'], 'backward')] = r

fail = []
print(f"{'R':>4}  {'paper':>6}  {'actual':>6}  {'off':>3}  {'dir':>8}  status")
print("-" * 50)
for R, w_exp, off_exp, dir_exp in PAPER:
    key = (off_exp, dir_exp)
    if key not in by_off:
        print(f"{R:>4}  {w_exp:>6}  {'MISS':>6}  {off_exp:>3}  {dir_exp:>8}  FAIL (run not loaded)")
        fail.append(R); continue
    res = by_off[key]
    ub = res.get('ub')
    if not ub or len(ub) < R:
        print(f"{R:>4}  {w_exp:>6}  {'SHORT':>6}  {off_exp:>3}  {dir_exp:>8}  FAIL (ub missing)")
        fail.append(R); continue
    w_act = ub[R - 1]
    ok = (w_act == w_exp)
    print(f"{R:>4}  {w_exp:>6}  {w_act:>6}  {off_exp:>3}  {dir_exp:>8}  {'OK' if ok else 'MISMATCH'}")
    if not ok:
        fail.append(R)

if fail:
    print(f"\nFAIL at R: {fail}", file=sys.stderr)
    sys.exit(1)
print(f"\nOK: all {len(PAPER)} checkpoints match the paper")
