#!/usr/bin/env python3
"""Count trails of weight <= WMAX that share (start, end) masks with a saved beam trail
(PAPER.md 4.10.3). usage: python3 hull_count.py beam_full.json OFFSET [--R 14] [--wmax 4]
An even count of equal-weight trails signals possible cancellation."""
import json, sys, argparse, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mysx_linear_beam import *

ap = argparse.ArgumentParser()
ap.add_argument("json"); ap.add_argument("offset", type=int)
ap.add_argument("--R", type=int, default=14); ap.add_argument("--wmax", type=int, default=4)
a = ap.parse_args()
d = json.load(open(a.json))
r = [x for x in d["results"] if x["offset"] == a.offset][0]
path = [int(h, 16) for h in r["paths"][str(a.R)]]
first = r.get("first_round", {}).get(str(a.R), a.offset)   # first round of the saved trail

def full_expand(x, sh):
    w = [(x >> (32 * i)) & M32 for i in range(8)]
    infos = []; tot = 0
    for p in range(4):
        o = cell_info(w[p], a.wmax)
        if o is None: return
        tot += o[0]; infos.append(o)
    if tot > a.wmax: return
    hi = 0
    for p in range(4): hi |= w[p] << (32 * (p + 4))
    combos = [hi]
    for p in range(4):
        h, basis, base = infos[p]; t = w[p + 4] ^ base
        span = [t]
        for bv in basis: span += [s ^ bv for s in span]
        combos = [c | (v << (32 * p)) for c in combos for v in span]
    for c in combos: yield lin(c, sh), tot

layer = {(path[0], 0): 1}
for R in range(1, a.R + 1):
    sh = ((first + R - 1) % 31) + 1
    nxt = {}
    for (x, wx), cnt in layer.items():
        for y, c in full_expand(x, sh):
            if wx + c <= a.wmax:
                nxt[(y, wx + c)] = nxt.get((y, wx + c), 0) + cnt
    layer = nxt
    t = {w: c for (y, w), c in layer.items() if y == path[R]}
    print("R=%2d  trails to the saved end mask by weight: %s   (layer size %d)" % (R, t, len(layer)))
    if not layer: break
