#!/usr/bin/env python3
"""scan_endpairs.py -- for a given R, take the top-K end-mask pairs (not only the single best)
of the beam final layer of each (offset, direction) and compute the exact budgeted hull of each
with hull_bidir.  Output: table  offset dir idx weight | #trails at min weight | signed hull (2 keys)."""
import sys, json, time, argparse, math
from fractions import Fraction
from mysx_linear_beam import (expand, expand_backward, make_starts, end_round, popcount, PERIOD, M32)
import hull_bidir as H
import mysx_linear_model as ML

def beam_layers(o, rounds, beam, hmax=16, rcap=64, gkeep=3, direction="forward"):
    bwd = direction == "backward"
    st0 = make_starts("single")
    layers = [(st0, [0] * len(st0), [-1] * len(st0))]
    for r in range(rounds):
        sh = (((o - r) if bwd else (o + r)) % PERIOD) + 1
        gen = expand_backward if bwd else expand
        st, wt, _ = layers[-1]
        nxt = {}
        for idx in range(len(st)):
            wx = wt[idx]
            for y, c in gen(st[idx], sh, hmax, rcap, gkeep):
                wy = wx + c
                en = nxt.get(y)
                if en is None or wy < en[0]:
                    nxt[y] = (wy, idx)
        if not nxt:
            break
        items = sorted(nxt.items(), key=lambda kv: (kv[1][0], popcount(kv[0])))[:beam]
        layers.append(([k for k, _ in items], [v[0] for _, v in items], [v[1] for _, v in items]))
    return layers

def path_of(layers, R, idx, bwd):
    path = []
    for L in range(R, -1, -1):
        path.append(layers[L][0][idx]); idx = layers[L][2][idx]
    return path if bwd else path[::-1]

ap = argparse.ArgumentParser()
ap.add_argument("--R", type=int, required=True)
ap.add_argument("--cells", required=True, help="e.g. 20:backward,23:forward,19:backward")
ap.add_argument("--topk", type=int, default=10)
ap.add_argument("--extra", type=int, default=0)
ap.add_argument("--max-states", type=int, default=800000)
ap.add_argument("--beam", type=int, default=2000)
a = ap.parse_args()
R = a.R
keys = [ML.rand_key(1000), ML.rand_key(1001)]
RKL = [[H.rk_int(rk) for rk in ML.key_schedule(k)[0]] for k in keys]
print("R=%d  top-%d end pairs per cell, wmax = weight + %d" % (R, a.topk, a.extra), flush=True)
print("%-12s %3s %6s | %-34s | %s" % ("cell", "idx", "w", "trails u->v by weight (<=wmax)", "signed hull, key0 / key1  (log2 |corr|)"), flush=True)
for cell in a.cells.split(","):
    o, d = cell.split(":"); o = int(o); bwd = d == "backward"
    layers = beam_layers(o, R, a.beam, direction=d)
    if len(layers) <= R:
        print("%2d:%-9s beam died before R" % (o, d)); continue
    first = (end_round(o) - R + 1) if bwd else o
    st, wt, _ = layers[R]
    for idx in range(min(a.topk, len(st))):
        path = path_of(layers, R, idx, bwd)
        w = wt[idx]; wmax = w + a.extra
        t0 = time.time()
        res = H.hull(path[0], path[R], first, R, wmax, None, False, a.max_states, verbose=False)
        if res is None:
            print("%2d:%-9s %3d %6d | ABORTED (> %d states)" % (o, d, idx, w, a.max_states), flush=True); continue
        vals = []
        for RK in RKL:
            sg = H.hull(path[0], path[R], first, R, wmax, RK, True, a.max_states, verbose=False)
            v = sum(Fraction(c, 1 << ww) for ww, c in sg.items())
            vals.append("0" if v == 0 else "%s2^%.2f" % ("-" if v < 0 else "+", math.log2(abs(v))))
        print("%2d:%-9s %3d %6d | %-34s | %s / %s   [%.0fs]" % (o, d, idx, w, dict(sorted(res.items())), vals[0], vals[1], time.time() - t0), flush=True)
