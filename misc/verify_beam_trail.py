#!/usr/bin/env python3
"""Prefix-by-prefix check of a saved beam trail against the real cipher (PAPER.md 4.10.3).
usage: python3 verify_beam_trail.py beam_full.json OFFSET [--R 14] [--seed 1] [--n 17]
Needs mysx_linear_beam.py in the same directory. Fixed key, final whitening disabled."""
import json, random, sys, argparse, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mysx_linear_beam import *

ap = argparse.ArgumentParser()
ap.add_argument("json"); ap.add_argument("offset", type=int)
ap.add_argument("--R", type=int, default=14); ap.add_argument("--seed", type=int, default=1)
ap.add_argument("--n", type=int, default=17, help="log2 of the number of random states")
a = ap.parse_args()
d = json.load(open(a.json))
r = [x for x in d["results"] if x["offset"] == a.offset][0]
path = [int(h, 16) for h in r["paths"][str(a.R)]]
o = a.offset
cum = [0]
for m in path[:-1]:
    cum.append(cum[-1] + sum(cell_info((m >> (32 * p)) & M32, 16)[0] for p in range(4)))
N = 1 << a.n
rng = random.Random(11)
rks = key_schedule(bytes(random.Random(a.seed).getrandbits(8) for _ in range(64)))
acc = [0] * (a.R + 1)
for _ in range(N):
    x = [rng.getrandbits(32) for _ in range(8)]
    base = popcount(path[0] & to_int(x)); st = x
    for R in range(1, a.R + 1):
        st = round_enc(st, rks[o + R - 1], o + R - 1)
        acc[R] += 1 - 2 * ((base ^ popcount(path[R] & to_int(st))) & 1)
print("offset %d, key seed %d, N=2^%d, sigma=%.4f" % (o, a.seed, a.n, N ** -0.5))
for R in range(1, a.R + 1):
    print("R=%2d  w=%3d  pred 2^-w=%.4f  emp=%+.4f" % (R, cum[R], 2.0 ** -cum[R], acc[R] / N))
