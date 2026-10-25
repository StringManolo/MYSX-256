#!/usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.normpath('cryptanalysis/models/linear'))
from mysx_linear_model import lin_fwd

def step(m, r):
    # weight-0 differential: ΔR=0, after Feistel s_mid=(0,0,0,0,ΔL0..ΔL3)
    return lin_fwd((0, 0, 0, 0, m[0], m[1], m[2], m[3]), r)

def chain(m, r0, cap=64):
    k = 0
    while k < cap and all(m[i] == 0 for i in range(4, 8)):
        m = step(m, r0 + k)
        k += 1
    return k

def bit_L(i):
    w, b = divmod(i, 32)
    m = [0]*8; m[w] = 1 << b
    return tuple(m)

rows = []
for r0 in range(31):
    lens = [chain(bit_L(i), r0) for i in range(128)]
    mx = max(lens); bi = lens.index(mx)
    rows.append((r0, mx, bi, lens.count(mx)))
rows.sort(key=lambda x: -x[1])
print("Differential free chain table (analogous to linear §4.3)")
print("r0  max_rounds  example_bit  n_bits_at_max")
for r0, mx, bi, n in rows:
    print(f"{r0:2d}  {mx:2d}         w{bi//32}b{bi%32:<2d}     {n}")
