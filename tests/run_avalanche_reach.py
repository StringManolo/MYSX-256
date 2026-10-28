#!/usr/bin/env python3
"""
tests/run_avalanche_reach.py - Alcance estructural minimo por ronda (min-reach), DETERMINISTA.

Para cada bit de entrada, propaga el conjunto de bits de salida que pueden cambiar
(modelo del paper: F activa los bits rotl(a,1)|rotl(a,8)|rotl(a,2) del vecino) y toma el
minimo sobre los 256 bits de entrada. Para el calendario consecutivo reproduce EXACTAMENTE
la columna minReach del paper (r=1..15). Para v0.2 NO debe coincidir con v0.1.

  --cal k1    calendario consecutivo (v0.1)
  --cal v02   calendario v0.2 (de MYSX_ROT_CAL si esta definida, si no el hardcodeado)

Sirve tambien de CONTROL del avalanche.js: si avalanche_v02 imprime la misma tabla que v0.1,
el calendario no se esta aplicando (bug de entorno), no es que v0.2 difunda igual.
"""
import argparse, os, sys

MYZ = [4,12,20,28,0,8,16,24,5,13,21,29,2,7,10,15,18,23,26,31,6,14,22,30,1,9,17,25,3,11,19,27]
V02_CAL = [22,5,8,7,17,10,30,1,11,26,6,3,12,23,25,13,28,20,21,19,24,2,18,9,4,15,29,27,16,14,31]
PAPER_V1 = [1,1,1,4,10,23,55,111,156,213,239,249,253,255,256]          # PAPER v0.1, r=1..15
EXPECTED_V02 = [1,1,1,1,4,10,24,41,103,166,207,229,251,253,256]        # calculado, r=1..15
M = 0xFFFFFFFF


def rotl(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & M

def b2w(bs): return [(bs[4*i] << 24) | (bs[4*i+1] << 16) | (bs[4*i+2] << 8) | bs[4*i+3] for i in range(8)]
def w2b(ws):
    b = []
    for w in ws: b += [(w >> 24) & 255, (w >> 16) & 255, (w >> 8) & 255, w & 255]
    return b

def step(S, r, cal):
    mid = [0] * 8
    for p in range(4):
        a, l = S[p + 4], S[p]
        mid[p] = a
        mid[p + 4] = l | rotl(a, 1) | rotl(a, 8) | rotl(a, 2)
    b = w2b(mid); b = [b[MYZ[j]] for j in range(32)]
    return [rotl(w, cal[r % 31]) for w in b2w(b)]

def table(cal, rmax):
    res = {r: (999, -1) for r in range(1, rmax + 1)}
    for pos in range(256):
        S = [0] * 8; S[pos // 32] = 1 << (pos % 32)
        for r in range(1, rmax + 1):
            S = step(S, r - 1, cal)
            n = sum(bin(x).count('1') for x in S)
            if n < res[r][0]: res[r] = (n, pos)
    return res

def get_cal(name):
    if name == 'k1': return list(range(1, 32))
    env = os.environ.get('MYSX_ROT_CAL')
    cal = [int(x) for x in env.split(',')] if env else V02_CAL
    assert sorted(cal) == list(range(1, 32)), 'calendario no es permutacion de 1..31'
    return cal

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--cal', choices=['k1', 'v02'], default='k1')
    ap.add_argument('--rmax', type=int, default=24)
    a = ap.parse_args()
    t = table(get_cal(a.cal), a.rmax)
    print(f"{'r':>3} {'minReach':>9} {'minBit':>7}")
    for r in range(1, a.rmax + 1): print(f"{r:>3} {t[r][0]:>9} {t[r][1]:>7}")
    reach = [t[r][0] for r in range(1, 16)]
    full = min(r for r in t if t[r][0] == 256)
    ok = True
    if a.cal == 'k1':
        if reach == PAPER_V1 and all(t[r][0] == 256 for r in range(15, a.rmax + 1)):
            print("OK: v0.1 structural min-reach matches the paper table (r=1..15)")
        else:
            print("FAIL: v0.1 min-reach differs from the paper:", reach); ok = False
    else:
        v1 = table(list(range(1, 32)), 15)
        diff = sum(1 for r in range(1, 16) if v1[r][0] != t[r][0])
        if reach == EXPECTED_V02:
            print("OK: v0.2 min-reach table matches the expected values (r=1..15)")
        else:
            print("FAIL: v0.2 min-reach differs from expected:", reach); ok = False
        if diff >= 8: print(f"OK: v0.2 differs from v0.1 at {diff} of 15 rounds (calendar is really applied)")
        else: print(f"FAIL: v0.2 identical to v0.1 at {15 - diff} of 15 rounds: calendar NOT applied?"); ok = False
    print(f"full reach (256) at r={full}")
    sys.exit(0 if ok else 1)

if __name__ == '__main__':
    main()
