#!/usr/bin/env python3
"""
search_mysx_deep.py — Búsqueda profunda de calendarios de rotación para MYSX.

Autocontenido: no importa search_mysx_cal.py. Incluye generadores de calendario,
la clase Lin (capa lineal con calendario explícito) y el pipeline de 3 fases:
  Fase 1: chain10 (offset 10, barato)
  Fase 2: chain31 (31 offsets, medio)
  Fase 3: dmitm exacto (multi-bit, caro)

Uso:
  python3 search_mysx_deep.py --n 100000 --seed 42
  python3 search_mysx_deep.py --n 1000000 --seed 7 --out deep_1m.json
"""
import sys, os, json, random, math, time, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ============================================================
# Constantes del cifrado
# ============================================================
MYZ_PERM = [4,12,20,28, 0,8,16,24, 5,13,21,29,
            2,7,10,15,18,23,26,31, 6,14,22,30,
            1,9,17,25, 3,11,19,27]
PERIOD = 31
N_ROUNDS = 128

# ============================================================
# Capa lineal con calendario explícito
# ============================================================
def rotl(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def rotr(x, n):
    return rotl(x, (32 - n) % 32)

def w2b(ws):
    b = []
    for w in ws:
        b += [(w>>24)&255, (w>>16)&255, (w>>8)&255, w&255]
    return b

def b2w(bs):
    return [(bs[4*i]<<24)|(bs[4*i+1]<<16)|(bs[4*i+2]<<8)|bs[4*i+3] for i in range(8)]

def i2w(s):
    return [(s >> (32*i)) & 0xFFFFFFFF for i in range(8)]

def w2i(ws):
    return sum(w << (32*i) for i, w in enumerate(ws))

def sbit(w, b):
    m = [0]*8; m[w] = 1 << b; return tuple(m)

class LinCal:
    def __init__(self, perm=MYZ_PERM, cal=None):
        self.perm = list(perm)
        self.cal = cal
    def sh(self, r):
        return self.cal[r]
    def transp(self, ws):
        b = w2b(ws)
        return b2w([b[self.perm[j]] for j in range(32)])
    def untransp(self, ws):
        b = w2b(ws)
        out = [0]*32
        for j in range(32):
            out[self.perm[j]] = b[j]
        return b2w(out)
    def fwd(self, s_mid, r):
        return [rotl(x, self.sh(r)) for x in self.transp(s_mid)]
    def bwd(self, s, r):
        return self.untransp([rotr(x, self.sh(r)) for x in s])
    def fstep(self, st, r):
        if any(st[4:8]): return None
        return tuple(self.fwd([0,0,0,0,st[0],st[1],st[2],st[3]], r))
    def bstep(self, st, r):
        n = self.bwd(st, r)
        if any(n[0:4]): return None
        return (n[4], n[5], n[6], n[7], 0, 0, 0, 0)

# ============================================================
# Métricas de seguridad (menor = más seguro)
# ============================================================
def fwd_spaces(lin, r0, kmax=30):
    vecs = [(1 << i, 1 << i) for i in range(128)]
    res = {}
    for k in range(1, kmax + 1):
        nv = []
        for st, inp in vecs:
            w = i2w(st)
            nv.append((w2i(lin.fwd([0,0,0,0,w[0],w[1],w[2],w[3]], r0 + k - 1)), inp))
        res[k] = nv
        piv = {}; ker = []
        for st, inp in nv:
            hi = st >> 128
            while hi:
                p = hi.bit_length() - 1
                if p in piv:
                    ph, ps, pi = piv[p]; hi ^= ph; st ^= ps; inp ^= pi
                else:
                    piv[p] = (hi, st, inp); break
            if hi == 0: ker.append((st, inp))
        vecs = ker
        if not vecs: break
    return res

def exact_ids(lin, S):
    P = PERIOD  # 31: el calendario tiene 128 entradas, pero el período es 31
    m = {r0: max(S[r0]) for r0 in S}
    out = []
    for R in range(P):
        for b in range(1, m[R] + 1):
            for a in range(1, 14 + 30):
                r0 = (R - a) % P
                if a > m[r0]: continue
                dV, dX = len(S[r0][a]), len(S[R][b])
                if dV == 1 and dX == 1 and S[r0][a][0][0] == S[R][b][0][1]:
                    continue
                out.append((a + b, R, a, b, dV, dX))
    out.sort(key=lambda x: (-x[0], x[1]))
    return m, out

def score_cheap(lin):
    S = fwd_spaces(lin, 10)
    return max(S) if S else 0

def score_medium(lin):
    S = {r0: fwd_spaces(lin, r0) for r0 in range(PERIOD)}
    vals = [max(S[r0]) for r0 in S if S[r0]]
    return max(vals) if vals else 0

def score_exact(lin):
    S = {r0: fwd_spaces(lin, r0) for r0 in range(PERIOD)}
    try:
        _, ids = exact_ids(lin, S)
        return ids[0][0] if ids else 0
    except Exception:
        return 0

# ============================================================
# Generadores de calendario
# ============================================================
def _from_perm31(seq31):
    assert len(seq31) == PERIOD
    assert sorted(seq31) == list(range(PERIOD))
    return [(seq31[r % PERIOD] + 1) for r in range(N_ROUNDS)]

def cal_affine_k(k):
    return _from_perm31([(k * r) % PERIOD for r in range(PERIOD)])

def cal_random(rng):
    seq = list(range(PERIOD))
    rng.shuffle(seq)
    return _from_perm31(seq)

# ============================================================
# Pipeline de búsqueda profunda
# ============================================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--n', type=int, default=100_000)
    ap.add_argument('--seed', type=int, default=42)
    ap.add_argument('--max_chain10', type=int, default=3)
    ap.add_argument('--max_chain31', type=int, default=5)
    ap.add_argument('--out', default=None)
    a = ap.parse_args()
    out = a.out or f"deep_n{a.n}_seed{a.seed}.json"

    # FASE 1: chain10
    print(f"FASE 1: chain10 sobre {a.n + 30} candidatos (max_chain10={a.max_chain10})")
    t0 = time.time()
    rng = random.Random(a.seed)
    cals = [(f"affine_k{k}", cal_affine_k(k)) for k in range(1, 31)]
    for i in range(a.n):
        cals.append((f"rand_s{a.seed}_{i}", cal_random(rng)))

    hits = []
    for i, (name, cal) in enumerate(cals):
        lin = LinCal(cal=cal)
        try:
            s = score_cheap(lin)
        except Exception:
            continue
        if s <= a.max_chain10:
            hits.append({'name': name, 'cal': cal, 'chain10': s})
        if (i + 1) % 10000 == 0:
            print(f"  {i+1}/{len(cals)}  hits={len(hits)}  {time.time()-t0:.0f}s")
    print(f"  FASE 1: {len(hits)} candidatos con chain10<={a.max_chain10} ({time.time()-t0:.0f}s)\n")

    # FASE 2: chain31
    print(f"FASE 2: chain31 sobre {len(hits)} candidatos (max_chain31={a.max_chain31})")
    t0 = time.time()
    hits2 = []
    for i, c in enumerate(hits):
        lin = LinCal(cal=c['cal'])
        try:
            s = score_medium(lin)
        except Exception:
            continue
        if s <= a.max_chain31:
            c['chain31'] = s
            hits2.append(c)
        if (i + 1) % 100 == 0:
            print(f"  {i+1}/{len(hits)}  {time.time()-t0:.0f}s")
    print(f"  FASE 2: {len(hits2)} candidatos con chain31<={a.max_chain31} ({time.time()-t0:.0f}s)\n")

    # FASE 3: dmitm exacto
    print(f"FASE 3: dmitm exacto sobre {len(hits2)} candidatos")
    t0 = time.time()
    for i, c in enumerate(hits2):
        lin = LinCal(cal=c['cal'])
        try:
            c['dmitm'] = score_exact(lin)
        except Exception:
            c['dmitm'] = 99
        print(f"  [{i+1}/{len(hits2)}] {c['name']:<28} chain10={c['chain10']} chain31={c['chain31']} dmitm={c['dmitm']}  {time.time()-t0:.0f}s")

    hits2.sort(key=lambda x: (x['dmitm'], x['chain31'], x['chain10']))
    with open(out, 'w') as f:
        json.dump(hits2, f, indent=0)

    print(f"\n{'chain10':>7}  {'chain31':>8}  {'dmitm':>5}  calendar")
    print('-' * 60)
    for c in hits2[:40]:
        print(f"{c['chain10']:>7}  {c['chain31']:>8}  {c['dmitm']:>5}  {c['name']}")
    print(f"\n→ {out}  ({len(hits2)} candidatos)")

if __name__ == '__main__':
    main()
