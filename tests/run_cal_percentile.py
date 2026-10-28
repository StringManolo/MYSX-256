#!/usr/bin/env python3
"""
tests/run_cal_percentile.py - Donde queda el calendario consecutivo (v0.1) y el v0.2 frente a
calendarios ALEATORIOS (sin filtrar). Respalda PAPER §1.2/§2.8/§4.13: "v0.1 esta en el peor ~2% por
DMITM exacto y ~0.2% por cadena de peso 0". Determinista (semilla fija). Usa algebra lineal exacta
(dmitm_verify.fwd_spaces / exact_ids), no heuristicas.
Uso: python3 tests/run_cal_percentile.py [--n 3000] [--seed 777]
"""
import argparse, os, random, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'cryptanalysis', 'DMITM'))
import dmitm_verify as dv

V02 = [22,5,8,7,17,10,30,1,11,26,6,3,12,23,25,13,28,20,21,19,24,2,18,9,4,15,29,27,16,14,31]

def stats(cal):
    dv.LIN.sh = lambda r, cal=cal: cal[r % 31]
    S = {r0: dv.fwd_spaces(dv.LIN, r0, kmax=30) for r0 in range(31)}
    m, ids = dv.exact_ids(dv.LIN, S)
    return max(m.values()), (ids[0][0] if ids else 0)

def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--n', type=int, default=3000); ap.add_argument('--seed', type=int, default=777)
    a = ap.parse_args()
    c1, d1 = stats(list(range(1, 32))); c2, d2 = stats(V02)
    rng = random.Random(a.seed); D = []; C = []
    for _ in range(a.n):
        cal = list(range(1, 32)); rng.shuffle(cal)
        c, d = stats(cal); C.append(c); D.append(d)
    D.sort(); C.sort(); n = a.n
    pct = lambda cond, xs: 100.0 * sum(1 for x in xs if cond(x)) / n
    print(f"random calendars: N={n} seed={a.seed}")
    print(f"exact DMITM min/median/max = {D[0]}/{D[n // 2]}/{D[-1]}")
    print(f"weight-0 chain min/median/max = {C[0]}/{C[n // 2]}/{C[-1]}")
    print(f"v0.1 consecutive: DMITM={d1} chain={c1}")
    print(f"fraction of random calendars with DMITM >= {d1}: {pct(lambda x: x >= d1, D):.1f}%")
    print(f"fraction of random calendars with chain >= {c1}: {pct(lambda x: x >= c1, C):.1f}%")
    print(f"v0.2: DMITM={d2} chain={c2}; fraction of random with DMITM <= {d2}: {pct(lambda x: x <= d2, D):.1f}%; "
          f"chain <= {c2}: {pct(lambda x: x <= c2, C):.1f}%")
    print("OK: percentile table computed")

if __name__ == '__main__':
    main()
