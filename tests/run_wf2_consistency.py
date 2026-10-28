#!/usr/bin/env python3
"""
tests/run_wf2_consistency.py - La tabla 8x9 del paper (§4.13) coincide con cryptanalysis/DMITM/wf2_deep_summary.json.

Direccion de las metricas (importante, el resumen original las tenia al reves):
  dp5, dp6, DMITM, chain, truncado : MENOR es mejor (menos bits balanceados / cadena mas corta)
  lin_fwd/bwd (peso de traza unica) : MAYOR es mejor (|corr| = 2^-peso: mas peso = mas dificil)
  MILP                              : MAYOR es mejor
"""
import json, os, sys
PATH = os.environ.get('WF2_JSON', 'cryptanalysis/DMITM/wf2_deep_summary.json')
EXPECT = {
    'affine_k1':      dict(dp5=21, dp6=4, lin_fwd10=1, lin_bwd10=1, lin_fwd14=5, lin_bwd14=5, dmitm_exact=17, chain_max=13),
    'rand_s9_45430':  dict(dp5=9,  dp6=4, lin_fwd10=1, lin_bwd10=3, lin_fwd14=8, lin_bwd14=11, dmitm_exact=9,  chain_max=5),
    'rand_s9_33719':  dict(dp6=12, lin_fwd14=13),     # falso positivo del cribado a R<=4
}
rows = {r['name']: r for r in json.load(open(PATH))}
bad = []
for name, exp in EXPECT.items():
    if name not in rows: bad.append(f"falta el candidato {name} (hay: {sorted(rows)})"); continue
    for k, v in exp.items():
        got = rows[name].get(k)
        if got != v: bad.append(f"{name}.{k}: json={got} esperado={v}")
if bad:
    print("FAIL:"); [print("  -", b) for b in bad]; sys.exit(1)
b, n = rows['affine_k1'], rows['rand_s9_45430']
better = [k for k in ('dp5', 'dmitm_exact', 'chain_max') if n[k] < b[k]] + [k for k in ('lin_bwd10', 'lin_fwd14', 'lin_bwd14') if n[k] > b[k]]
tie = [k for k in ('dp6', 'lin_fwd10') if n[k] == b[k]]
worse = [k for k in ('dp5', 'dp6', 'dmitm_exact', 'chain_max') if n[k] > b[k]] + [k for k in ('lin_fwd10', 'lin_bwd10', 'lin_fwd14', 'lin_bwd14') if n[k] < b[k]]
print(f"OK: wf2 table matches the paper; v0.2 vs v0.1: {len(better)} better {better}, {len(tie)} tie {tie}, {len(worse)} worse {worse}")
