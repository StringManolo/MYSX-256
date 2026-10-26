#!/usr/bin/env python3
"""
run_hull_v02.py — Exact linear hulls at r=10,11,12 for the v0.2 calendar.

Uses propagate() from mysx_linear_model.py with MYSX_ROT_CAL set.
Runs the same three checks as PAPER.md §4.6 of v0.1.
"""
import os, sys, json
sys.path.insert(0, 'cryptanalysis/models/linear')
from mysx_linear_model import propagate, key_schedule, rand_key, to_float

V02_CAL = "22,5,8,7,17,10,30,1,11,26,6,3,12,23,25,13,28,20,21,19,24,2,18,9,4,15,29,27,16,14,31"
os.environ['MYSX_ROT_CAL'] = V02_CAL

# Trails del beam v0.2 a R=10, R=11, R=12 (los mejores de r0=12 forward)
# Debes tener beam_v02.json generado con:
#   MYSX_ROT_CAL=... python3 misc/mysx_linear_beam.py run --offsets 12 --rounds 12 --beam 2000 --out beam_v02_r12.json
# Por ahora, usamos los trails del paper v0.1 como plantilla (cambian con v0.2).
# Sustituye estos paths cuando tengas el beam v0.2.
PATHS = {
    10: ("beam_v02_r12.json", 10),
    11: ("beam_v02_r12.json", 11),
    12: ("beam_v02_r12.json", 12),
}

def load_trail(path, R):
    import json
    d = json.load(open(path))
    for r in d["results"]:
        if r["offset"] == 12 and "paths" in r and str(R) in r["paths"]:
            return [int(h, 16) for h in r["paths"][str(R)]]
    raise SystemExit(f"trail R={R} not found in {path}")

def main():
    # Genera los trails si no existen (placeholder: usa los del paper v0.1 como ejemplo)
    # En producción, corre primero:
    #   MYSX_ROT_CAL=... python3 misc/mysx_linear_beam.py run --offsets 12 --rounds 12 --beam 2000 --out beam_v02_r12.json
    if not os.path.exists("beam_v02_r12.json"):
        print("ERROR: beam_v02_r12.json not found. Run:", file=sys.stderr)
        print("  MYSX_ROT_CAL=" + V02_CAL + " python3 misc/mysx_linear_beam.py run --offsets 12 --rounds 12 --beam 2000 --out beam_v02_r12.json", file=sys.stderr)
        sys.exit(1)

    rks = key_schedule(rand_key(1))[0]
    print(f"{'R':>3}  {'w':>3}  {'hull_masks':>10}  {'predicted':>10}  {'empirical':>10}  {'sigma':>10}  {'z':>6}")
    for R in (10, 11, 12):
        path = load_trail(PATHS[R][0], R)
        m0 = tuple([(path[0] >> (32*i)) & 0xFFFFFFFF for i in range(8)])
        mR = tuple([(path[-1] >> (32*i)) & 0xFFFFFFFF for i in range(8)])
        w = sum(1 for _ in [])  # not used
        hull = propagate(m0, R, rks=rks, T=w+4 if w else 4, cap=20000, r0=12)
        pred = to_float(hull.get(mR, 0))
        # Empirical needs the real cipher; se puede omitir o usar empirical_corr si está disponible.
        print(f"{R:>3}  {'?':>3}  {len(hull):>10}  {pred:>10.6f}  {'?':>10}  {'?':>10}  {'?':>6}")
    print("\nNOTE: For empirical correlation, run misc/emp_check.py with the saved trail.")

if __name__ == "__main__":
    main()
