#!/usr/bin/env python3
"""run_hull_v02.py — Exact hulls at r=10,11,12 for v0.2."""
import sys, os, json, subprocess
V02_CAL = "22,5,8,7,17,10,30,1,11,26,6,3,12,23,25,13,28,20,21,19,24,2,18,9,4,15,29,27,16,14,31"
os.environ['MYSX_ROT_CAL'] = V02_CAL
sys.path.insert(0, 'cryptanalysis/models/linear')

BEAM = "beam_v02_r12.json"
if not os.path.exists(BEAM):
    print(f"{BEAM} not found; generating (~2 min)...", file=sys.stderr)
    env = os.environ.copy()
    env['MYSX_ROT_CAL'] = V02_CAL
    r = subprocess.run(
        ['python3', 'misc/mysx_linear_beam.py', 'run',
         '--offsets', '12', '--rounds', '12', '--beam', '2000',
         '--jobs', '2', '--paths', '10,11,12', '--out', BEAM],
        capture_output=True, text=True, env=env, timeout=900
    )
    if r.returncode != 0 or not os.path.exists(BEAM):
        print(f"ERROR: beam generation failed: {r.stderr[-500:]}", file=sys.stderr)
        sys.exit(1)

from mysx_linear_model import propagate, key_schedule, rand_key, to_float

d = json.load(open(BEAM))
res = next((x for x in d['results'] if x['offset'] == 12), None)
if res is None or 'paths' not in res:
    print(f"ERROR: no trails at offset 12 in {BEAM}", file=sys.stderr)
    sys.exit(1)

rks = key_schedule(rand_key(1))[0]
print(f"\n{'R':>3}  {'hull':>5}  {'predicted':>10}")
print("-" * 30)
found = 0
for R in (10, 11, 12):
    if str(R) not in res['paths']:
        continue
    path = [int(h, 16) for h in res['paths'][str(R)]]
    m0 = tuple([(path[0] >> (32*i)) & 0xFFFFFFFF for i in range(8)])
    mR = tuple([(path[-1] >> (32*i)) & 0xFFFFFFFF for i in range(8)])
    hull = propagate(m0, R, rks=rks, T=8, cap=20000, r0=12)
    pred = to_float(hull.get(mR, 0))
    print(f"{R:>3}  {len(hull):>5}  {pred:>+10.6f}")
    found += 1

if found == 0:
    print("FAIL: no trails for r=10,11,12", file=sys.stderr)
    sys.exit(1)
print(f"\nOK: {found} hulls computed for v0.2")
