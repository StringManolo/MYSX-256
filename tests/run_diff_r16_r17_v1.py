#!/usr/bin/env python3
"""run_diff_r16_r17_v1.py — R=16, R=17 empirical differential verification (v0.1).

Paper claim (§3.5): observed 1.63e-2 vs prediction 1.56e-2 at R=16,
1.1e-3 vs 9.8e-4 at R=17, within sampling error.

Regenerates the trails with mysx_linear_beam.py (deterministic) and verifies
each empirically with 8 fixed keys x 2^17 pairs.
"""
import subprocess, json, sys, os, random

BEAM_OUT = '/tmp/beam_v1_r0_10_16_17.json'

def hex_to_words(h):
    n = int(h, 16)
    return [(n >> (32*i)) & 0xFFFFFFFF for i in range(8)]

# 1. Generate trails (deterministic)
print("=== Generating R=16, R=17 trails at r0=10 ===", file=sys.stderr)
r = subprocess.run(
    ['python3', 'misc/mysx_linear_beam.py', 'run',
     '--offsets', '10', '--rounds', '17', '--beam', '2000',
     '--jobs', '1', '--paths', '16,17', '--out', BEAM_OUT],
    capture_output=True, text=True
)
if r.returncode != 0:
    print(f"ERROR: beam failed:\n{r.stderr[-1000:]}", file=sys.stderr)
    sys.exit(1)

# 2. Parse
data = json.load(open(BEAM_OUT))
res = next((x for x in data['results'] if x['offset'] == 10), None)
if res is None or 'paths' not in res:
    print("ERROR: no trails in beam output", file=sys.stderr)
    sys.exit(1)

trails = {}
for R in (16, 17):
    if str(R) not in res['paths']:
        print(f"ERROR: R={R} missing from beam", file=sys.stderr)
        sys.exit(1)
    path = res['paths'][str(R)]
    w = res['ub'][R-1] if len(res['ub']) >= R else None
    trails[R] = {'d_in': hex_to_words(path[0]),
                 'd_out': hex_to_words(path[-1]), 'w': w}
    print(f"R={R}: w={w}")

# 3. Empirical verification
sys.path.insert(0, 'cryptanalysis/DMITM')
from dmitm_verify import key_schedule, round_enc, rand_key

def verify_trail(R, d_in, d_out, n_keys=8, n_pairs=1<<17, seed=1):
    rnd = random.Random(seed)
    hits = total = 0
    for k in range(n_keys):
        rks, _ = key_schedule(rand_key(seed + k))
        for _ in range(n_pairs):
            P  = [rnd.getrandbits(32) for _ in range(8)]
            P2 = [P[i] ^ d_in[i] for i in range(8)]
            s1, s2 = list(P), list(P2)
            for r in range(10, 10 + R):
                s1 = round_enc(s1, rks[r], r)
                s2 = round_enc(s2, rks[r], r)
            if [s1[i] ^ s2[i] for i in range(8)] == d_out:
                hits += 1
            total += 1
    return hits, total

print("\n=== Empirical verification ===")
all_ok = True
for R in (16, 17):
    t = trails[R]
    hits, total = verify_trail(R, t['d_in'], t['d_out'])
    obs = hits / total
    exp = 2.0 ** (-t['w'])
    sigma = (exp * (1 - exp) / total) ** 0.5 if exp < 1 else 0
    z = (obs - exp) / sigma if sigma > 0 else 0
    print(f"R={R}: w={t['w']}, expected={exp:.4e}, observed={obs:.4e}, "
          f"hits={hits}/{total}, sigma={sigma:.2e}, z={z:+.2f}")
    if abs(z) > 4:
        print(f"  FAIL: |z| = {abs(z):.2f} > 4", file=sys.stderr)
        all_ok = False
    if not (0.5 * exp <= obs <= 2 * exp):
        print(f"  FAIL: observed outside [0.5*expected, 2*expected]", file=sys.stderr)
        all_ok = False

if not all_ok:
    sys.exit(1)
print("\nOK: R=16 and R=17 empirical within 4σ of 2^-w")
