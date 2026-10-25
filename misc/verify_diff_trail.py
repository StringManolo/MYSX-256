#!/usr/bin/env python3
"""Verify a deterministic differential trail against the real cipher."""
import sys, os, random
sys.path.insert(0, os.path.normpath('cryptanalysis/models/linear'))
from mysx_linear_model import key_schedule, round_enc, rand_key

def verify(delta_in, delta_out, R, r0, n_keys=8, n_pairs=1<<15, seed=1):
    rnd = random.Random(seed)
    total_m = total_t = 0
    for k in range(n_keys):
        rks, _ = key_schedule(rand_key(seed + k))
        m = 0
        for _ in range(n_pairs):
            P  = [rnd.getrandbits(32) for _ in range(8)]
            P2 = [P[i] ^ delta_in[i] for i in range(8)]
            s1, s2 = list(P), list(P2)
            for r in range(r0, r0 + R):
                s1 = round_enc(s1, rks[r], r)
                s2 = round_enc(s2, rks[r], r)
            if tuple(s1[i] ^ s2[i] for i in range(8)) == tuple(delta_out):
                m += 1
        print(f"  key {k+1}: {m}/{n_pairs} ({100*m/n_pairs:.4f}%)")
        total_m += m; total_t += n_pairs
    print(f"  TOTAL: {total_m}/{total_t} ({100*total_m/total_t:.4f}%)")
    return total_m == total_t

if __name__ == '__main__':
    # Trail: R=6, r0=15, input w2b30, output w4b5
    din  = (0, 0, 1<<30, 0, 0, 0, 0, 0)
    dout = (0, 0, 0, 0, 1<<5, 0, 0, 0)
    print("R=6, r0=15, din=w2b30, dout=w4b5 (deterministic expected)")
    ok = verify(din, dout, R=6, r0=15, n_keys=8, n_pairs=1<<15)
    sys.exit(0 if ok else 1)
