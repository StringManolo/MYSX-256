#!/usr/bin/env python3
import random, sys, os
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(
    os.path.join(_HERE, '..', 'cryptanalysis', 'models', 'linear')))
from mysx_linear_model import key_schedule, round_enc, rand_key

def verify_bit(R, w, b, toggle_bits, n=20000, seed=1, r0=0):
    rnd = random.Random(seed)
    rks, _ = key_schedule(rand_key(seed))
    bad = 0
    for _ in range(n):
        base = [rnd.getrandbits(32) for _ in range(8)]
        for (tw, tb) in toggle_bits:
            base[tw] &= ~(1 << tb)
        s0 = list(base); s1 = list(base)
        for (tw, tb) in toggle_bits:
            s1[tw] |= (1 << tb)
        for r in range(r0, r0 + R):
            s0 = round_enc(s0, rks[r], r)
            s1 = round_enc(s1, rks[r], r)
        if ((s0[w] >> b) & 1) ^ ((s1[w] >> b) & 1):
            bad += 1
    return bad, n

if __name__ == '__main__':
    R, r0 = 6, 15
    toggle = ((0, 0), (4, 0))
    print(f"R={R} r0={r0} toggle=word0[0],word4[0]  (4-text integral)")
    ok = True
    for (w, b) in [(5, 6), (7, 9)]:
        bad, n = verify_bit(R, w, b, toggle, n=20000, seed=1, r0=r0)
        status = "OK (balanced)" if bad == 0 else f"NOT balanced ({bad}/{n})"
        print(f"  word{w} bit{b}: {status}")
        if bad != 0: ok = False
    print("RESULT:", "ALL PASS" if ok else "SOME FAILED")
    sys.exit(0 if ok else 1)
