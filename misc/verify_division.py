#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_division.py -- Empirical verification of integral distinguishers
found by mysx_division_property.py.

For an integral distinguisher over R rounds with input division property
k_in (single active bit at (word 0, bit 0)), a bit (w, b) of the output
is *balanced* iff the XOR of that bit over all inputs is 0.  We
approximate the integral by fixing all input bits except bit 0 of word 0
to random values, varying that bit over {0, 1}, and checking whether the
output bit (w, b) flips.  A balanced bit gives 0 flips in every sample.

Usage:
    python3 verify_division.py --rounds 10 --balanced-bits "0:31,3:6"
    python3 verify_division.py --rounds 10 --word 0
    python3 verify_division.py --rounds 10 --word 3
    python3 verify_division.py --rounds 10 --bit 0 31
"""

import argparse
import os
import random
import sys

# Make mysx_linear_model importable from anywhere
_HERE = os.path.dirname(os.path.abspath(__file__))
_LINEAR_DIR = os.path.join(_HERE, '..', 'cryptanalysis', 'models', 'linear')
sys.path.insert(0, os.path.normpath(_LINEAR_DIR))

from mysx_linear_model import key_schedule, round_enc, rand_key


def verify_bit(R, w, b, n=20000, seed=1, r0=0):
    """Return (bad_count, n) for output bit (w, b) over R rounds.

    bad_count is the number of samples where the output bit flipped
    between the two inputs (base with bit 0 = 0 and base with bit 0 = 1).
    A balanced bit gives bad_count = 0.
    """
    rnd = random.Random(seed)
    rks, _ = key_schedule(rand_key(seed))
    bad = 0
    for _ in range(n):
        base = [rnd.getrandbits(32) for _ in range(8)]
        base[0] &= ~1
        s0 = list(base)
        s1 = list(base)
        s1[0] |= 1
        # Encrypt both states separately (CORRECTED: reassign s0, s1)
        for r in range(r0, r0 + R):
            s0 = round_enc(s0, rks[r], r)
            s1 = round_enc(s1, rks[r], r)
        if ((s0[w] >> b) & 1) ^ ((s1[w] >> b) & 1):
            bad += 1
    return bad, n


def fmt_status(bad, n):
    if bad == 0:
        return "OK  (balanced)"
    return f"not balanced ({bad}/{n})"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, required=True)
    ap.add_argument("--word", type=int, default=None)
    ap.add_argument("--bit", type=int, nargs=2, metavar=("W", "B"), default=None)
    ap.add_argument("--samples", type=int, default=20000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--r0", type=int, default=0)
    ap.add_argument("--balanced-bits", default=None,
                    help="Comma-separated 'w:b' pairs known to be balanced")
    args = ap.parse_args()

    if args.balanced_bits:
        pairs = []
        for tok in args.balanced_bits.split(","):
            w, b = tok.split(":")
            pairs.append((int(w), int(b)))
        print(f"Verifying {len(pairs)} bits known balanced at R={args.rounds}")
        print(f"Samples per bit: {args.samples}, seed: {args.seed}\n")
        ok = True
        for (w, b) in pairs:
            bad, n = verify_bit(args.rounds, w, b, args.samples,
                                args.seed, args.r0)
            status = fmt_status(bad, n)
            print(f"  word {w:2d} bit {b:2d}: {status}")
            if bad != 0:
                ok = False
        print("\nRESULT:", "ALL PASS" if ok else "SOME FAILED")
        return 0 if ok else 1

    if args.bit:
        w, b = args.bit
        bad, n = verify_bit(args.rounds, w, b, args.samples, args.seed, args.r0)
        print(f"R={args.rounds}, word {w} bit {b}: {fmt_status(bad, n)}")
        return 0 if bad == 0 else 1

    if args.word is not None:
        print(f"Checking all 32 bits of word {args.word} at R={args.rounds}")
        print(f"Samples per bit: {args.samples}, seed: {args.seed}\n")
        n_bal = 0
        for b in range(32):
            bad, n = verify_bit(args.rounds, args.word, b, args.samples,
                                args.seed, args.r0)
            print(f"  bit {b:2d}: {fmt_status(bad, n)}")
            if bad == 0:
                n_bal += 1
        print(f"\n{n_bal}/32 bits balanced in word {args.word}")
        return 0

    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
