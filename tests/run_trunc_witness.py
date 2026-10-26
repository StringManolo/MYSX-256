#!/usr/bin/env python3
"""run_trunc_witness.py — Verify the paper's 39-round truncated impossible witness.

Paper §4.12: Δs[44]=w2b29 --18r--> s[62] <--21r-- Δs[83]=w7b24,
conflict at bit w6b16.

This verifies the specific witness in O(1), instead of the global
search (which is O(N²) and takes hours).
"""
import sys, os, argparse
sys.path.insert(0, 'cryptanalysis/DMITM')
from dmitm_verify import Lin

V02_CAL = [22,5,8,7,17,10,30,1,11,26,6,3,12,23,25,13,28,20,21,19,24,2,18,9,4,15,29,27,16,14,31]
K1_CAL  = list(range(1, 32))

class LinCal(Lin):
    def __init__(self, cal):
        super().__init__()
        self.cal = cal
    def sh(self, r):
        return self.cal[r % 31]


def single_bit(word, bit):
    d = [0] * 8
    d[word] = 1 << bit
    return d


def int_to_words(n):
    return [(n >> (32*i)) & 0xFFFFFFFF for i in range(8)]


def words_to_int(ws):
    return sum(w << (32*i) for i, w in enumerate(ws))


def fwd_chain(lin, r_start, state, n):
    """Apply n forward rounds. state = list of 8 words (differences)."""
    val = state[:]
    unk = [0] * 8
    for k in range(n):
        r = r_start + k
        val, unk = lin.fwd_trunc(val, unk, r)
    return val, unk


def bwd_chain(lin, r_end, state, n):
    """Apply n backward rounds. state = list of 8 words (differences)."""
    val = state[:]
    unk = [0] * 8
    for k in range(n):
        r = r_end - k
        if r > 0:
            val, unk = lin.bwd_trunc(val, unk, r - 1)
        else:
            break
    return val, unk


def check_conflict(vf, uf, vb, ub):
    """Return the list of bit positions where fwd and bwd are incompatible."""
    M = (1 << 256) - 1
    known_f = ~uf & M
    known_b = ~ub & M
    c1 = vf & known_f & known_b & ~vb & M
    c2 = vb & known_b & known_f & ~vf & M
    return c1 | c2


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--cal', default='v02', choices=['k1', 'v02'])
    ap.add_argument('--R', type=int, default=39)
    ap.add_argument('--verbose', action='store_true')
    a = ap.parse_args()

    cal = K1_CAL if a.cal == 'k1' else V02_CAL
    lin = LinCal(cal)

    # Paper witness (from PAPER.md §4.12):
    #   s[44] --18r--> s[62] <--21r-- s[83]
    #   18 + 21 = 39 rounds total
    #   Δs[44] = w2b29, Δs[83] = w7b24
    r_start = 44
    r_mid   = 62
    r_end   = 83
    fwd_rounds = r_mid - r_start       # 18
    bwd_rounds = r_end - r_mid         # 21

    d_in  = single_bit(2, 29)          # w2b29
    d_out = single_bit(7, 24)          # w7b24

    print(f"Witness: R={a.R} rounds ({r_start}..{r_end})")
    print(f"  fwd: Δs[{r_start}]=w2b29 --{fwd_rounds}r--> s[{r_mid}]")
    print(f"  bwd: Δs[{r_end}]=w7b24 --{bwd_rounds}r--> s[{r_mid}]")

    vf, uf = fwd_chain(lin, r_start, d_in, fwd_rounds)
    vb, ub = bwd_chain(lin, r_end, d_out, bwd_rounds)

    vf_i = words_to_int(vf)
    uf_i = words_to_int(uf)
    vb_i = words_to_int(vb)
    ub_i = words_to_int(ub)

    print(f"\n  s[{r_mid}] forward:  val={vf_i:#066x}, unk={uf_i:#066x}")
    print(f"  s[{r_mid}] backward: val={vb_i:#066x}, unk={ub_i:#066x}")

    conflict = check_conflict(vf_i, uf_i, vb_i, ub_i)
    bits = [i for i in range(256) if (conflict >> i) & 1]

    if not bits:
        print(f"\nFAIL: no conflict between forward and backward chains")
        print(f"  The witness is NOT reproducible with this configuration.")
        sys.exit(1)

    print(f"\n  Conflict at {len(bits)} bit(s):")
    for b in bits[:10]:
        print(f"    w{b // 32}b{b % 32}")

    print(f"\nOK: witness confirmed — {len(bits)} conflicting bit(s) at s[{r_mid}]")
    print(f"  This is an impossible differential of {a.R} rounds ({r_start}..{r_end})")
    print(f"BEST: {a.R} rounds (R={r_mid}, w2b29 -> w7b24)")


if __name__ == '__main__':
    main()
