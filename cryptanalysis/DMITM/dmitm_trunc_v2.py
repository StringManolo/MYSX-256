#!/usr/bin/env python3
"""
dmitm_trunc_v2.py — Truncated impossible differential search (v0.2 fixes).

Fixes vs dmitm_trunc.py:
  - --n_bits default 256 (was 128)
  - heap top-K conflicts (was: all conflicts, then sort)
  - cap forward/backward states per round to top-K
  - clean output: length + offsets + bit indices
"""
import sys, os, json, argparse, time, heapq
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dmitm_verify import Lin, MYZ_PERM, rotl, rotr, simonF, key_schedule, round_enc, rand_key

MASK256 = (1 << 256) - 1


class LinCal(Lin):
    def __init__(self, cal):
        super().__init__()
        self.cal = list(cal)
    def sh(self, r):
        return self.cal[r % 31]


def to_int(val):
    return sum(v << (32 * i) for i, v in enumerate(val))


def conflict(vf, uf, vb, ub):
    known_f = ~uf & MASK256
    known_b = ~ub & MASK256
    c1 = vf & known_f & known_b & ~vb & MASK256
    c2 = vb & known_b & known_f & ~vf & MASK256
    return (c1 | c2) != 0


def desc_bit(b):
    return f"w{b // 32}b{b % 32}"


def desc_conflict(vf, uf, vb, ub):
    known_f = ~uf & MASK256
    known_b = ~ub & MASK256
    c1 = vf & known_f & known_b & ~vb & MASK256
    c2 = vb & known_b & known_f & ~vf & MASK256
    bits = []
    for i in range(256):
        if (c1 >> i) & 1 or (c2 >> i) & 1:
            bits.append(f"w{i // 32}b{i % 32}")
    return ",".join(bits[:3]) + ("..." if len(bits) > 3 else "")


def search(lin, max_fwd, max_bwd, n_bits, top_k_per_round, top_k_results):
    from collections import defaultdict
    t0 = time.time()

    F = defaultdict(list)
    B = defaultdict(list)

    # Forward
    for r_start in range(128):
        for b_in in range(n_bits):
            delta = [0] * 8
            delta[b_in // 32] = 1 << (b_in % 32)
            val, unk = list(delta), [0] * 8
            for k in range(max_fwd):
                r = r_start + k
                if r >= 128: break
                if k > 0:
                    F[r].append((r_start, b_in, to_int(val), to_int(unk)))
                val, unk = lin.fwd_trunc(val, unk, r)
        if (r_start + 1) % 32 == 0:
            print(f"  fwd {r_start+1}/128  {time.time()-t0:.0f}s", file=sys.stderr)

    # Backward
    for r_end in range(128):
        for b_out in range(n_bits):
            delta = [0] * 8
            delta[b_out // 32] = 1 << (b_out % 32)
            val, unk = list(delta), [0] * 8
            for k in range(max_bwd):
                r = r_end - k
                if r < 0: break
                if k > 0:
                    B[r].append((r_end, b_out, to_int(val), to_int(unk)))
                if r > 0:
                    val, unk = lin.bwd_trunc(val, unk, r - 1)
                else:
                    break
        if (r_end + 1) % 32 == 0:
            print(f"  bwd {r_end+1}/128  {time.time()-t0:.0f}s", file=sys.stderr)

    # Cap per round: keep the most INFORMATIVE chains (fewest unknown bits),
    # tie-break by earliest start (forward) or latest end (backward).
    # The previous heuristic (sort by r_start only) discarded the useful
    # chains because there are thousands of chains from r_start=32,33,...
    for r in F:
        F[r].sort(key=lambda x: (bin(x[3]).count('1'), x[0]))
        F[r] = F[r][:top_k_per_round]
    for r in B:
        B[r].sort(key=lambda x: (bin(x[3]).count('1'), -x[0]))
        B[r] = B[r][:top_k_per_round]

    nF = sum(len(v) for v in F.values())
    nB = sum(len(v) for v in B.values())
    print(f"  propagation done, {time.time()-t0:.0f}s (F={nF}, B={nB})", file=sys.stderr)

    # Conflict detection
    heap = []
    tie = 0
    for r in F:
        for (rs, bi, vf, uf) in F[r]:
            for (re, bo, vb, ub) in B[r]:
                if conflict(vf, uf, vb, ub):
                    length = re - rs
                    entry = (length, r, rs, bi, re, bo, vf, uf, vb, ub)
                    tie += 1
                    if len(heap) < top_k_results:
                        heapq.heappush(heap, (length, tie, entry))
                    elif length > heap[0][0]:
                        heapq.heapreplace(heap, (length, tie, entry))

    print(f"  conflict detection done, {time.time()-t0:.0f}s", file=sys.stderr)
    results = sorted([e for (_, _, e) in heap], key=lambda x: -x[0])
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cal", default="v02", choices=["k1", "v02"])
    ap.add_argument("--cal_file", default=None)
    ap.add_argument("--cal_idx", type=int, default=0)
    ap.add_argument("--max_fwd", type=int, default=20)
    ap.add_argument("--max_bwd", type=int, default=20)
    ap.add_argument("--n_bits", type=int, default=256)
    ap.add_argument("--top_k_per_round", type=int, default=100)
    ap.add_argument("--top_k_results", type=int, default=200)
    ap.add_argument("--top", type=int, default=5)
    a = ap.parse_args()

    if a.cal_file:
        cands = json.load(open(a.cal_file))
        c = cands[a.cal_idx]
        cal = [c["cal"][r % 31] for r in range(31)]
        name = c.get("name", f"idx{a.cal_idx}")
    elif a.cal == "k1":
        cal = list(range(1, 32))
        name = "k1 (consecutive)"
    else:
        cal = [22,5,8,7,17,10,30,1,11,26,6,3,12,23,25,13,28,20,21,19,24,2,18,9,4,15,29,27,16,14,31]
        name = "v02 (rand_s9_45430)"

    print(f"cal={name}  max_fwd={a.max_fwd} max_bwd={a.max_bwd} n_bits={a.n_bits}")
    lin = LinCal(cal)
    results = search(lin, a.max_fwd, a.max_bwd, a.n_bits,
                     a.top_k_per_round, a.top_k_results)

    print(f"\nTop {a.top} of {len(results)} candidates:")
    print(f"{'len':>4}  {'R':>3}  {'rs':>3}  {'bi':>8}  {'re':>3}  {'bo':>8}  conflict")
    for w in results[:a.top]:
        length, r_mid, rs, bi, re, bo, vf, uf, vb, ub = w
        print(f"{length:>4}  {r_mid:>3}  {rs:>3}  {desc_bit(bi):>8}  "
              f"{re:>3}  {desc_bit(bo):>8}  {desc_conflict(vf, uf, vb, ub)}")

    if results:
        w = results[0]
        print(f"\nBEST: {w[0]} rounds (R={w[1]}, {desc_bit(w[3])} -> {desc_bit(w[5])})")
    else:
        print("\nNo truncated impossible found in this search space.")


if __name__ == "__main__":
    main()
