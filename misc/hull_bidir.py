#!/usr/bin/env python3
"""
hull_bidir.py -- budgeted, EXACT linear-hull enumeration between the two end masks
of a saved beam trail (PAPER.md 4.10.3), meet-in-the-middle.

hull_count.py only expands forward from the start mask, so its layers explode as
soon as the trail has heavy rounds at the beginning (backward trails) or in the
middle. This tool grows a forward frontier from the start mask u and a backward
frontier from the end mask v, always extending the smaller one, and joins them in
the middle. Every trail u -> v of total weight <= WMAX has prefix weight <= WMAX and
suffix weight <= WMAX, so it is found: the result is the COMPLETE set of such
trails (unless --max-states aborts the run). Exclusions inherited from the beam
tool: a cell with b = 0xFFFFFFFF is skipped (h = 15, so it only matters when
WMAX >= 15).

Per weight w it reports N_w (number of trails), and the rigorous key-independent
test  N_min = 1  and  sum_{w > w_min} N_w 2^-w < 2^-w_min  (=> no cancellation,
|corr| in [2^-w_min - S, 2^-w_min + S] for every key).  With --keys K it also
computes the exact signed hull (sum of sign * 2^-w) for K random keys, using the
same signs as mysx_linear_model.py (cell sign from corr_Z, key sign (-1)^{m.rk}).

usage:
  python3 hull_bidir.py beam.json OFFSET --R 16 --wmax 12 [--keys 3] [--max-states 3000000]
The JSON must contain the path for that R (re-run mysx_linear_beam.py run --paths ...).
"""
import json, sys, argparse, os, time, itertools, random
from collections import defaultdict
from fractions import Fraction
from functools import lru_cache

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "cryptanalysis", "models", "linear"))   # mysx_linear_model.py
from mysx_linear_beam import M32, lin, lin_inv, cell_info, popcount
import mysx_linear_model as ML

PERIOD = 31


def _spans(infos, w_other, bases_xor):
    """per cell: list of low-word choices t ^ span(basis)"""
    out = []
    for p, (h, basis, base) in enumerate(infos):
        t = w_other[p] ^ base
        span = [t]
        for bv in basis:
            span += [s ^ bv for s in span]
        out.append(span)
    return out


@lru_cache(maxsize=None)
def cell_sign(b, g):
    if b == 0:
        return 1
    return 1 if ML.corr_Z(b, g) > 0 else -1


def fwd_edges(x, sh, cap, signed):
    """x = mask on s[r].  yield (child on s[r+1], cost, cell_sign_product)."""
    w = [(x >> (32 * i)) & M32 for i in range(8)]
    infos, tot = [], 0
    for p in range(4):
        o = cell_info(w[p], cap)
        if o is None:
            return
        tot += o[0]
        if tot > cap:
            return
        infos.append(o)
    hi = 0
    for p in range(4):
        hi |= w[p] << (32 * (p + 4))
    spans = _spans(infos, [w[p + 4] for p in range(4)], None)
    for vs in itertools.product(*spans):
        c = hi | vs[0] | (vs[1] << 32) | (vs[2] << 64) | (vs[3] << 96)
        s = 1
        if signed:
            for p in range(4):
                s *= cell_sign(w[p], vs[p] ^ w[p + 4])      # g_p = n[p] ^ m[p+4]
        yield lin(c, sh), tot, s


def bwd_edges(x, sh, cap, signed):
    """x = mask on s[r+1].  yield (parent on s[r], cost, cell_sign_product)."""
    n = lin_inv(x, sh)
    w = [(n >> (32 * i)) & M32 for i in range(8)]
    infos, tot = [], 0
    for p in range(4):
        o = cell_info(w[p + 4], cap)
        if o is None:
            return
        tot += o[0]
        if tot > cap:
            return
        infos.append(o)
    lo = 0
    for p in range(4):
        lo |= w[p + 4] << (32 * p)                           # m[p] = n[p+4]
    spans = _spans(infos, [w[p] for p in range(4)], None)    # m[p+4] = n[p] ^ g_p
    for vs in itertools.product(*spans):
        m = lo | (vs[0] << 128) | (vs[1] << 160) | (vs[2] << 192) | (vs[3] << 224)
        s = 1
        if signed:
            for p in range(4):
                s *= cell_sign(w[p + 4], vs[p] ^ w[p])      # g_p = m[p+4] ^ n[p]
        yield m, tot, s


def rk_int(rk):
    return sum(v << (32 * i) for i, v in enumerate(rk))


def fmin(layer):
    return min(min(d) for d in layer.values())


def step(layer, direction, r_abs, wmax, RK, signed, max_states, other_min=0):
    """one round of frontier growth. layer: {mask: {weight: value}}"""
    sh = (r_abs % PERIOD) + 1
    out = {}
    edges = fwd_edges if direction == "f" else bwd_edges
    for x, dw in layer.items():
        cap = wmax - min(dw) - other_min
        ks = 1
        if signed and direction == "f":
            ks = -1 if (x & RK).bit_count() & 1 else 1
        for y, cost, cs in edges(x, sh, cap, signed):
            s = cs * ks
            if signed and direction == "b":
                s *= -1 if (y & RK).bit_count() & 1 else 1    # key sign of the source mask y
            d = out.get(y)
            if d is None:
                d = out[y] = {}
            for w, val in dw.items():
                nw = w + cost
                if nw + other_min <= wmax:
                    d[nw] = d.get(nw, 0) + (val * s if signed else val)
        if len(out) > max_states:
            return None
    return {k: {w: v for w, v in d.items()} for k, d in out.items() if d}


def stream_join(F, B, jf, first, wmax, RK_list, signed, tot, forward_side):
    """Last round: do NOT materialise the meeting layer. Expand the frontier `src`
    one round and look every child up in the other frontier (memory = F + B)."""
    if forward_side:
        omin = fmin(B)
        r_abs = first + jf
        RK = RK_list[r_abs] if signed else 0
        sh = (r_abs % PERIOD) + 1
        for x, dw in F.items():
            ks = -1 if (signed and (x & RK).bit_count() & 1) else 1
            for y, cost, cs in fwd_edges(x, sh, wmax - min(dw) - omin, signed):
                d2 = B.get(y)
                if d2 is None:
                    continue
                s = cs * ks
                for w1, v1 in dw.items():
                    for w2, v2 in d2.items():
                        if w1 + cost + w2 <= wmax:
                            tot[w1 + cost + w2] += (v1 * v2 * s) if signed else v1 * v2
    else:
        omin = fmin(F)
        r_abs = first + jf                      # round between layer jf and jf+1 (= jb)
        RK = RK_list[r_abs] if signed else 0
        sh = (r_abs % PERIOD) + 1
        for x, dw in B.items():
            for y, cost, cs in bwd_edges(x, sh, wmax - min(dw) - omin, signed):
                d2 = F.get(y)
                if d2 is None:
                    continue
                s = cs * (-1 if (signed and (y & RK).bit_count() & 1) else 1)
                for w1, v1 in d2.items():
                    for w2, v2 in dw.items():
                        if w1 + cost + w2 <= wmax:
                            tot[w1 + cost + w2] += (v1 * v2 * s) if signed else v1 * v2


def hull(u, v, first, R, wmax, RK_list, signed, max_states, verbose=True):
    """RK_list[r] = 256-bit int of round key of absolute round r (or None if unsigned).
    Returns {weight: count (unsigned) or signed sum} over all trails u->v of weight <= wmax."""
    F = {u: {0: 1}}
    B = {v: {0: 1}}
    jf, jb = 0, R
    tot = defaultdict(int)
    while True:
        if not F or not B:
            return dict(tot)
        if jb - jf == 1:                        # final round: stream the join
            stream_join(F, B, jf, first, wmax, RK_list, signed, tot, len(F) <= len(B))
            return dict(tot)
        if len(F) <= len(B):
            r_abs = first + jf
            RK = RK_list[r_abs] if signed else 0
            nxt = step(F, "f", r_abs, wmax, RK, signed, max_states, fmin(B))
            if nxt is None:
                return None
            F, jf = nxt, jf + 1
            if verbose:
                print("   fwd -> layer %2d: %8d masks (bwd frontier layer %d: %d)" % (jf, len(F), jb, len(B)), flush=True)
        else:
            r_abs = first + jb - 1
            RK = RK_list[r_abs] if signed else 0
            nxt = step(B, "b", r_abs, wmax, RK, signed, max_states, fmin(F))
            if nxt is None:
                return None
            B, jb = nxt, jb - 1
            if verbose:
                print("   bwd -> layer %2d: %8d masks (fwd frontier layer %d: %d)" % (jb, len(B), jf, len(F)), flush=True)


def load_trail(fn, offset, R):
    d = json.load(open(fn))
    r = [x for x in d["results"] if x["offset"] == offset][0]
    if str(R) not in r.get("paths", {}):
        sys.exit("no saved path for R=%d in %s (available: %s); re-run mysx_linear_beam.py run --paths ..."
                 % (R, fn, sorted(map(int, r.get("paths", {})))))
    path = [int(h, 16) for h in r["paths"][str(R)]]
    direction = r.get("direction", d["params"].get("direction", "forward"))
    first = r.get("first_round", {}).get(str(R), offset)
    return path, first, direction


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("json")
    ap.add_argument("offset", type=int)
    ap.add_argument("--R", type=int, default=14)
    ap.add_argument("--wmax", type=int, default=None, help="default: saved trail weight + --extra")
    ap.add_argument("--extra", type=int, default=2)
    ap.add_argument("--keys", type=int, default=0, help="also compute the exact signed hull for K random keys")
    ap.add_argument("--max-states", type=int, default=3000000)
    a = ap.parse_args()
    path, first, direction = load_trail(a.json, a.offset, a.R)
    R = a.R
    # weight of the saved trail
    wsaved = 0
    for i in range(R):
        wsaved += sum(cell_info((path[i] >> (32 * p)) & M32, 64)[0] for p in range(4))
    wmax = a.wmax if a.wmax is not None else wsaved + a.extra
    print("trail: %s offset %d  R=%d  rounds %d..%d  saved weight %d  wmax %d"
          % (direction, a.offset, R, first, first + R - 1, wsaved, wmax))
    t0 = time.time()
    res = hull(path[0], path[R], first, R, wmax, None, False, a.max_states)
    if res is None:
        print("ABORTED: frontier exceeded --max-states (%d). Lower --wmax or raise --max-states." % a.max_states)
        sys.exit(2)
    print("  done in %.1fs" % (time.time() - t0))
    print("  trails u->v by weight (complete for weight <= %d): %s" % (wmax, dict(sorted(res.items()))))
    if res:
        wmin = min(res)
        S = sum(Fraction(n, 1 << w) for w, n in res.items() if w > wmin)
        top = Fraction(res[wmin], 1 << wmin)
        print("  w_min = %d, N_min = %d, sum of all other trails 2^-w = %.3e (= 2^%.2f)  vs 2^-%d"
              % (wmin, res[wmin], float(S), (float(S) and __import__('math').log2(S)) or 0, wmin))
        if res[wmin] == 1:
            print("  => isolated at its minimum weight within the budget; "
                  + ("no cancellation possible (rest < 2^-wmin)" if S < top else "rest NOT negligible: cancellation/doubling possible"))
        elif res[wmin] % 2 == 0:
            print("  => EVEN number of min-weight trails: cancellation possible (key dependent)")
        else:
            print("  => %d trails at min weight: interference possible" % res[wmin])
    if a.keys and res:
        for k in range(a.keys):
            key = ML.rand_key(1000 + k)
            rks = ML.key_schedule(key)[0]
            RK_list = [rk_int(rk) for rk in rks]
            t0 = time.time()
            sg = hull(path[0], path[R], first, R, wmax, RK_list, True, a.max_states, verbose=False)
            val = sum(Fraction(c, 1 << w) for w, c in sg.items())
            import math
            lg = math.log2(abs(val)) if val else float("-inf")
            print("  key %d: signed hull = %s2^%.3f (exact over trails of weight <= %d)   per-weight signed sums %s   [%.1fs]"
                  % (k, "-" if val < 0 else "+", lg, wmax, dict(sorted(sg.items())), time.time() - t0))


if __name__ == "__main__":
    main()
