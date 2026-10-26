#!/usr/bin/env python3
"""
mysx_linear_beam.py -- beam search over the exact MYSX-256/512 linear model
(PAPER.md section 4.2/4.3), for up to 128 rounds and every rotation offset.

Self-contained: it re-implements the exact LAT of F, the exact mask
propagation and the real cipher (only for selftest). It reports ACHIEVABLE
single-trail weights (upper bounds on the best weight), never lower bounds.

Commands
  selftest                 check model vs. the real cipher (run this first)
  reproduce                reproduce the PAPER.md section 4.5 table (r0=12, 27, R<=14)
  run [options]            full search (default: all 31 offsets, 128 rounds)

Weight convention: w = sum of h(b) per round, |corr| = 2^-w, data ~ 2^(2w).
So a distinguisher with 2^128 data needs w <= 64.
"""
import sys, os, json, random, argparse, time, heapq
from functools import lru_cache
from multiprocessing import Pool, cpu_count

M32 = 0xFFFFFFFF
PERIOD = 31
TOTAL_ROUNDS = 128
PERM = [4, 12, 20, 28, 0, 8, 16, 24, 5, 13, 21, 29,
        2, 7, 10, 15, 18, 23, 26, 31, 6, 14, 22, 30,
        1, 9, 17, 25, 3, 11, 19, 27]
INV = [0] * 32
for _i, _p in enumerate(PERM):
    INV[_p] = _i

try:
    (0).bit_count()
    def popcount(x): return x.bit_count()
except AttributeError:
    def popcount(x): return bin(x).count("1")


def rotl(x, n):
    n %= 32
    return ((x << n) | (x >> (32 - n))) & M32 if n else x


def rotr(x, n):
    return rotl(x, 32 - n)


# ---------------------------------------------------------------- linear layer
# State mask = one 256-bit int, bit 32*i + j  <->  word i, bit j.
def build_tables():
    """Forward and inverse linear layer (byte transposition + word rotation) as
    per-byte lookup tables over the 256-bit mask (little-endian byte layout)."""
    LT, LTI = {}, {}
    for sh in range(1, 32):
        img = [0] * 256
        inv = [0] * 256
        for i in range(8):
            for j in range(32):
                bi = i * 4 + (3 - j // 8)          # big-endian byte index
                k = INV[bi]                         # destination byte
                i2 = k // 4
                db = (3 - (k % 4)) * 8 + (j % 8)
                d = 32 * i2 + ((db + sh) % 32)
                img[32 * i + j] = 1 << d
                inv[d] = 1 << (32 * i + j)
        for tabs_out, im in ((LT, img), (LTI, inv)):
            tabs = []
            for k in range(32):
                t = [0] * 256
                for v in range(1, 256):
                    low = (v & -v).bit_length() - 1
                    t[v] = t[v & (v - 1)] ^ im[8 * k + low]
                tabs.append(t)
            tabs_out[sh] = tabs
    return LT, LTI


LT, LTI = build_tables()


def lin(x, sh):
    tabs = LT[sh]
    out = 0
    bs = x.to_bytes(32, "little")
    for k in range(32):
        b = bs[k]
        if b:
            out ^= tabs[k][b]
    return out


def lin_inv(x, sh):
    tabs = LTI[sh]
    out = 0
    bs = x.to_bytes(32, "little")
    for k in range(32):
        b = bs[k]
        if b:
            out ^= tabs[k][b]
    return out


# ------------------------------------------------------------------ exact LAT
@lru_cache(maxsize=None)
def cell_info(b, hmax):
    """(h, basis of im(A_b), rotr(b,2)) for output mask b of F, or None if excluded.
    Valid input masks: g = rotr(b,2) ^ l, l in im(A_b)  (4^h of them, |corr| = 2^-h).
    Excluded: h > hmax, and b = 0xFFFFFFFF (full cycle, special case; dropping
    it only restricts the search, so results stay valid upper bounds)."""
    if b == 0:
        return (0, (), 0)
    if b == M32:
        return None
    cols = [0] * 32
    for j in range(32):
        if (b >> ((j + 1) % 32)) & 1:               # edge (j, j-7) iff b_{j+1}
            k = (j - 7) % 32
            cols[j] |= 1 << k
            cols[k] |= 1 << j
    basis = []
    for c in cols:
        for bv in basis:
            c = min(c, c ^ bv)
        if c:
            basis.append(c)
    rank = len(basis)
    assert rank % 2 == 0, "rank of A_b must be even"
    h = rank // 2
    if h > hmax:
        return None
    return (h, tuple(basis), rotr(b, 2))


def all_gs(b):
    """Every valid g for b (testing only; 4^h elements)."""
    h, basis, base = cell_info(b, 16)
    span = [0]
    for bv in basis:
        span += [s ^ bv for s in span]
    return h, [base ^ l for l in span]


def coset_choices(t, basis, K, seed):
    """Low-word choices c = t ^ l, l in span(basis) (c = n[p] = m[p+4] ^ g).
    Returns the K sparsest (all of them if K == 0 and the span is small)."""
    rank = len(basis)
    if rank <= 8:
        span = [t]
        for bv in basis:
            span += [s ^ bv for s in span]
        if K and len(span) > K:
            return heapq.nsmallest(K, span, key=popcount)
        return span
    K = K or 16
    rng = random.Random(seed)
    found = set()

    def greedy(c):
        improved = True
        while improved:
            improved = False
            for bv in basis:
                if popcount(c ^ bv) < popcount(c):
                    c ^= bv
                    improved = True
        return c

    found.add(greedy(t))
    tries = 0
    while len(found) < K and tries < 6 * K:
        tries += 1
        c = t
        for bv in basis:
            if rng.getrandbits(1):
                c ^= bv
        found.add(greedy(c))
    return sorted(found, key=popcount)[:K]


def expand(x, sh, hmax, rcap, gkeep):
    """Yield (child_mask, round_cost)."""
    w = [(x >> (32 * i)) & M32 for i in range(8)]
    infos = []
    tot = 0
    for p in range(4):
        o = cell_info(w[p], hmax)
        if o is None:
            return
        tot += o[0]
        infos.append(o)
    if tot > rcap:
        return
    hi = 0
    for p in range(4):
        hi |= w[p] << (32 * (p + 4))                 # n[p+4] = m[p]
    combos = [hi]
    for p in range(4):
        h, basis, base = infos[p]
        t = w[p + 4] ^ base
        if h == 0:
            cs = (w[p + 4],)
        else:
            cs = coset_choices(t, basis, gkeep, w[p] ^ (w[p + 4] << 1))
        # n[p] = m[p+4] ^ g_p ranges over the coset (t ^ l) ^ base ^ ... see note:
        # g = base ^ l  =>  n[p] = m[p+4] ^ base ^ l = t ^ l
        if len(cs) == 1:
            v = cs[0] << (32 * p)
            combos = [c | v for c in combos]
        else:
            combos = [c | (v << (32 * p)) for c in combos for v in cs]
    for c in combos:
        yield lin(c, sh), tot


def expand_backward(x, sh, hmax, rcap, gkeep):
    """Backward step. x = mask on s[r+1]; yield (mask on s[r], round_cost).
    n = lin^-1(x); m[p] = n[p+4] (this is b_p, cost h(b_p));
    m[p+4] = n[p] ^ g_p, g_p valid for b_p, i.e. m[p+4] in the coset
    (n[p] ^ rotr(b_p,2)) ^ im(A_b): the same coset as the forward step with
    the roles of n[p] and m[p+4] exchanged."""
    n = lin_inv(x, sh)
    w = [(n >> (32 * i)) & M32 for i in range(8)]
    infos = []
    tot = 0
    for p in range(4):
        o = cell_info(w[p + 4], hmax)
        if o is None:
            return
        tot += o[0]
        infos.append(o)
    if tot > rcap:
        return
    lo = 0
    for p in range(4):
        lo |= w[p + 4] << (32 * p)                   # m[p] = n[p+4]
    combos = [lo]
    for p in range(4):
        h, basis, base = infos[p]
        t = w[p] ^ base
        if h == 0:
            cs = (w[p],)
        else:
            cs = coset_choices(t, basis, gkeep, w[p + 4] ^ (w[p] << 1))
        if len(cs) == 1:
            v = cs[0] << (32 * (p + 4))
            combos = [c | v for c in combos]
        else:
            combos = [c | (v << (32 * (p + 4))) for c in combos for v in cs]
    for c in combos:
        yield c, tot


# ---------------------------------------------------------------- beam search
def make_starts(kind):
    if kind == "single":
        return [1 << i for i in range(256)]
    if kind == "pairs47":                            # pairs inside words 4..7
        return [(1 << a) | (1 << b) for a in range(128, 256) for b in range(a + 1, 256)]
    if kind == "pairs":
        return [(1 << a) | (1 << b) for a in range(256) for b in range(a + 1, 256)]
    if kind.startswith("rand:"):                     # rand:N:K  N masks, K bits each
        _, n, k = kind.split(":")
        rng = random.Random(1)
        return [sum(1 << b for b in rng.sample(range(256), int(k))) for _ in range(int(n))]
    raise ValueError("unknown starts: " + kind)


def end_round(o):
    """Backward mode: the last round of the trail is the largest round index
    e <= 127 with e = o (mod 31)."""
    return o + PERIOD * ((TOTAL_ROUNDS - 1 - o) // PERIOD)


def beam_run(o, rounds, starts, beam, hmax, rcap, gkeep, want_paths=(), direction="forward", cal=None):
    """forward : o = index (mod 31) of the first round; starts are masks on s[r0];
                 trail covers rounds r0..r0+R-1.
    backward: o = index (mod 31) of the last round e; starts are masks on s[e+1];
                 trail covers rounds e-R+1..e (rounds are inverted one by one).
    Paths are always returned in forward order (mask on s[first] .. s[last+1])."""
    bwd = direction == "backward"
    e = end_round(o) if bwd else None
    st0 = list(dict.fromkeys(starts))
    layers = [(st0, [0] * len(st0), [-1] * len(st0))]
    best = []
    died = None
    for r in range(rounds):
        if bwd:
            sh = cal[(o - r) % PERIOD] if cal else ((o - r) % PERIOD) + 1
            gen = expand_backward
        else:
            sh = cal[(o + r) % PERIOD] if cal else ((o + r) % PERIOD) + 1
            gen = expand
        st, wt, _ = layers[-1]
        nxt = {}
        for idx in range(len(st)):
            wx = wt[idx]
            for y, c in gen(st[idx], sh, hmax, rcap, gkeep):
                wy = wx + c
                en = nxt.get(y)
                if en is None or wy < en[0]:
                    nxt[y] = (wy, idx)
        if not nxt:
            died = r + 1
            break
        items = sorted(nxt.items(), key=lambda kv: (kv[1][0], popcount(kv[0])))[:beam]
        layers.append(([k for k, _ in items], [v[0] for _, v in items], [v[1] for _, v in items]))
        best.append(items[0][1][0])
    paths = {}
    first_round = {}
    for R in want_paths:
        if R < len(layers):
            idx, path = 0, []
            for L in range(R, -1, -1):
                path.append("%064x" % layers[L][0][idx])
                idx = layers[L][2][idx]
            paths[R] = path if bwd else path[::-1]      # forward order
            first_round[R] = (e - R + 1) if bwd else o
    realizable = (e + 1) if bwd else (TOTAL_ROUNDS - o)
    return {"offset": o, "direction": direction, "beam_best": best, "died_at": died,
            "paths": paths, "first_round": first_round, "realizable_R": realizable}


def _worker(args):
    t0 = time.time()
    res = beam_run(*args)
    res["secs"] = round(time.time() - t0, 1)
    return res


def suffix_min(v):
    out = list(v)
    for i in range(len(out) - 2, -1, -1):
        out[i] = min(out[i], out[i + 1])
    return out


# ------------------------------------------------------- real cipher (selftest)
CONST = [0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
         0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89]


def simonF(x):
    return ((rotl(x, 1) & rotl(x, 8)) ^ rotl(x, 2)) & M32


def key_schedule(key):
    s = [int.from_bytes(key[4 * i:4 * i + 4], "big") for i in range(16)]
    rks = []
    for r in range(TOTAL_ROUNDS):
        spread = ((r + 1) * 0x9E3779B9) & M32
        rk = [0] * 8
        for i in range(8):
            rk[i] = s[i] ^ s[(i + 5) & 15] ^ s[(i + 11) & 15] ^ CONST[(r + i) & 7] ^ spread
            if i < 4:
                rk[i] ^= s[(i + 8) & 15] ^ CONST[(r + i + 3) & 7]
        rks.append(rk)
        L, R = s[:8], s[8:]
        for i in range(8):
            a, b, c = R[i], R[(i + 1) & 7], R[(i + 3) & 7]
            F = rotl((a + b) & M32, 7) ^ rotl(c, 13) ^ CONST[i] ^ spread
            s[i] = R[i]
            s[i + 8] = L[i] ^ F
    return rks


def round_enc(st, rk, r):
    st = [st[i] ^ rk[i] for i in range(8)]
    for i in range(4):
        L, R = st[i], st[i + 4]
        st[i], st[i + 4] = R, L ^ simonF(R)
    bs = b"".join(w.to_bytes(4, "big") for w in st)
    t = bytes(bs[PERM[i]] for i in range(32))
    st = [int.from_bytes(t[4 * i:4 * i + 4], "big") for i in range(8)]
    sh = r % 31 + 1
    return [rotl(w, sh) for w in st]


def to_int(st):
    return sum(w << (32 * i) for i, w in enumerate(st))


def selftest():
    rng = random.Random(0xC0FFEE)
    ok = True

    # 1) exact LAT of F (sampled)
    N = 1 << 15
    xs = [rng.getrandbits(32) for _ in range(N)]
    Fx = [simonF(x) for x in xs]
    tol = 5 / N ** 0.5
    bad = 0
    for b in [1 << 3, 1 << 17, (1 << 5) | (1 << 12), (1 << 5) | (1 << 6), 0x00F0A000 & ~0xFF]:
        if cell_info(b, 4) is None:
            continue
        h, gs = all_gs(b)
        assert len(gs) == 4 ** h
        for g in gs[:6]:
            c = sum(1 - 2 * ((popcount(b & f) ^ popcount(g & x)) & 1) for x, f in zip(xs, Fx)) / N
            if abs(abs(c) - 2.0 ** -h) > tol:
                bad += 1
        for _ in range(4):
            g = rng.getrandbits(32)
            if g in gs:
                continue
            c = sum(1 - 2 * ((popcount(b & f) ^ popcount(g & x)) & 1) for x, f in zip(xs, Fx)) / N
            if abs(c) > tol:
                bad += 1
    print("[1] exact LAT of F vs sampling:", "OK" if bad == 0 else "FAIL (%d)" % bad)
    ok &= bad == 0

    # 2) one real round: model cell+linear layer vs real round function
    key = bytes(rng.getrandbits(8) for _ in range(64))
    rks = key_schedule(key)
    bad = 0
    N2 = 1 << 14
    for trial in range(6):
        r = rng.randrange(0, 128)
        p = rng.randrange(4)
        b = 1 << rng.randrange(32)
        h, gs = all_gs(b)
        g = gs[rng.randrange(len(gs))]
        m = [0] * 8
        m[p] = b
        m[p + 4] = rng.getrandbits(32) if trial % 2 else 0
        n = [0] * 8
        n[p + 4] = m[p]
        for q in range(4):
            n[q] = m[q + 4] ^ (g if q == p else 0)
        mnext = lin(to_int(n), r % 31 + 1)
        mi = to_int(m)
        s = 0
        for _ in range(N2):
            x = [rng.getrandbits(32) for _ in range(8)]
            y = round_enc(x, rks[r], r)
            s += 1 - 2 * ((popcount(mi & to_int(x)) ^ popcount(mnext & to_int(y))) & 1)
        c = s / N2
        if abs(abs(c) - 2.0 ** -h) > 5 / N2 ** 0.5:
            bad += 1
    print("[2] one-round trail vs real round function:", "OK" if bad == 0 else "FAIL (%d)" % bad)
    ok &= bad == 0

    # 3) weight-0 chains of the paper (r0=12 and 27, 9 rounds) vs real cipher
    for o in (12, 27):
        res = beam_run(o, 9, make_starts("single"), 1200, 2, 8, 0, want_paths=(9,))
        w9 = res["beam_best"][8]
        path = [int(h, 16) for h in res["paths"][9]]
        good = (w9 == 0)
        if good:
            consts = set()
            for _ in range(256):
                x = [rng.getrandbits(32) for _ in range(8)]
                st = list(x)
                for r in range(o, o + 9):
                    st = round_enc(st, rks[r], r)
                consts.add((popcount(path[0] & to_int(x)) ^ popcount(path[-1] & to_int(st))) & 1)
            good = (len(consts) == 1)
        print("[3] r0=%d: 9-round weight-0 chain found=%s, |corr|=1 on real cipher: %s"
              % (o, w9 == 0, "OK" if good else "FAIL"))
        ok &= good

    # 4) duality: every forward edge must be a backward edge with the same cost
    bad = 0
    checked = 0
    for trial in range(40):
        sh = rng.randrange(1, 32)
        m = 0
        for _ in range(rng.choice((1, 1, 2, 3))):
            m |= 1 << rng.randrange(256)
        for y, c in expand(m, sh, 16, 64, 0):
            checked += 1
            if not any(x == m and cc == c for x, cc in expand_backward(y, sh, 16, 64, 0)):
                bad += 1
            if checked > 3000:
                break
        if checked > 3000:
            break
    print("[4] forward edges are backward edges (%d edges):" % checked, "OK" if bad == 0 else "FAIL (%d)" % bad)
    ok &= bad == 0

    # 5) backward search: 9-round weight-0 chains vs the real cipher + forward validity
    for o in (20, 4):                                   # chains of r0=12 (ends at 20) and r0=27 (ends at 35=4 mod 31)
        res = beam_run(o, 9, make_starts("single"), 1200, 2, 8, 0, want_paths=(9,), direction="backward")
        w9 = res["beam_best"][8]
        good = (w9 == 0)
        if good:
            path = [int(h, 16) for h in res["paths"][9]]
            first = res["first_round"][9]
            consts = set()
            for _ in range(256):
                x = [rng.getrandbits(32) for _ in range(8)]
                st = list(x)
                for r in range(first, first + 9):
                    st = round_enc(st, rks[r], r)
                consts.add((popcount(path[0] & to_int(x)) ^ popcount(path[-1] & to_int(st))) & 1)
            good = (len(consts) == 1)
        print("[5] backward end-residue %d: 9-round weight-0 chain found=%s, |corr|=1 on real cipher: %s"
              % (o, w9 == 0, "OK" if good else "FAIL"))
        ok &= good

    # 6) a backward trail with weight > 0 is a valid forward trail with the same weight
    res = beam_run(23, 14, make_starts("single"), 300, 16, 64, 3, want_paths=(14,), direction="backward")
    path = [int(h, 16) for h in res["paths"][14]]
    first = res["first_round"][14]
    wsum, valid = 0, True
    for i in range(14):
        sh = ((first + i) % PERIOD) + 1
        cost = None
        for y, c in expand(path[i], sh, 16, 64, 0):
            if y == path[i + 1]:
                cost = c
                break
        if cost is None:
            valid = False
            break
        wsum += cost
    valid = valid and wsum == res["beam_best"][13]
    print("[6] backward R=14 trail (weight %d) is a valid forward trail with equal weight: %s"
          % (res["beam_best"][13], "OK" if valid else "FAIL"))
    ok &= valid
    print("SELFTEST", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


# ------------------------------------------------------------------ commands
PAPER_TABLE = {12: [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 7, 12],
               27: [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 6, 11]}


def reproduce(args):
    jobs = [(o, 14, make_starts("single"), 1200, 2, 8, 0, ()) for o in (12, 27)]
    with Pool(min(2, cpu_count())) as pool:
        res = pool.map(_worker, jobs)
    print("Paper section 4.5 (upper bounds). 'ours' <= 'paper' means we reproduce or beat it.")
    for r in res:
        o = r["offset"]
        ours = r["beam_best"]
        print("r0=%d ours :" % o, ours)
        print("r0=%d paper:" % o, PAPER_TABLE[o])
    return 0


def parse_offsets(s):
    out = []
    for part in s.split(","):
        if "-" in part:
            a, b = part.split("-")
            out += list(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return out


def realizable_R(r):
    if "realizable_R" in r:
        return r["realizable_R"]
    return TOTAL_ROUNDS - r["offset"]            # old forward-only files


def summarize(results, rounds, title):
    """results: list of per-offset dicts (any mix of directions)."""
    checkpoints = [c for c in (9, 10, 12, 14, 16, 18, 20, 22, 24, 32, 40, 48, 56, 64, 80, 96,
                               112, 128) if c <= rounds]
    print("\n%s" % title)
    print("   R   weight  offset  dir        data~2^(2w)")
    for R in checkpoints:
        cand = [(r["ub"][R - 1], r["offset"], r.get("direction", "forward")) for r in results
                if len(r["ub"]) >= R and R <= realizable_R(r)]
        if cand:
            w, o, d = min(cand)
            print("  %3d   %5d   %5d  %-9s  2^%d" % (R, w, o, d, 2 * w))
    for thr in (32, 64):
        rs = [R for R in range(1, rounds + 1)
              if any(len(r["ub"]) >= R and R <= realizable_R(r) and r["ub"][R - 1] < thr
                     for r in results)]
        print("largest R with an achievable trail of weight < %d (data ~2^%d): %s"
              % (thr, 2 * thr, max(rs) if rs else "none"))
    print("(heuristic: upper bounds only; NOT a security proof, and hull/sign effects "
          "can cancel single trails)")


def run(args):
    offsets = parse_offsets(args.offsets)
    want = tuple(int(v) for v in args.paths.split(",")) if args.paths else ()
    starts = make_starts(args.starts)
    cal = None
    if args.cal_file:
        cands = json.load(open(args.cal_file))
        c = cands[args.cal_idx]
        cal = [c["cal"][r % 31] for r in range(31)]
        print(f"cal: {c.get('name', args.cal_idx)}")
    jobs = [(o, args.rounds, starts, args.beam, args.cell_h, args.round_cost, args.g_keep, want,
             args.direction, cal) for o in offsets]
    print("direction=%s offsets=%s rounds=%d beam=%d starts=%s (%d) cell-h<=%d g-keep=%d jobs=%d"
          % (args.direction, offsets, args.rounds, args.beam, args.starts, len(starts),
             args.cell_h, args.g_keep, args.jobs), flush=True)
    results = []
    t0 = time.time()
    with Pool(args.jobs) as pool:
        for r in pool.imap_unordered(_worker, jobs):
            r["ub"] = suffix_min(r["beam_best"])
            results.append(r)
            note = " (beam died at round %d: raise --cell-h)" % r["died_at"] if r["died_at"] else ""
            print("  offset %2d done in %6.1fs  ub[R=14]=%s  ub[R=%d]=%s%s"
                  % (r["offset"], r["secs"],
                     r["ub"][13] if len(r["ub"]) > 13 else "-", len(r["ub"]),
                     r["ub"][-1] if r["ub"] else "-", note), flush=True)
    results.sort(key=lambda r: r["offset"])
    summarize(results, args.rounds, "Best achievable weight per R (trail must fit inside the 128 rounds):")
    with open(args.out, "w") as f:
        json.dump({"params": vars(args), "results": results}, f)
    print("saved", args.out, "total %.0fs" % (time.time() - t0))
    return 0


def merge(args):
    allr = []
    for fn in args.files:
        d = json.load(open(fn))
        for r in d["results"]:
            r.setdefault("direction", d["params"].get("direction", "forward"))
            allr.append(r)
    rounds = max(len(r["ub"]) for r in allr)
    print("merged %d result sets from %d files" % (len(allr), len(args.files)))
    summarize(allr, rounds, "Combined best achievable weight per R:")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    sub.add_parser("reproduce")
    mg = sub.add_parser("merge", help="combine several result files (any directions)")
    mg.add_argument("files", nargs="+")
    p = sub.add_parser("run")
    p.add_argument("--direction", choices=("forward", "backward"), default="forward",
                   help="forward: starts are masks on s[r0] (r0 = offset); backward: starts are "
                        "masks on the output of the last round, offset = last round index mod 31")
    p.add_argument("--offsets", default="0-30", help="e.g. 0-30 or 0,12,27 (rotation offset mod 31)")
    p.add_argument("--rounds", type=int, default=128)
    p.add_argument("--beam", type=int, default=600)
    p.add_argument("--starts", default="single", help="single | pairs47 | pairs | rand:N:K")
    p.add_argument("--cell-h", type=int, default=16, help="max h(b) per cell expanded")
    p.add_argument("--round-cost", type=int, default=64, help="max weight per round expanded")
    p.add_argument("--g-keep", type=int, default=3,
                   help="per cell keep the K sparsest valid g (0 = all, slower, more exhaustive)")
    p.add_argument("--jobs", type=int, default=cpu_count())
    p.add_argument("--paths", default="14,32,64,128", help="R values whose best trail masks are saved")
    p.add_argument("--out", default="beam_results.json")
    p.add_argument("--cal_file", default=None)
    p.add_argument("--cal_idx", type=int, default=0)
    args = ap.parse_args()
    sys.exit({"selftest": lambda: selftest(), "reproduce": lambda: reproduce(args),
              "run": lambda: run(args), "merge": lambda: merge(args)}[args.cmd]())


if __name__ == "__main__":
    main()
