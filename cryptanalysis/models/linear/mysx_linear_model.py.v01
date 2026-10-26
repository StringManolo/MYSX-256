#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mysx_linear_model.py  --  Exact linear-cryptanalysis model of MYSX-256/512 (v0.1-draft)

What this file gives you (everything needed to do linear cryptanalysis of MYSX):

  1. A bit-exact Python port of the cipher (key schedule + round), validated
     against KNOWN_KAT_DIGEST of mysx.prod.js.
  2. The exact linear layer (byte transposition + word rotation) as a mask map.
  3. The EXACT linear approximation table of the only non-linear element,
     F(x) = (rotl(x,1) & rotl(x,8)) ^ rotl(x,2):
        |corr| = 2^-h(b),  h(b) = (GF(2)-rank of the F-connectivity graph) / 2,
     closed-form set of valid input masks and closed-form sign.
  4. Exact mask propagation through a round (forward and backward), the
     key-dependent sign of every trail, and correlation-vector (linear hull)
     propagation for a fixed key or in ELP mode (key independent).
  5. An empirical verifier (numpy) that checks any predicted correlation
     against the real cipher.

Usage:
    python3 mysx_linear_model.py selftest
    python3 mysx_linear_model.py report [outdir]

Conventions
  * word i, bit b  = bit b (LSB = 0) of 32-bit state word i; words are big-endian
    when serialised to bytes (as in mysx.prod.js).
  * A mask is a tuple of 8 words.  Mask u selects the parity  u . s  of state s.
  * Round r maps s[r] -> s[r+1].  Trail masks m_0 .. m_R satisfy
        m_{r+1} . s[r+1]  =  m_r . s[r]  (+) m_r . rk[r]   (up to the F-approximations)
  * corr(m_0, m_R) = E_x[(-1)^(m_0.s[0] + m_R.s[R])]   for a fixed key.
"""
import sys, os, json, time, hashlib, random
from collections import defaultdict
from functools import lru_cache
from itertools import product
from operator import itemgetter

M32 = 0xFFFFFFFF
ROUNDS = 128
CONST = [0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
         0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89]
MYZ_PERM = [4, 12, 20, 28, 0, 8, 16, 24, 5, 13, 21, 29,
            2, 7, 10, 15, 18, 23, 26, 31, 6, 14, 22, 30,
            1, 9, 17, 25, 3, 11, 19, 27]
MYZ_INV = [0] * 32
for _j, _s in enumerate(MYZ_PERM):
    MYZ_INV[_s] = _j
KNOWN_KAT_DIGEST = '3a8084d0b7df7eb691cfb54494410a5222652c219a336ee58bde48a64524a8b3'

_PERM_GET = itemgetter(*MYZ_PERM)
_INV_GET = itemgetter(*MYZ_INV)

# ----------------------------------------------------------------------------
# 0. Bit-exact port of the cipher (mysx.prod.js)
# ----------------------------------------------------------------------------
def rotl32(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & M32

def rotr32(x, n):
    return rotl32(x, 32 - (n & 31))

def parity(x):
    return x.bit_count() & 1

def simonF(x):
    return ((rotl32(x, 1) & rotl32(x, 8)) ^ rotl32(x, 2)) & M32

def key_schedule(key):
    assert len(key) == 64
    s = [int.from_bytes(key[4 * i:4 * i + 4], 'big') for i in range(16)]
    add_keys = []
    for r in range(ROUNDS):
        spread = ((r + 1) * 0x9E3779B9) & M32
        rk = [0] * 8
        for i in range(8):
            v = s[i] ^ s[(i + 5) & 15] ^ s[(i + 11) & 15] ^ CONST[(r + i) & 7] ^ spread
            if i < 4:
                v ^= s[(i + 8) & 15] ^ CONST[(r + i + 3) & 7]
            rk[i] = v
        add_keys.append(tuple(rk))
        L, R = s[0:8], s[8:16]
        for i in range(8):
            a, b, c = R[i], R[(i + 1) & 7], R[(i + 3) & 7]
            F = rotl32((a + b) & M32, 7) ^ rotl32(c, 13) ^ CONST[i] ^ spread
            s[i] = R[i]
            s[i + 8] = L[i] ^ F
    rk_final = tuple(s[i] ^ s[(i + 8) & 15] ^ CONST[(ROUNDS + i) & 7] for i in range(8))
    return add_keys, rk_final

def lin_fwd(n, r):
    """Linear layer of round r applied to a vector/mask n (8 words): byte
    transposition then word rotation.  Masks and data move identically."""
    b = b''.join(w.to_bytes(4, 'big') for w in n)
    p = bytes(_PERM_GET(b))
    sh = (r % 31) + 1
    return tuple(rotl32(int.from_bytes(p[4 * i:4 * i + 4], 'big'), sh) for i in range(8))

def lin_bwd(m, r):
    """Inverse of lin_fwd."""
    sh = (r % 31) + 1
    w = [rotr32(x, sh) for x in m]
    b = b''.join(x.to_bytes(4, 'big') for x in w)
    p = bytes(_INV_GET(b))
    return tuple(int.from_bytes(p[4 * i:4 * i + 4], 'big') for i in range(8))

def round_enc(st, rk, r):
    st = [st[i] ^ rk[i] for i in range(8)]
    for i in range(4):
        L, R = st[i], st[i + 4]
        st[i] = R
        st[i + 4] = L ^ simonF(R)
    return list(lin_fwd(st, r))

def encrypt_block(block, sched, nr=ROUNDS, whiten=True):
    add_keys, rk_final = sched
    st = [int.from_bytes(block[4 * i:4 * i + 4], 'big') for i in range(8)]
    for r in range(nr):
        st = round_enc(st, add_keys[r], r)
    if whiten:
        st = [st[i] ^ rk_final[i] for i in range(8)]
    return b''.join(w.to_bytes(4, 'big') for w in st)

def kat_digest():
    key = bytes(range(64))
    sch = key_schedule(key)
    buf = bytearray()
    for t in range(16):
        pt = bytes(((t * 32 + i) & 0xff) for i in range(32))
        buf += pt + encrypt_block(pt, sch)
    return hashlib.sha256(bytes(buf)).hexdigest()

# ----------------------------------------------------------------------------
# 1. Exact LAT of F
#
#   b.F(x) (+) g.x  =  Q_b(x) (+) l.x ,    l = rotr(b,2) (+) g
#   Q_b(x) = b . (rotl(x,1) & rotl(x,8)) = XOR_j b_{j+1} x_j x_{j-7}
#
#   Q_b is a quadratic form whose graph G_b is a subgraph of the 32-cycle
#   j -- j-7 (gcd(7,32)=1): edge (j, j-7) is present iff b_{j+1} = 1.
#   A_b = adjacency matrix of G_b over GF(2) (symmetric, zero diagonal).
#
#   THEOREM (used and machine-checked below):
#     corr(b,g) != 0  <=>  l in colspace(A_b)  (l = A_b y)
#     then corr(b,g) = (-1)^{Q_b(y)} * c0(b),  |c0(b)| = 2^{-h},  h = rank(A_b)/2
#   so #valid g = 2^{rank} = 4^h and  sum_g corr^2 = 1 (Parseval).
#   For forests h = maximum matching of G_b = minimum vertex cover (Koenig);
#   the only cycle case is b = 0xFFFFFFFF where rank = 30 (h = 15, not 16).
# ----------------------------------------------------------------------------
def Qb(b, x):
    return parity(b & rotl32(x, 1) & rotl32(x, 8))

def adj_columns(b):
    A = [0] * 32
    for j in range(32):
        if (b >> ((j + 1) & 31)) & 1:
            k = (j - 7) & 31
            A[j] ^= 1 << k
            A[k] ^= 1 << j
    return A

def corr_Z(b, g):
    """Exact Z = sum_x (-1)^{b.F(x) + g.x} by a transfer-matrix trace around the
    32-cycle (v_t = -7t mod 32).  corr = Z / 2^32.  Exact, signed, O(32)."""
    l = rotr32(b, 2) ^ g
    p00, p01, p10, p11 = 1, 0, 0, 1
    v = 0
    for _ in range(32):
        w = (b >> ((v + 1) & 31)) & 1
        lv = (l >> v) & 1
        m10 = -1 if lv else 1
        m11 = -1 if (w ^ lv) else 1
        # P = P @ [[1,1],[m10,m11]]
        p00, p01, p10, p11 = (p00 + p01 * m10, p00 + p01 * m11,
                              p10 + p11 * m10, p10 + p11 * m11)
        v = (v - 7) & 31
    return p00 + p11

class LatRow:
    __slots__ = ('b', 'rank', 'h', 'sign0', 'pivots', 'cols', 'base')

@lru_cache(maxsize=None)
def lat_row(b):
    A = adj_columns(b)
    ech = []            # echelon list of (lead_bit, vec)
    pivots = []
    for v in range(32):
        x = A[v]
        for lead, vec in ech:
            if (x >> lead) & 1:
                x ^= vec
        if x:
            ech.append((x.bit_length() - 1, x))
            pivots.append(v)
    row = LatRow()
    row.b = b
    row.rank = len(pivots)
    row.h = row.rank // 2
    row.pivots = tuple(pivots)
    row.cols = tuple(A[v] for v in pivots)
    row.base = rotr32(b, 2)                     # g for l = 0
    Z0 = corr_Z(b, row.base)
    assert abs(Z0) == 1 << (32 - row.h), (hex(b), Z0, row.h)
    row.sign0 = 1 if Z0 > 0 else -1
    return row

def h_of(b):
    return lat_row(b).h

def valid_gammas(b):
    """All (g, sign) with corr(b,g) = sign * 2^-h.  4^h entries."""
    row = lat_row(b)
    out = []
    n = len(row.pivots)
    for sub in range(1 << n):
        l = 0
        y = 0
        for i in range(n):
            if (sub >> i) & 1:
                l ^= row.cols[i]
                y |= 1 << row.pivots[i]
        sg = row.sign0 * (-1 if Qb(b, y) else 1)
        out.append((row.base ^ l, sg))
    return out

_VG_CACHE = {}
def valid_gammas_cached(b):
    r = _VG_CACHE.get(b)
    if r is None:
        r = _VG_CACHE[b] = valid_gammas(b)
    return r

def h_closed_form(b):
    """h from the run structure of G_b on the cycle (cross-check of lat_row)."""
    if b == M32:
        return 15
    if b == 0:
        return 0
    # edge t of the cycle order v_t=-7t carries weight b_{v_t+1}
    e = []
    v = 0
    for _ in range(32):
        e.append((b >> ((v + 1) & 31)) & 1)
        v = (v - 7) & 31
    # rotate so that we start right after a zero edge
    z = e.index(0)
    e = e[z:] + e[:z]
    h = 0
    run = 0
    for x in e + [0]:
        if x:
            run += 1
        else:
            if run:
                h += (run + 1) // 2           # run edges -> run+1 vertices -> floor((run+1)/2)
            run = 0
    return h

# ----------------------------------------------------------------------------
# 2. Round model: forward mask propagation with exact per-cell correlation
#
#   input  mask m on s[r] (words m[0..7]); cell p (p=0..3) has L=word p, R=word p+4
#     b_p = m[p]                      (activity of the cell: ONLY words 0..3 matter)
#     g_p in valid_gammas(b_p)        (choice of the approximation of b_p.F(R))
#     n[p+4] = m[p],  n[p] = m[p+4] (+) g_p        (mask on s_mid)
#   output mask on s[r+1] = lin_fwd(n, r)
#   round weight  w_r = sum_p h(m[p]);  every valid choice has |corr| = 2^-w_r
#   sign = prod_p sign_p * (-1)^{m . rk[r]}
# ----------------------------------------------------------------------------
HMAX_EXPAND = 6      # never enumerate a cell with h > 6 (4^6 = 4096 children)

def round_weight(m):
    return sum(lat_row(m[p]).h for p in range(4))

def round_options(m, r):
    """Yield (next_mask, sign) for all valid linear approximations of round r."""
    lists = [valid_gammas_cached(m[p]) for p in range(4)]
    for combo in product(*lists):
        n = [0] * 8
        sg = 1
        for p, (g, s) in enumerate(combo):
            n[p] = m[p + 4] ^ g
            n[p + 4] = m[p]
            sg *= s
        yield lin_fwd(n, r), sg

def round_back(m_next, r):
    """Backward direction: given the mask on s[r+1], return for each cell the
    activity b_p and the fixed part of the input mask (the other half is
    n[p] (+) g_p).  Useful for ciphertext-side (last-round) analysis."""
    n = lin_bwd(m_next, r)
    return [(n[p + 4], n[p]) for p in range(4)]       # (b_p, n[p]);  m_r[p]=b_p, m_r[p+4]=n[p]^g_p

def key_sign(m, rk):
    p = 0
    for i in range(8):
        p ^= parity(m[i] & rk[i])
    return -1 if p else 1

SCALE = 1 << 400      # exact fixed-point: correlation c  <->  int(c * SCALE)

def propagate(m0, R, rks=None, elp=False, T=40, cap=200000, r0=0, verbose=False):
    """Correlation-vector (linear hull) propagation from mask m0 over rounds
    r0..r0+R-1.  Returns dict {mask_at_s[R]: value}.
      rks given  : fixed-key signed correlations (exact up to pruning);
      elp=True   : key-independent expected linear potential  sum_T corr_T^2.
    Entries with |corr| < 2^-T (ELP < 2^-2T) are pruned; at most `cap` entries
    are kept per round (largest first).  The result is a *partial* hull: it
    contains every trail with weight <= T, nothing else."""
    vec = {tuple(m0): SCALE}
    thr = (SCALE >> (2 * T)) if elp else (SCALE >> T)
    for r in range(r0, r0 + R):
        out = defaultdict(int)
        for m, c in vec.items():
            if rks is not None and not elp:
                c *= key_sign(m, rks[r])
            hs = [lat_row(m[p]).h for p in range(4)]
            if max(hs) > HMAX_EXPAND:
                continue
            w = sum(hs)
            c2 = c >> (2 * w if elp else w)
            if abs(c2) < thr:
                continue
            for m2, sg in round_options(m, r):
                out[m2] += c2 if elp else c2 * sg
        vec = {k: v for k, v in out.items() if v != 0}
        if len(vec) > cap:
            vec = dict(sorted(vec.items(), key=lambda kv: -abs(kv[1]))[:cap])
        if verbose:
            print(f"  round {r}: {len(vec)} masks", file=sys.stderr)
    return vec

def to_float(c):
    return c / SCALE

def log2abs(c):
    import math
    if c == 0:
        return float('-inf')
    return math.log2(abs(c)) - 400

# ----------------------------------------------------------------------------
# 3. Single-trail search (layered beam search, exact rules => every reported
#    weight is an achievable single-trail weight, i.e. an UPPER bound on the
#    best single-trail weight, never a lower bound)
# ----------------------------------------------------------------------------
def low_hw_masks(maxhw):
    """All 256-bit masks of Hamming weight 1..maxhw (as 8-word tuples)."""
    out = []
    for i in range(256):
        w = [0] * 8
        w[i // 32] = 1 << (i % 32)
        out.append(tuple(w))
    if maxhw >= 2:
        for i in range(256):
            for j in range(i + 1, 256):
                w = [0] * 8
                w[i // 32] |= 1 << (i % 32)
                w[j // 32] |= 1 << (j % 32)
                out.append(tuple(w))
    return out

def beam_trails(R, starts, beam=4000, hexp=3, keep_path=True, r0=0):
    """layer[r] : {mask_at_s[r]: (weight, parent_mask)}.  Returns per-round
    best (weight, path) found.  Expands only states whose round weight has
    every cell h <= hexp (children = 4^h per cell)."""
    layer = {}
    for m in starts:
        layer[m] = (0, None)
    layers = [layer]
    best = {}
    for k in range(R):
        r = r0 + k
        nxt = {}
        for m, (w, _) in layer.items():
            hs = [lat_row(m[p]).h for p in range(4)]
            if max(hs) > hexp:
                continue
            wr = sum(hs)
            for m2, _sg in round_options(m, r):
                w2 = w + wr
                old = nxt.get(m2)
                if old is None or w2 < old[0]:
                    nxt[m2] = (w2, m)
        if not nxt:
            break
        items = sorted(nxt.items(), key=lambda kv: kv[1][0])[:beam]
        layer = dict(items)
        layers.append(layer)
        bm, (bw, _) = items[0]
        # reconstruct path
        path = [bm]
        cur = bm
        for li in range(len(layers) - 1, 0, -1):
            cur = layers[li][cur][1]
            path.append(cur)
        path.reverse()
        best[k + 1] = (bw, path)
    return best

# ----------------------------------------------------------------------------
# 4. Empirical verifier (numpy): real cipher, reduced rounds, fixed key
# ----------------------------------------------------------------------------
def _np():
    import numpy as np
    return np

def _np_rotl(x, n):
    np = _np()
    n = n & 31
    return (x << np.uint32(n)) | (x >> np.uint32(32 - n))

def _np_par(x):
    np = _np()
    x = x ^ (x >> np.uint32(16))
    x = x ^ (x >> np.uint32(8))
    x = x ^ (x >> np.uint32(4))
    x = x ^ (x >> np.uint32(2))
    x = x ^ (x >> np.uint32(1))
    return x & np.uint32(1)

def np_round(st, rk, r):
    np = _np()
    st = [st[i] ^ np.uint32(rk[i]) for i in range(8)]
    for i in range(4):
        L, R = st[i], st[i + 4]
        F = (_np_rotl(R, 1) & _np_rotl(R, 8)) ^ _np_rotl(R, 2)
        st[i], st[i + 4] = R, L ^ F
    N = st[0].shape[0]
    B = np.empty((32, N), dtype=np.uint8)
    for i in range(8):
        for k in range(4):
            B[4 * i + k] = ((st[i] >> np.uint32(24 - 8 * k)) & np.uint32(0xff)).astype(np.uint8)
    P = B[MYZ_PERM]
    sh = (r % 31) + 1
    out = []
    for i in range(8):
        w = (P[4 * i].astype(np.uint32) << np.uint32(24)) | (P[4 * i + 1].astype(np.uint32) << np.uint32(16)) \
            | (P[4 * i + 2].astype(np.uint32) << np.uint32(8)) | P[4 * i + 3].astype(np.uint32)
        out.append(_np_rotl(w, sh))
    return out

def empirical_corr(m0, mR, rks, R, N=1 << 22, seed=1, r0=0, chunk=1 << 20):
    """Monte-Carlo estimate of E[(-1)^(m0.s[r0] + mR.s[r0+R])] over N random
    plaintexts with the fixed round keys `rks`.  Returns (corr, sigma)."""
    np = _np()
    rng = np.random.default_rng(seed)
    tot = 0
    done = 0
    while done < N:
        n = min(chunk, N - done)
        st = [rng.integers(0, 1 << 32, size=n, dtype=np.uint64).astype(np.uint32) for _ in range(8)]
        pin = np.zeros(n, dtype=np.uint32)
        for i in range(8):
            if m0[i]:
                pin ^= _np_par(st[i] & np.uint32(m0[i]))
        for r in range(r0, r0 + R):
            st = np_round(st, rks[r], r)
        pout = np.zeros(n, dtype=np.uint32)
        for i in range(8):
            if mR[i]:
                pout ^= _np_par(st[i] & np.uint32(mR[i]))
        tot += int(n - 2 * int(np.count_nonzero(pin ^ pout)))
        done += n
    return tot / N, 1.0 / (N ** 0.5)

# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------
def fmt_mask(m):
    return ' '.join(f'{w:08x}' for w in m)

def mask_bits(m):
    return [32 * i + b for i in range(8) for b in range(32) if (m[i] >> b) & 1]

def rand_key(seed):
    rnd = random.Random(seed)
    return bytes(rnd.getrandbits(8) for _ in range(64))

# ----------------------------------------------------------------------------
# 5. Exact weight-0 (|corr| = 1) chains
#    A round has weight 0 iff words 0..3 of its input mask are zero.  The round
#    then acts as a pure bit permutation  n=(m4..m7,0,0,0,0) -> lin_fwd(n, r).
# ----------------------------------------------------------------------------
def free_step(m, r):
    return lin_fwd((m[4], m[5], m[6], m[7], 0, 0, 0, 0), r)

def free_chain(m, r0, cap=64):
    """(k, path): k consecutive weight-0 rounds starting at round r0 from mask m;
    path[j] is the mask on s[r0+j]."""
    path = [m]
    k = 0
    while k < cap and not any(m[p] for p in range(4)):
        m = free_step(m, r0 + k)
        path.append(m)
        k += 1
    return k, path

def single_bit(i):
    w = [0] * 8
    w[i // 32] = 1 << (i % 32)
    return tuple(w)

def free_chain_table():
    rows = []
    for r0 in range(31):
        lens = [free_chain(single_bit(i), r0)[0] for i in range(128, 256)]
        mx = max(lens)
        bi = 128 + lens.index(mx)
        rows.append(dict(r0_mod31=r0, shift=(r0 % 31) + 1, max_free_rounds=mx,
                         n_bits_at_max=lens.count(mx), n_bits_ge3=sum(1 for x in lens if x >= 3),
                         n_bits_ge2=sum(1 for x in lens if x >= 2), example_start_bit=bi))
    return rows

def chain_sign(path, k, rks, r0):
    s = 1
    for j in range(k):
        s *= key_sign(path[j], rks[r0 + j])
    return s

# ----------------------------------------------------------------------------
# 6. Self-test
# ----------------------------------------------------------------------------
def _brute_Z(b, g):
    np = _np()
    l = rotr32(b, 2) ^ g
    A = adj_columns(b)
    act = [v for v in range(32) if A[v]]
    for v in range(32):
        if not A[v] and (l >> v) & 1:
            return 0
    k = len(act)
    idx = np.arange(1 << k, dtype=np.uint64)
    x = np.zeros(1 << k, dtype=np.uint32)
    for t, v in enumerate(act):
        x |= (((idx >> np.uint64(t)) & np.uint64(1)).astype(np.uint32)) << np.uint32(v)
    F = (_np_rotl(x, 1) & _np_rotl(x, 8)) ^ _np_rotl(x, 2)
    f = _np_par((F & np.uint32(b)) ^ (x & np.uint32(g)))
    return (int((1 << k) - 2 * int(f.sum()))) * (1 << (32 - k))

def selftest():
    ok = [True]
    def check(name, cond, extra=''):
        ok[0] = ok[0] and bool(cond)
        print(f'[{"PASS" if cond else "FAIL"}] {name} {extra}')
    rnd = random.Random(2026)
    check('Python port reproduces KNOWN_KAT_DIGEST of mysx.prod.js', kat_digest() == KNOWN_KAT_DIGEST)
    check('lin_bwd inverts lin_fwd (rounds 0..61)',
          all(lin_bwd(lin_fwd(n, r), r) == n for r in range(62)
              for n in [tuple(rnd.getrandbits(32) for _ in range(8))]))
    bs = [rnd.getrandbits(32) & rnd.getrandbits(32) & rnd.getrandbits(32) for _ in range(1500)] + [M32, 1, 0x80000000]
    check('h(b) (GF(2) rank/2) == run formula on the 32-cycle', all(lat_row(b).h == h_closed_form(b) for b in bs))
    bad = 0
    for _ in range(60):
        b = 0
        for _ in range(rnd.randint(1, 8)):
            b |= 1 << rnd.randrange(32)
        vg = valid_gammas(b)
        row = lat_row(b)
        if len(vg) != 4 ** row.h:
            bad += 1
        for g, s in rnd.sample(vg, min(8, len(vg))):
            if _brute_Z(b, g) != s * (1 << (32 - row.h)) or corr_Z(b, g) != s * (1 << (32 - row.h)):
                bad += 1
        full = set(g for g, _ in vg)
        for _ in range(6):
            g = rnd.getrandbits(32)
            if (corr_Z(b, g) != 0) != (g in full) or _brute_Z(b, g) != corr_Z(b, g):
                bad += 1
    check('F-LAT theorem (valid set, |corr|=2^-h, closed-form sign) vs brute force', bad == 0, f'mismatches={bad}')
    pars = all(len(valid_gammas(b)) * 4.0 ** (-lat_row(b).h) == 1.0 for b in (1, 3, 0x81, 0xF, 0x1F, 0x10101, 0x80000001))
    check('Parseval: sum over g of corr^2 = 1', pars)
    np = _np()
    rng = np.random.default_rng(5)
    x = rng.integers(0, 1 << 32, size=1 << 21, dtype=np.uint64).astype(np.uint32)
    Fx = (_np_rotl(x, 1) & _np_rotl(x, 8)) ^ _np_rotl(x, 2)
    worst = 0.0
    for b in (1, 0x80000000, 0x101, 0x2000100, 0x1010101, 7):
        for g, s in valid_gammas(b)[:5]:
            f = _np_par((Fx & np.uint32(b)) ^ (x & np.uint32(g)))
            c = 1 - 2 * float(f.mean())
            worst = max(worst, abs(c - corr_Z(b, g) / 2 ** 32) * len(x) ** 0.5)
    check('Monte-Carlo with the real F agrees with the exact LAT', worst < 4.5, f'worst |z|={worst:.2f}')
    ok_chain = True
    for r0 in (0, 12, 27):
        best = max((free_chain(single_bit(i), r0) + (i,) for i in range(128, 256)), key=lambda t: t[0])
        k, path, i = best
        for seed in (1, 2):
            rks = key_schedule(rand_key(seed))[0]
            emp, sig = empirical_corr(path[0], path[k], rks, k, N=1 << 20, seed=seed, r0=r0)
            if abs(emp - chain_sign(path, k, rks, r0)) > 5 * sig:
                ok_chain = False
    check('|corr|=1 chains (5 and 9 rounds) incl. key sign match the real cipher', ok_chain)
    rks = key_schedule(rand_key(5))[0]
    m0 = single_bit(0)
    hull = propagate(m0, 2, rks=rks, T=12)
    top = sorted(hull.items(), key=lambda kv: -abs(kv[1]))[:4]
    zs = []
    for mR, c in top:
        emp, sig = empirical_corr(m0, mR, rks, 2, N=1 << 22, seed=9)
        zs.append(abs(emp - to_float(c)) / sig)
    check('2-round hull prediction (weight>0, signed, fixed key) vs real cipher', max(zs) < 4.5,
          'top |corr|=' + ','.join(f'{abs(to_float(c)):.4g}' for _, c in top) + f' max|z|={max(zs):.2f}')
    print('ALL PASS' if ok[0] else 'SOME TESTS FAILED')
    return 0 if ok[0] else 1


# ----------------------------------------------------------------------------
# 7. Report generator: LINEAR_MODEL.md + linear_model_data.json
# ----------------------------------------------------------------------------
def _cycles(perm):
    seen, out = set(), []
    for i in range(len(perm)):
        if i in seen:
            continue
        c, j = [], i
        while j not in seen:
            seen.add(j)
            c.append(j)
            j = perm[j]
        out.append(c)
    return out

def report(outdir='.'):
    from collections import Counter
    t0 = time.time()
    os.makedirs(outdir, exist_ok=True)
    D = {}
    log = lambda s: print(f'[{time.time() - t0:6.1f}s] {s}', file=sys.stderr)

    # --- linear layer
    D['shift_schedule_r_mod_31'] = [(r % 31) + 1 for r in range(31)]
    D['myz_perm'] = MYZ_PERM
    D['myz_inv'] = MYZ_INV
    cyc = _cycles(MYZ_PERM)
    D['myz_cycles'] = cyc
    # word each input byte (of s_mid word w) lands in after the transposition
    dest = {j: MYZ_INV[j] for j in range(32)}
    D['byte_dest_word'] = {j: dest[j] // 4 for j in range(32)}

    # --- LAT data
    rnd = random.Random(1)
    D['h_hw1'] = sorted({lat_row(1 << i).h for i in range(32)})
    D['h_hw2_hist'] = dict(Counter(lat_row((1 << i) | (1 << j)).h for i in range(32) for j in range(i + 1, 32)))
    D['h_uniform_random_hist'] = dict(sorted(Counter(lat_row(rnd.getrandbits(32)).h for _ in range(1 << 14)).items()))
    dense = []
    for m in range(1, 16):
        b = 0
        for t in range(2 * m):
            b |= 1 << ((1 - 7 * t) % 32)
        dense.append(dict(h=lat_row(b).h, hamming=bin(b).count('1'), mask=f'{b:08x}'))
        assert lat_row(b).h == m
    D['densest_masks_per_weight'] = dense
    D['h_full_mask'] = lat_row(M32).h
    log('LAT data done')

    # --- free chains
    D['free_chain_table'] = free_chain_table()
    log('free chain table done')

    # --- verified |corr|=1 chains
    ver = []
    for r0 in (12, 27, 0):
        k, path, i = max((free_chain(single_bit(b), r0) + (b,) for b in range(128, 256)), key=lambda t: t[0])
        entry = dict(r0=r0, rounds=k, start_bit=i, start_mask=fmt_mask(path[0]), end_mask=fmt_mask(path[k]),
                     end_bit=mask_bits(path[k]), per_round_masks=[fmt_mask(p) for p in path], keys=[])
        for seed in (1, 2, 3):
            rks = key_schedule(rand_key(seed))[0]
            emp, sig = empirical_corr(path[0], path[k], rks, k, N=1 << 21, seed=seed, r0=r0)
            entry['keys'].append(dict(seed=seed, predicted_sign=chain_sign(path, k, rks, r0),
                                      empirical=emp, sigma=sig))
        ver.append(entry)
    D['verified_chains'] = ver
    log('chains verified')

    # --- beam search beyond the free chain
    starts = low_hw_masks(1)
    beam_out = {}
    paths = {}
    for r0 in (12, 27):
        best = beam_trails(14, starts, beam=1200, hexp=2, r0=r0)
        beam_out[r0] = {k: w for k, (w, _) in sorted(best.items())}
        paths[r0] = best
        log(f'beam window r0={r0} done')
    D['beam_best_weight'] = {str(r0): v for r0, v in beam_out.items()}

    # --- hull check of trails with weight > 0 (fixed key, signed)
    checks = []
    rks = key_schedule(rand_key(1))[0]
    for R in (10, 11, 12):
        w, path = paths[12][R]
        hull = propagate(path[0], R, rks=rks, T=w + 4, cap=20000, r0=12)
        pred = hull.get(path[-1], 0)
        emp, sig = empirical_corr(path[0], path[-1], rks, R, N=1 << 22, seed=21, r0=12)
        checks.append(dict(r0=12, rounds=R, weight=w, start_bit=mask_bits(path[0]), end_bits=mask_bits(path[-1]),
                           hull_masks_kept=len(hull), predicted=to_float(pred), empirical=emp, sigma=sig,
                           z=(emp - to_float(pred)) / sig))
        log(f'hull check R={R} done')
    D['hull_checks'] = checks

    json.dump(D, open(os.path.join(outdir, 'linear_model_data.json'), 'w'), indent=1)
    open(os.path.join(outdir, 'LINEAR_MODEL.md'), 'w').write(_render_md(D))
    log('written')

def _render_md(D):
    L = []
    A = L.append
    A('# MYSX-256/512 v0.1-draft: exact linear model and cryptanalysis data\n')
    A('Generated by `python3 mysx_linear_model.py report` (all numbers below are produced by that script; '
      '`python3 mysx_linear_model.py selftest` machine-checks the model against the real cipher).\n')
    A('## 1. The model in one page\n')
    A('Bit `b` of a word is the bit with weight `2^b`; `bit i of rotl(x,k) = x_{i-k}`. A mask `u` selects the parity '
      '`u . s`. Trail masks `m_0 .. m_R` (`m_r` on `s[r]`) satisfy, for a fixed key,\n')
    A('```\nm_{r+1} . s[r+1]  =  m_r . s[r]  (+)  m_r . rk[r]      up to the approximations of F\n```\n')
    A('**Only non-linear element:** `F(x) = (rotl(x,1) & rotl(x,8)) ^ rotl(x,2)`. For masks `b` (output) and `g` (input):\n')
    A('```\nb.F(x) (+) g.x = Q_b(x) (+) l.x ,   l = rotr(b,2) (+) g ,   Q_b(x) = XOR_j b_{j+1} x_j x_{j-7}\n```\n')
    A('`Q_b` is a quadratic form whose graph `G_b` is a subgraph of the 32-cycle `j -- j-7` (edge `(j, j-7)` present iff '
      '`b_{j+1} = 1`; one single cycle because gcd(7,32)=1). With `A_b` the GF(2) adjacency matrix of `G_b`:\n')
    A('* `corr(b,g) != 0`  iff  `l = A_b y` for some `y` (so exactly `2^rank(A_b) = 4^h` valid `g`);')
    A('* then `corr(b,g) = (-1)^{Q_b(y)} * c0(b)` and `|corr| = 2^-h`, `h = rank(A_b)/2`;')
    A('* `h(b)` = maximum matching = minimum vertex cover of `G_b` (a forest; König), except `b = 0xFFFFFFFF` '
      '(full cycle): rank 30, `h = 15`;')
    A('* a run of `e` consecutive active edges costs `floor((e+1)/2)`; Parseval holds (`sum_g corr^2 = 1`).\n')
    A('**Round, forward direction** (input mask `m` on `s[r]`, cells `p = 0..3` with `L = word p`, `R = word p+4`):\n')
    A('```\nb_p = m[p]                       only words 0..3 of the input mask decide the cost\ng_p in valid(b_p)                free choice among 4^h(b_p) values, all with |corr| = 2^-h(b_p)\nn[p+4] = m[p] ;  n[p] = m[p+4] (+) g_p\nm_next = lin_fwd(n, r)           byte transposition, then rotl by (r mod 31)+1: masks move like data\nweight w_r = sum_p h(m[p]) ;  sign = prod_p sign_p * (-1)^{m . rk[r]}\n```\n')
    A('Backward direction (ciphertext side): `n = lin_bwd(m_next, r)`; then `b_p = n[p+4]`, `m[p] = b_p`, '
      '`m[p+4] = n[p] (+) g_p`. Final whitening adds the constant sign `(-1)^{m_R . rkFinal}`.\n')
    A('**Correlation of a trail** = `prod_r 2^-w_r * (-1)^{sum_r m_r.rk[r]} * prod sign_p`. **Linear hull** (exact, '
      'fixed key) = sum over all trails with the same `(m_0, m_R)`; `propagate()` computes it by correlation-vector '
      'propagation (pruned by weight). **ELP** (key independent, assumes independent round keys, which is not true '
      'for this deterministic schedule) = `sum corr_T^2`: `propagate(..., elp=True)`.\n')

    A('## 2. Linear-layer data\n')
    A(f"* Rotation amount by round: `(r mod 31) + 1`, so the linear layer repeats with period 31: `{D['shift_schedule_r_mod_31']}`.")
    A(f"* `MYZ_PERM` (output byte j takes input byte MYZ_PERM[j]): `{D['myz_perm']}`")
    A(f"* `MYZ_INV`: `{D['myz_inv']}`")
    A(f"* Cycle structure of the byte permutation: lengths `{sorted(len(c) for c in D['myz_cycles'])}`, cycles `{D['myz_cycles']}`.")
    A('* Only bytes that start in words 0..3 of `n` and land in words 4..7 keep a mask at zero cost: input byte index '
      '`j` (word `j//4`) lands in word `MYZ_INV[j]//4`.\n')
    A('| input byte j | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 |\n|---|' + '---|' * 16)
    A('| lands in word | ' + ' | '.join(str(D['byte_dest_word'][j]) for j in range(16)) + ' |\n')

    A('## 3. LAT of F: cost data\n')
    A(f"* Single-bit `b`: `h = {D['h_hw1']}` for all 32 positions (corr `+-1/2`, 4 valid `g`).")
    A(f"* Two-bit `b` (496 masks), histogram of `h`: `{D['h_hw2_hist']}` (the 32 pairs with bit distance 7 are adjacent edges and cost only 1).")
    A(f"* Uniformly random 32-bit `b` (16384 samples), histogram of `h`: `{D['h_uniform_random_hist']}`.")
    A(f"* Full mask `0xFFFFFFFF`: `h = {D['h_full_mask']}`.")
    A('* Densest masks per unit of weight (bits `(1-7t) mod 32`, `t < 2m`): every extra 2 consecutive edges costs 1.\n')
    A('| h | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |\n|---|' + '---|' * 8)
    A('| Hamming weight | ' + ' | '.join(str(x['hamming']) for x in D['densest_masks_per_weight'][:8]) + ' |')
    A('| mask | ' + ' | '.join('`' + x['mask'] + '`' for x in D['densest_masks_per_weight'][:8]) + ' |\n')
    A('So the cost per active mask bit is about 1/2 in the best case, never lower than 15/32 per bit.\n')

    A('## 4. Exact weight-0 chains (correlation +-1)\n')
    A('A round has weight 0 iff words 0..3 of its input mask are zero; it is then a pure bit permutation and the '
      'tracked bit never meets `F`. Because the rotation schedule has period 31 there are only 31 distinct windows. '
      'The table is exact (every one of the 128 single-bit masks in words 4..7 was followed).\n')
    A('| window r mod 31 | shift | max free rounds | #bits reaching max | #bits >= 3 rounds | #bits >= 2 rounds |\n|---|---|---|---|---|---|')
    for x in D['free_chain_table']:
        A(f"| {x['r0_mod31']} | {x['shift']} | {x['max_free_rounds']} | {x['n_bits_at_max']} | {x['n_bits_ge3']} | {x['n_bits_ge2']} |")
    best = max(D['free_chain_table'], key=lambda x: x['max_free_rounds'])
    A(f"\nLongest chain: **{best['max_free_rounds']} consecutive rounds** (windows r = 12 and r = 27 mod 31). "
      'Verified against the real cipher (fixed random keys, 2^21 plaintexts, reduced rounds, no whitening):\n')
    A('| window r0 | rounds | input mask (bit) | output mask (bit) | key seed | predicted sign | empirical corr | sigma |\n|---|---|---|---|---|---|---|---|')
    for e in D['verified_chains']:
        for kx in e['keys']:
            A(f"| {e['r0']} | {e['rounds']} | s[{e['r0']}] bit {e['start_bit']} | s[{e['r0'] + e['rounds']}] bit {e['end_bit'][0]} | "
              f"{kx['seed']} | {kx['predicted_sign']:+d} | {kx['empirical']:+.5f} | {kx['sigma']:.1e} |")
    A('\nThe magnitude is 1 for every key; only the sign depends on the key (through `sum m_r . rk[r]`).\n')

    A('## 5. Best single trails beyond the free chain (beam search, UPPER bounds)\n')
    A('Layered beam search with the exact rules, starts = all 256 single-bit masks, beam 1200, cells with `h <= 2` '
      'expanded. Each weight is an achievable single-trail weight, i.e. an upper bound on the best weight, not a minimum.\n')
    rs = sorted(next(iter(D['beam_best_weight'].values())).keys(), key=int)
    A('| rounds R | ' + ' | '.join(str(k) for k in rs) + ' |\n|---|' + '---|' * len(rs))
    for r0, v in D['beam_best_weight'].items():
        A(f'| best weight, window r0={r0} | ' + ' | '.join(str(v[k]) for k in rs) + ' |')
    A('')
    A('## 6. Hull check of trails with weight > 0 (signed, fixed key)\n')
    A('Prediction = exact signed sum of all trails of weight <= weight+4 with the same end masks; empirical = real cipher, 2^22 plaintexts.\n')
    A('| window r0 | R | best-trail weight | hull masks kept | predicted corr | empirical corr | sigma | z |\n|---|---|---|---|---|---|---|---|')
    for c in D['hull_checks']:
        A(f"| {c['r0']} | {c['rounds']} | {c['weight']} | {c['hull_masks_kept']} | {c['predicted']:+.6f} | {c['empirical']:+.6f} | {c['sigma']:.1e} | {c['z']:+.2f} |")
    A('')
    A('## 7. What this does and does not establish\n')
    A('**Established (machine-checked by `selftest`):** the exact LAT of F (valid set, magnitude, sign); the exact '
      'per-round mask rule; key-sign tracking; existence of key-independent-magnitude (|corr| = 1) single-bit '
      'relations over up to 9 consecutive rounds; the model reproduces the real cipher within sampling error.\n')
    A('**Not established:** a lower bound on the best trail weight over 128 rounds (beam values are upper bounds from '
      'single-bit starts only); an exact hull (pruned); the cost of a key-recovery attack; behaviour of multi-bit '
      'starts at larger R. The weight-0 windows are a property of 5-9 round windows of a 128-round cipher, not an '
      'attack on the full cipher.\n')
    A('**Exact MILP/SAT encoding (for a certified bound):** variables = the 8 mask words per round; per cell, '
      'weight = minimum vertex cover of `G_b` (cover variables `S_v`, constraints `S_j + S_{j-7} >= b_{j+1}`, '
      'objective `sum S_v`; exact for `b != 0xFFFFFFFF`), and the validity constraint `g = rotr(b,2) (+) A_b y` '
      '(equivalently `l` orthogonal to `ker A_b`: per odd path component the XOR of `l` over its even-position vertices '
      'is 0, and `l_v = 0` on vertices touched by no active edge). Sign tracking is not needed for magnitudes.\n')
    A('## 8. API cheat sheet\n')
    A('```python\nfrom mysx_linear_model import *\nlat_row(b).h                  # cost h(b) of output mask b\nvalid_gammas(b)               # all (g, sign) with corr = sign*2^-h\ncorr_Z(b, g) / 2**32          # exact signed corr of b.F(x)^g.x\nround_options(m, r)           # all (next_mask, sign) of round r from mask m\nlin_fwd(n, r), lin_bwd(m, r)  # linear layer on masks\nrks = key_schedule(key)[0]    # real round keys\npropagate(m0, R, rks=rks, T=20, r0=0)   # signed hull, fixed key\npropagate(m0, R, elp=True, T=20)        # ELP, key independent\nempirical_corr(m0, mR, rks, R, N=1<<22, r0=0)\nbeam_trails(R, low_hw_masks(1), beam=1200, hexp=2, r0=12)\n```\n')
    return '\n'.join(L) + '\n'


if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'selftest'
    if cmd == 'selftest':
        sys.exit(selftest())
    elif cmd == 'report':
        report(sys.argv[2] if len(sys.argv) > 2 else '.')
    else:
        print(__doc__)
