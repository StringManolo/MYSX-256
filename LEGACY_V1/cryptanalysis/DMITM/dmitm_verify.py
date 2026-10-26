#!/usr/bin/env python3
"""
dmitm_verify.py - Verificacion independiente y ampliacion del analisis de
diferenciales imposibles (miss-in-the-middle sobre cadenas de peso 0) de MYSX-256/512.

Es AUTOCONTENIDO: reimplementa la capa lineal, la ronda y la key schedule desde el
paper (SPEC §2). No importa nada del repo (solo lee KAT.json para el test `kat`).

Uso:  python3 dmitm_verify.py [comando] [opciones]

  selfcheck   inversas lineales, round_dec = round_enc^-1, tabla fwd §3.5 (un bit)
  sb          busqueda MITM de UN BIT: reproduce el 15 de DeepSeek (words 0-3, min_len=4)
              y la version corregida (finales en words 0-7, min_len=1)
  exact       algebra lineal exacta (multi-bit): m(r0) exacto por offset + mejor
              imposible EXACTO (dimension de subespacios, sin restringir a un bit)
  extend      extension truncada bit a bit hacia plaintext y ciphertext del mejor testigo
  real        verifica contra el cifrado real (rondas del SPEC, key schedule real) las
              PREMISAS del argumento (determinismo fwd y bwd, 100%) para los mejores
              testigos, con claves normales y degeneradas
  design      comparativa: Myszkowski/31 vs permutaciones aleatorias y otros periodos
  kat         conformidad de esta reimplementacion con KAT.json (--kat ruta)
  all         selfcheck + sb + exact + extend + real  (design y kat aparte)

Opciones: --pairs N (real, def 2000)  --perms N (design, def 12)  --kat RUTA
"""
import sys, os, random, time, json, argparse
from collections import defaultdict, Counter

M32 = 0xFFFFFFFF
MYZ_PERM = [4,12,20,28, 0,8,16,24, 5,13,21,29,
            2,7,10,15,18,23,26,31, 6,14,22,30,
            1,9,17,25, 3,11,19,27]
CONST = [0x243f6a88,0x85a308d3,0x13198a2e,0x03707344,
         0xa4093822,0x299f31d0,0x082efa98,0xec4e6c89]

def rotl(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & M32
def rotr(x, n): return rotl(x, (32 - n) % 32)

def w2b(ws):
    b = []
    for w in ws: b += [(w>>24)&255, (w>>16)&255, (w>>8)&255, w&255]
    return b
def b2w(bs):
    return [(bs[4*i]<<24)|(bs[4*i+1]<<16)|(bs[4*i+2]<<8)|bs[4*i+3] for i in range(8)]
def i2w(s): return [(s >> (32*i)) & M32 for i in range(8)]
def w2i(ws): return sum(w << (32*i) for i, w in enumerate(ws))
def sbit(w, b):
    m = [0]*8; m[w] = 1 << b; return tuple(m)
def desc(ws):
    act = [(w, b) for w in range(8) for b in range(32) if (ws[w] >> b) & 1]
    return ",".join(f"w{w}b{b}" for w, b in act) if len(act) <= 4 else f"<{len(act)} bits>"

# =============================================================================
# Capa lineal parametrizable (permutacion de bytes + periodo de rotacion)
# =============================================================================
import os as _os
_ROT_CAL_STR = _os.environ.get('MYSX_ROT_CAL', '')
if _ROT_CAL_STR:
    ROT_CAL = [int(x) for x in _ROT_CAL_STR.split(',')]
    assert len(ROT_CAL) == 31, f"MYSX_ROT_CAL: 31 valores, tiene {len(ROT_CAL)}"
    assert sorted(ROT_CAL) == list(range(1, 32)), "MYSX_ROT_CAL: permutación de 1..31"
else:
    ROT_CAL = None

class Lin:
    def __init__(self, perm=MYZ_PERM, period=31, step=1):
        self.perm = list(perm); self.period = period; self.step = step
    def sh(self, r):
        if ROT_CAL is not None and self.step == 1 and self.period == 31:
            return ROT_CAL[r % 31]
        return (r * self.step) % self.period + 1
    def transp(self, ws):
        b = w2b(ws); return b2w([b[self.perm[j]] for j in range(32)])
    def untransp(self, ws):
        b = w2b(ws); out = [0]*32
        for j in range(32): out[self.perm[j]] = b[j]
        return b2w(out)
    def fwd(self, s_mid, r):
        return [rotl(x, self.sh(r)) for x in self.transp(s_mid)]
    def bwd(self, s, r):
        return self.untransp([rotr(x, self.sh(r)) for x in s])
    def fstep(self, st, r):
        if any(st[4:8]): return None
        return tuple(self.fwd([0,0,0,0,st[0],st[1],st[2],st[3]], r))
    def bstep(self, st, r):
        n = self.bwd(st, r)
        if any(n[0:4]): return None
        return (n[4], n[5], n[6], n[7], 0, 0, 0, 0)
    # --- propagacion truncada bit a bit: (val, unk), unk=1 => bit desconocido
    def dF(self, Rv, Ru):
        kz = ~(Rv | Ru) & M32                       # bits de DeltaR conocidos a 0
        and_unk = ~(rotl(kz, 1) & rotl(kz, 8)) & M32  # AND de F puede activarse
        fu = (rotl(Ru, 2) | and_unk) & M32
        fv = rotl(Rv, 2) & ~fu & M32
        return fv, fu
    def fwd_trunc(self, val, unk, r):
        mv = [0]*8; mu = [0]*8
        for p in range(4):
            Rv, Ru = val[p+4], unk[p+4]; Lv, Lu = val[p], unk[p]
            fv, fu = self.dF(Rv, Ru)
            mv[p], mu[p] = Rv, Ru
            mu[p+4] = Lu | fu; mv[p+4] = (Lv ^ fv) & ~mu[p+4] & M32
        sh = self.sh(r)
        return ([rotl(x, sh) for x in self.transp(mv)],
                [rotl(x, sh) for x in self.transp(mu)])
    def bwd_trunc(self, val, unk, r):
        sh = self.sh(r)
        v = self.untransp([rotr(x, sh) for x in val])
        u = self.untransp([rotr(x, sh) for x in unk])
        nv = [0]*8; nu = [0]*8
        for p in range(4):
            Rv, Ru = v[p], u[p]; Xv, Xu = v[p+4], u[p+4]
            fv, fu = self.dF(Rv, Ru)
            nv[p+4], nu[p+4] = Rv, Ru
            nu[p] = Xu | fu; nv[p] = (Xv ^ fv) & ~nu[p] & M32
        return nv, nu

LIN = Lin()

# =============================================================================
# Cifrado real segun SPEC (§2): ronda, ronda inversa, key schedule
# =============================================================================
def simonF(x): return ((rotl(x,1) & rotl(x,8)) ^ rotl(x,2)) & M32

def round_enc(s, rk, r):
    s = [s[i] ^ rk[i] for i in range(8)]
    mid = [0]*8
    for p in range(4):
        L, R = s[p], s[p+4]; mid[p] = R; mid[p+4] = L ^ simonF(R)
    return LIN.fwd(mid, r)

def round_dec(s, rk, r):
    mid = LIN.bwd(s, r); o = [0]*8
    for p in range(4):
        R = mid[p]; L = mid[p+4] ^ simonF(R); o[p] = L; o[p+4] = R
    return [o[i] ^ rk[i] for i in range(8)]

def key_schedule(key):
    s = [int.from_bytes(key[4*i:4*i+4], 'big') for i in range(16)]
    rks = []
    for r in range(128):
        spread = ((r+1) * 0x9E3779B9) & M32
        rk = [s[i] ^ s[(i+5)%16] ^ s[(i+11)%16] ^ CONST[(r+i)%8] ^ spread for i in range(8)]
        for i in range(4): rk[i] ^= s[(i+8)%16] ^ CONST[(r+i+3)%8]
        L, R = s[0:8], s[8:16]; ns = [0]*16
        for i in range(8):
            a, b, c = R[i], R[(i+1)%8], R[(i+3)%8]
            F = rotl((a+b) & M32, 7) ^ rotl(c, 13) ^ CONST[i] ^ spread
            ns[i] = R[i]; ns[i+8] = L[i] ^ F
        s = ns; rks.append(rk)
    fin = [s[i] ^ s[(i+8)%16] ^ CONST[(128+i)%8] for i in range(8)]
    return rks, fin

def rand_key(seed): return random.Random(seed).randbytes(64)

# =============================================================================
# selfcheck
# =============================================================================
_EXPECTED_FWD = {0:3,1:3,2:3,3:3,4:3,5:3,6:3,10:13,11:12,12:11,13:10,14:9,
                 15:8,16:7,17:6,18:5,27:3,28:3,29:3}

def sb_fwd_len(lin, r0, w, b, maxr=128):
    st = sbit(w, b); k = 0
    while k < maxr and not any(st[4:8]):
        st = lin.fstep(st, r0 + k); k += 1
    return k

def cmd_selfcheck(a):
    print("="*70); print("SELFCHECK"); print("="*70)
    rng = random.Random(1)
    for r in range(128):
        for _ in range(200):
            s = [rng.getrandbits(32) for _ in range(8)]
            assert LIN.bwd(LIN.fwd(s, r), r) == s
    print("  [OK] lin_bwd(lin_fwd(s)) = s   (128 rondas x 200)")
    rks, _ = key_schedule(rand_key(3))
    for r in range(128):
        for _ in range(50):
            s = [rng.getrandbits(32) for _ in range(8)]
            assert round_dec(round_enc(list(s), rks[r], r), rks[r], r) == s
    print("  [OK] round_dec = round_enc^-1  (128 rondas x 50)")
    # ciclos de la permutacion
    seen = set(); cyc = []
    for i in range(32):
        if i in seen: continue
        c = 0; j = i
        while j not in seen: seen.add(j); c += 1; j = MYZ_PERM[j]
        cyc.append(c)
    print(f"  longitudes de ciclo de MYZ_PERM: {sorted(cyc)}")
    print("  tabla forward §3.5 (un bit, words 0-3):")
    ok = True
    for r0 in range(31):
        best = max(sb_fwd_len(LIN, r0, w, b) for w in range(4) for b in range(32))
        e = _EXPECTED_FWD.get(r0)
        st = "" if e is None else ("OK" if e == best else f"MISMATCH(paper {e})")
        if e is not None and e != best: ok = False
        print(f"    r0={r0:2d}: {best:2d}  {st}")
    print("  [OK] tabla §3.5 reproducida" if ok else "  [!!] hay MISMATCH con el paper")

# =============================================================================
# sb : MITM de un bit, version DeepSeek vs corregida
# =============================================================================
def sb_chains(lin, end_words, min_len_bwd):
    fw = {}
    for r1 in range(128):
        for w in range(4):
            for b in range(32):
                st = sbit(w, b); t = [(r1, st)]; r = r1
                while r < 128 and not any(st[4:8]):
                    st = lin.fstep(st, r); r += 1; t.append((r, st))
                if len(t) > 1: fw[(r1, w, b)] = t
    bw = {}
    for r2 in range(1, 128):
        for w in end_words:
            for b in range(32):
                st = sbit(w, b); t = [(r2, st)]; r = r2 - 1
                while r >= 0:
                    st = lin.bstep(st, r)
                    if st is None: break
                    t.append((r, st)); r -= 1
                if len(t) - 1 >= min_len_bwd: bw[(r2, w, b)] = t
    return fw, bw

def sb_mitm(fw, bw, thr):
    fa = defaultdict(list); ba = defaultdict(list)
    for (r1, w, b), t in fw.items():
        for R, s in t: fa[R].append((R - r1, r1, w, b, s))
    for (r2, w, b), t in bw.items():
        for R, s in t: ba[R].append((r2 - R, r2, w, b, s))
    out = {}
    for R in range(128):
        F = sorted(fa[R], key=lambda x: -x[0]); G = sorted(ba[R], key=lambda x: -x[0])
        for f in F:
            for g in G:
                tot = f[0] + g[0]
                if tot < thr: break
                if f[4] != g[4]:
                    key = (f[1] % 31, f[2], f[3], tot, g[2], g[3])
                    out.setdefault(key, (tot, R, f, g))
    return sorted(out.values(), key=lambda x: -x[0])

def cmd_sb(a):
    print("="*70); print("SB: MITM de un bit (reproduccion + correccion)"); print("="*70)
    t0 = time.time()
    for label, ew, ml in (("DeepSeek: finales words 0-3, min_len=4", range(4), 4),
                          ("Corregido: finales words 0-3, min_len=1", range(4), 1),
                          ("Corregido: finales words 0-7, min_len=1", range(8), 1)):
        fw, bw = sb_chains(LIN, ew, ml)
        mx = max(len(t) - 1 for t in bw.values())
        res = sb_mitm(fw, bw, 14)
        cnt = Counter(r[0] for r in res)
        print(f"\n  [{label}]  max cadena backward = {mx}")
        print(f"   diferenciales distintos (dedup mod 31) por total: {dict(sorted(cnt.items()))}")
        for tot, R, f, g in res[:6]:
            print(f"    total {tot}: fwd s[{f[1]}] w{f[2]}b{f[3]} ({f[0]}r)  ->  s[{R}] ; "
                  f"bwd s[{g[1]}] w{g[2]}b{g[3]} ({g[0]}r)   estados: {desc(f[4])} vs {desc(g[4])}")
    print(f"\n  ({time.time()-t0:.0f}s)")

# =============================================================================
# exact : algebra lineal multi-bit
# =============================================================================
def fwd_spaces(lin, r0, kmax=30):
    """res[k] = [(estado_final_en_s[r0+k], entrada_en_s[r0])] base del subespacio
    de diferencias con k rondas consecutivas de peso 0 desde r0 (dim = len)."""
    vecs = [(1 << i, 1 << i) for i in range(128)]
    res = {}
    for k in range(1, kmax + 1):
        nv = []
        for st, inp in vecs:
            w = i2w(st)
            nv.append((w2i(lin.fwd([0,0,0,0,w[0],w[1],w[2],w[3]], r0 + k - 1)), inp))
        res[k] = nv
        piv = {}; ker = []
        for st, inp in nv:
            hi = st >> 128
            while hi:
                p = hi.bit_length() - 1
                if p in piv:
                    ph, ps, pi = piv[p]; hi ^= ph; st ^= ps; inp ^= pi
                else:
                    piv[p] = (hi, st, inp); break
            if hi == 0: ker.append((st, inp))
        vecs = ker
        if not vecs: break
    return res

def exact_ids(lin, S):
    P = lin.period
    m = {r0: max(S[r0]) for r0 in S}
    out = []
    for R in range(P):
        for b in range(1, m[R] + 1):
            for a in range(1, 14 + 30):
                r0 = (R - a) % P
                if a > m[r0]: continue
                dV, dX = len(S[r0][a]), len(S[R][b])
                if dV == 1 and dX == 1 and S[r0][a][0][0] == S[R][b][0][1]:
                    continue  # misma recta: no hay imposible
                out.append((a + b, R, a, b, dV, dX))
    out.sort(key=lambda x: (-x[0], x[1]))
    return m, out

def witness(lin, S, R, a, b):
    P = lin.period; r0 = (R - a) % P
    V = S[r0][a]; X = S[R][b]
    for xs, xi in X:           # xi = diferencia en s[R], xs = en s[R+b]
        for us, ui in V:       # us = diferencia en s[R] desde el lado fwd
            if us != xi:
                return dict(R=R, a=a, b=b, din=i2w(ui), u=i2w(us), x=i2w(xi), dout=i2w(xs))
    return None

def cmd_exact(a):
    print("="*70); print("EXACT: algebra lineal GF(2) (multi-bit)"); print("="*70)
    t0 = time.time()
    S = {r0: fwd_spaces(LIN, r0) for r0 in range(31)}
    m, ids = exact_ids(LIN, S)
    print("  m(r0): maxima rondas consecutivas de peso 0 (exacto, cualquier diferencia en words 0-3)")
    diff = 0
    for r0 in range(31):
        sbm = max(sb_fwd_len(LIN, r0, w, b) for w in range(4) for b in range(32))
        flag = "" if sbm == m[r0] else f"  <-- multi-bit MEJORA al un-bit ({sbm})"
        if flag: diff += 1
        print(f"    r0={r0:2d}: exacto={m[r0]:2d} (dim espacio con 1 ronda de peso0 = 128; dim con m rondas = {len(S[r0][m[r0]])}){flag}")
    print(f"  maximo global = {max(m.values())} (paper: 13).   offsets donde multi-bit > un-bit: {diff}")
    print(f"\n  Mejores diferenciales imposibles EXACTOS (a rondas fwd + b rondas bwd en s[R]):")
    cnt = Counter(i[0] for i in ids)
    print(f"   n.o de (R,a,b) por total: {dict(sorted(cnt.items())[-6:])}")
    for tot, R, aa, bb, dV, dX in ids[:12]:
        print(f"    total={tot}  R={R:2d} (mod 31)  a={aa:2d} b={bb:2d}  dim_in={dV}  dim_out={dX}")
    best = ids[0]
    w = witness(LIN, S, best[1], best[2], best[3])
    print(f"\n  Testigo del mejor (R={best[1]}, a={best[2]}, b={best[3]}):")
    print(f"    Din={desc(w['din'])}  ->(a rondas)-> {desc(w['u'])} en s[R]")
    print(f"    Dout={desc(w['dout'])}  <-(b rondas)<- {desc(w['x'])} en s[R]   (u != x => imposible)")
    print(f"  ({time.time()-t0:.0f}s)")
    return S, ids

# =============================================================================
# extend : extension truncada
# =============================================================================
def count_bits(val, unk):
    U = sum(bin(x).count('1') for x in unk)
    O = sum(bin(v & ~u & M32).count('1') for v, u in zip(val, unk))
    return 256 - U - O, O, U

def cmd_extend(a, ids=None, S=None):
    print("="*70); print("EXTEND: extension truncada (bit a bit, cota conservadora)"); print("="*70)
    if ids is None:
        S = {r0: fwd_spaces(LIN, r0) for r0 in range(31)}; _, ids = exact_ids(LIN, S)
    best = ids[0]; w = witness(LIN, S, best[1], best[2], best[3])
    Rabs = best[1] + 31; rs = Rabs - best[2]; re = Rabs + best[3]
    print(f"  testigo total={best[0]}: Din={desc(w['din'])} en s[{rs}], Dout={desc(w['dout'])} en s[{re}]")
    print("  columnas: (bits=0 conocidos, bits=1 conocidos, bits desconocidos) sobre 256")
    val, unk = list(w['din']), [0]*8
    print("  hacia plaintext (cada ronda extra delante):")
    for e in range(0, 7):
        z, o, u = count_bits(val, unk)
        print(f"    +{e} rondas: ({z:3d},{o:3d},{u:3d})   <- diferencias de entrada posibles: 2^{u}")
        val, unk = LIN.bwd_trunc(val, unk, rs - 1 - e)
    val, unk = list(w['dout']), [0]*8
    print("  hacia ciphertext (cada ronda extra detras):")
    for e in range(0, 7):
        z, o, u = count_bits(val, unk)
        print(f"    +{e} rondas: ({z:3d},{o:3d},{u:3d})")
        val, unk = LIN.fwd_trunc(val, unk, re + e)
    print("  Lectura: si u=256 tras +1 ronda, no hay extension util (el filtro de claves no")
    print("  restringe nada); es el numero que decide si el imposible sirve para recuperar clave.")

# =============================================================================
# real : premisas contra el cifrado
# =============================================================================
def diff(x, y): return [p ^ q for p, q in zip(x, y)]

def verify_witness(wit, keys, npairs, seed=5):
    Rabs = wit['R'] + 31; rs = Rabs - wit['a']; re = Rabs + wit['b']
    rnd = random.Random(seed)
    tot = {'fwd': 0, 'bwd': 0, 'bwd_dec': 0, 'span_mid': 0, 'span_hit': 0}; n = 0
    for name, key in keys:
        rks, _ = key_schedule(key)
        for _ in range(npairs):
            n += 1
            P = [rnd.getrandbits(32) for _ in range(8)]
            # premisa 1: a rondas hacia delante, Din -> u (100%)
            s1, s2 = list(P), [P[i] ^ wit['din'][i] for i in range(8)]
            mids = None
            for r in range(rs, Rabs):
                s1 = round_enc(s1, rks[r], r); s2 = round_enc(s2, rks[r], r)
            if diff(s1, s2) == wit['u']: tot['fwd'] += 1
            # premisa 2: b rondas hacia delante desde x -> Dout (100%)
            s1, s2 = list(P), [P[i] ^ wit['x'][i] for i in range(8)]
            for r in range(Rabs, re):
                s1 = round_enc(s1, rks[r], r); s2 = round_enc(s2, rks[r], r)
            if diff(s1, s2) == wit['dout']: tot['bwd'] += 1
            # premisa 2 por el camino inverso: Dout en s[re] -> x en s[Rabs] (100%)
            c1, c2 = list(P), [P[i] ^ wit['dout'][i] for i in range(8)]
            for r in range(re - 1, Rabs - 1, -1):
                c1 = round_dec(c1, rks[r], r); c2 = round_dec(c2, rks[r], r)
            if diff(c1, c2) == wit['x']: tot['bwd_dec'] += 1
            # tramo completo: Din -> Dout debe NO ocurrir
            s1, s2 = list(P), [P[i] ^ wit['din'][i] for i in range(8)]
            for r in range(rs, re):
                s1 = round_enc(s1, rks[r], r); s2 = round_enc(s2, rks[r], r)
                if r == Rabs - 1 and diff(s1, s2) == wit['u']: tot['span_mid'] += 1
            if diff(s1, s2) == wit['dout']: tot['span_hit'] += 1
    return tot, n

def cmd_real(a, ids=None, S=None):
    print("="*70); print("REAL: premisas del argumento contra la ronda real (SPEC)"); print("="*70)
    if ids is None:
        S = {r0: fwd_spaces(LIN, r0) for r0 in range(31)}; _, ids = exact_ids(LIN, S)
    keys = [("key=0", bytes(64)), ("key=ff", b'\xff'*64)] + \
           [(f"rand{s}", rand_key(s)) for s in (11, 12, 13, 14)]
    picks = [ids[0]]
    for t in ids[1:]:
        if t[0] < ids[0][0]: picks.append(t); break
    picks.append(next(t for t in ids if t[0] == 15))
    print("  PREMISAS (deben dar n/n): fwd=Din->u ; bwd=x->Dout ; bwd_dec=Dout->x por round_dec ;")
    print("  span_mid = el estado intermedio observado en el cifrado real es u ;")
    print("  span_hit = hits del diferencial imposible completo (esperado 0, SOLO sanity: p=2^-256).")
    allok = True
    for t in picks:
        wit = witness(LIN, S, t[1], t[2], t[3])
        tot, n = verify_witness(wit, keys, a.pairs)
        ok = all(tot[k] == n for k in ('fwd', 'bwd', 'bwd_dec', 'span_mid')) and tot['span_hit'] == 0
        allok &= ok
        print(f"  total={t[0]} R={t[1]} a={t[2]} b={t[3]}: n={n}  " +
              "  ".join(f"{k}={v}" for k, v in tot.items()) + ("   OK" if ok else "   FALLO"))
    print("  => " + ("premisas confirmadas: el imposible se sigue por argumento estructural"
                     if allok else "ALGUN FALLO: revisar (el argumento NO queda probado)"))

# =============================================================================
# design : ¿es Myszkowski/31 especial?
# =============================================================================
def design_stats(lin):
    S = {r0: fwd_spaces(lin, r0) for r0 in range(lin.period)}
    m, ids = exact_ids(lin, S)
    return max(m.values()), (ids[0][0] if ids else 0)

def cmd_design(a):
    print("="*70); print("DESIGN: Myszkowski/31 vs permutaciones y calendarios de rotacion alternativos"); print("="*70)
    t0 = time.time()
    mm, mi = design_stats(LIN)
    print(f"  MYZ_PERM, periodo 31 : max cadena peso0 = {mm},  mejor imposible exacto = {mi}")
    for st in (2, 3, 5, 7):   # calendario de rotacion alternativo: shift=(st*r mod 31)+1
        mm, mi = design_stats(Lin(MYZ_PERM, 31, st))
        print(f"  MYZ_PERM, shift=({st}*r mod 31)+1 : max cadena = {mm},  mejor imposible = {mi}")
    rows = []
    rng = random.Random(2026)
    for i in range(a.perms):
        p = list(range(32)); rng.shuffle(p)
        mm, mi = design_stats(Lin(p, 31)); rows.append((mm, mi))
        print(f"  perm aleatoria #{i:2d}, periodo 31: max cadena = {mm:2d},  mejor imposible = {mi}")
    if rows:
        print(f"  aleatorias: max cadena media {sum(r[0] for r in rows)/len(rows):.1f} "
              f"(rango {min(r[0] for r in rows)}-{max(r[0] for r in rows)}), "
              f"imposible medio {sum(r[1] for r in rows)/len(rows):.1f} "
              f"(rango {min(r[1] for r in rows)}-{max(r[1] for r in rows)})")
    print("  Si MYSX queda cerca de la media aleatoria, NO hay base para afirmar que Myszkowski")
    print("  tenga 'efecto estructural' sobre estos imposibles. Si queda lejos, si lo hay.")
    print(f"  ({time.time()-t0:.0f}s)")

# =============================================================================
# kat
# =============================================================================
def cmd_kat(a):
    if ROT_CAL is not None:
        print('='*70); print('KAT skipped: MYSX_ROT_CAL set, KAT.json is for k=1'); print('='*70)
        return
    print("="*70); print("KAT: conformidad de esta reimplementacion con KAT.json"); print("="*70)
    path = a.kat or "KAT.json"
    if not os.path.exists(path):
        print(f"  no existe {path}; usa --kat RUTA"); return
    kat = json.load(open(path)); ent = kat.get('block', [])
    ok = 0
    for i, e in enumerate(ent):
        key = bytes.fromhex(e['key']); pt = bytes.fromhex(e['plaintext'])
        rks, fin = key_schedule(key)
        s = [int.from_bytes(pt[4*j:4*j+4], 'big') for j in range(8)]
        for r in range(128): s = round_enc(s, rks[r], r)
        s = [s[j] ^ fin[j] for j in range(8)]
        ct = b''.join(w.to_bytes(4, 'big') for w in s)
        good = ct == bytes.fromhex(e['ciphertext']); ok += good
        print(f"  block #{i}: {'OK' if good else 'MISMATCH'}")
    print(f"  => {ok}/{len(ent)}")

# =============================================================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('cmd', nargs='?', default='all')
    ap.add_argument('--pairs', type=int, default=2000)
    ap.add_argument('--perms', type=int, default=12)
    ap.add_argument('--kat', default=None)
    a = ap.parse_args()
    t0 = time.time()
    if a.cmd in ('all', 'selfcheck'): cmd_selfcheck(a)
    if a.cmd in ('all', 'sb'): cmd_sb(a)
    S = ids = None
    if a.cmd in ('all', 'exact'): S, ids = cmd_exact(a)
    if a.cmd in ('all', 'extend'): cmd_extend(a, ids, S)
    if a.cmd in ('all', 'real'): cmd_real(a, ids, S)
    if a.cmd == 'design': cmd_design(a)
    if a.cmd == 'kat': cmd_kat(a)
    print(f"\nTiempo total: {time.time()-t0:.0f}s")

if __name__ == '__main__':
    main()