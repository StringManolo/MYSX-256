#!/usr/bin/env python3
"""
dmitm_doubts.py — Cierra las dudas abiertas del análisis imposible de MYSX.

  Q1   Subir muestra del R=10 a 2^15 × 8 (estándar del paper §3.5)
  Q2   Verificar cadenas individuales (forward 13r, backward 12r) contra cifrado real
  Q3   Trazar el conflicto de la palabra incompatible, bit a bit
  Q4   Verificar R=11 con diff_words=[0,5] (2 palabras incompatibles)
  Q10  Deduplicar candidatos por período 31 (repeticiones de la misma cadena)
  EXTRA Multi-bit: pares adyacentes en forward/backward

Uso: python3 cryptanalysis/DMITM/dmitm_doubts.py [all|q1|q2|q3|q4|dedup|multi|test]
"""
import sys, os, random, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dmitm_impossible import (
    rotl, rotr, words_to_bytes, bytes_to_words,
    lin_fwd, lin_bwd, fwd_step, bwd_step, single_bit,
    build_chains, fwd_chain_length, bwd_chain_length,
    MYZ_PERM,
)

# --- Import del modelo lineal del cifrado ---
_LIN_OK = False
_LIN_ERR = None
try:
    _here = os.path.dirname(os.path.abspath(__file__))
    _repo = os.path.abspath(os.path.join(_here, '..', '..'))
    sys.path.insert(0, os.path.join(_repo, 'cryptanalysis', 'models', 'linear'))
    sys.path.insert(0, os.path.normpath('cryptanalysis/models/linear'))
    from mysx_linear_model import key_schedule, round_enc, rand_key
    _LIN_OK = True
except Exception as e:
    _LIN_ERR = str(e)

# Muestras: PAPER = igual que §3.5; FAST = 4× más rápido
PAPER_KEYS, PAPER_PAIRS = 8, 1 << 15      # 262144 pares totales
FAST_KEYS,  FAST_PAIRS  = 4, 1 << 14      # 65536 pares totales


# =============================================================================
# Ronda inversa (inversa exacta de round_enc, SPEC §7)
# =============================================================================
def simonF(x):
    return (rotl(x, 1) & rotl(x, 8)) ^ rotl(x, 2)


def round_dec(s, rk, r):
    """Inversa de round_enc: rot⁻¹ → transp⁻¹ → feistel⁻¹ → addkey⁻¹."""
    shift = (r % 31) + 1
    s = [rotr(s[i], shift) for i in range(8)]
    bs = words_to_bytes(s)
    unperm = [0] * 32
    for j in range(32):
        unperm[MYZ_PERM[j]] = bs[j]
    s = bytes_to_words(unperm)
    for p in range(4):
        R = s[p]
        L = s[p + 4] ^ simonF(R)
        s[p] = L
        s[p + 4] = R
    s = [s[i] ^ rk[i] for i in range(8)]
    return s


def test_round_dec():
    print("TEST — round_dec es inversa de round_enc")
    if not _LIN_OK:
        print(f"  OMITIDO: {_LIN_ERR}")
        return False
    rng = random.Random(7)
    for r in range(128):
        rks, _ = key_schedule(rand_key(r))
        for _ in range(200):
            s = [rng.getrandbits(32) for _ in range(8)]
            c = round_enc(list(s), rks[r], r)
            assert round_dec(list(c), rks[r], r) == s, f"fallo r={r}"
    print("  OK: 128 × 200 rondas invertibles")
    return True


# =============================================================================
# Verificación empírica de un imposible
# =============================================================================
def verify_impossible(c, n_keys, n_pairs, seed=1, label=""):
    r1, w1, b1 = c['fwd'][0], c['fwd'][1], c['fwd'][2]
    r2, w2, b2 = c['bwd'][0], c['bwd'][1], c['bwd'][2]
    d_in  = list(single_bit(w1, b1))
    d_out = list(single_bit(w2, b2))
    rnd = random.Random(seed)
    hits = total = 0
    t0 = time.time()
    for k in range(n_keys):
        rks, _ = key_schedule(rand_key(seed + k))
        kh = 0
        for _ in range(n_pairs):
            P  = [rnd.getrandbits(32) for _ in range(8)]
            P2 = [P[i] ^ d_in[i] for i in range(8)]
            s1, s2 = list(P), list(P2)
            for r in range(r1, r2):
                s1 = round_enc(s1, rks[r], r)
                s2 = round_enc(s2, rks[r], r)
            if tuple(s1[i] ^ s2[i] for i in range(8)) == tuple(d_out):
                kh += 1
            total += 1
        hits += kh
        print(f"    key {k+1}/{n_keys}: {kh}/{n_pairs}")
    print(f"  {label}: {hits}/{total} ({time.time()-t0:.1f}s) "
          f"{'✓ CONFIRMADO' if hits == 0 else '✗ FALLO'}")
    return hits, total


# =============================================================================
# Verificación de cadenas individuales (forward y backward)
# =============================================================================
def verify_fwd_chain(r_start, d_in, r_end, d_out, n_keys, n_pairs, seed=11):
    rnd = random.Random(seed)
    hits = total = 0
    for k in range(n_keys):
        rks, _ = key_schedule(rand_key(seed + 100 + k))
        for _ in range(n_pairs):
            P  = [rnd.getrandbits(32) for _ in range(8)]
            P2 = [P[i] ^ d_in[i] for i in range(8)]
            s1, s2 = list(P), list(P2)
            for r in range(r_start, r_end):
                s1 = round_enc(s1, rks[r], r)
                s2 = round_enc(s2, rks[r], r)
            if tuple(s1[i] ^ s2[i] for i in range(8)) == tuple(d_out):
                hits += 1
            total += 1
    return hits, total


def verify_bwd_chain(r_start, d_in, r_end, d_out, n_keys, n_pairs, seed=13):
    """Δs[r_end]=d_out ⇒ Δs[r_start]=d_in, moviéndose hacia atrás."""
    rnd = random.Random(seed)
    hits = total = 0
    for k in range(n_keys):
        rks, _ = key_schedule(rand_key(seed + 200 + k))
        for _ in range(n_pairs):
            P  = [rnd.getrandbits(32) for _ in range(8)]
            P2 = [P[i] ^ d_out[i] for i in range(8)]
            s1, s2 = list(P), list(P2)
            for r in range(r_end - 1, r_start - 1, -1):
                s1 = round_dec(s1, rks[r], r)
                s2 = round_dec(s2, rks[r], r)
            if tuple(s1[i] ^ s2[i] for i in range(8)) == tuple(d_in):
                hits += 1
            total += 1
    return hits, total


# =============================================================================
# Reconstrucción de candidatos (idéntica al paso 4 original, ordenada)
# =============================================================================
def rebuild_candidates():
    from collections import defaultdict
    fwd, bwd = build_chains(min_len=4)
    fwd_at = defaultdict(list); bwd_at = defaultdict(list)
    for (r1, w, b), traj in fwd.items():
        for R, st in traj:
            fwd_at[R].append((r1, w, b, st, R - r1))
    for (r2, w, b), traj in bwd.items():
        for R, st in traj:
            bwd_at[R].append((r2, w, b, st, r2 - R))
    results = []
    for R in range(128):
        for f in fwd_at[R]:
            for g in bwd_at[R]:
                if f[4] + g[4] < 12: continue
                if f[3] != g[3]:
                    dw = [i for i in range(8) if f[3][i] != g[3][i]]
                    results.append({'R': R, 'total': f[4]+g[4],
                                    'fwd': f, 'bwd': g, 'diff_words': dw})
    results.sort(key=lambda x: (-x['total'], -len(x['diff_words'])))
    return results


# =============================================================================
# Q3 — Trazar el conflicto bit a bit
# =============================================================================
def q3_trace(c):
    f, g = c['fwd'], c['bwd']
    print(f"\nCandidato R={c['R']} total={c['total']}")
    print(f"  fwd: r1={f[0]} Δ_in=w{f[1]}b{f[2]} len={f[4]}")
    print(f"  bwd: r2={g[0]} Δ_out=w{g[1]}b{g[2]} len={g[4]}")
    print(f"\n  Estados en s[R={c['R']}]:")
    print(f"  {'w':>2}  {'fwd(hex)':>10}  {'bwd(hex)':>10}  {'XOR':>10}  "
          f"{'bits fwd':>34}  {'bits bwd':>34}")
    for i in range(8):
        fv, gv = f[3][i], g[3][i]
        if fv != gv:
            fb = format(fv, '032b'); gb = format(gv, '032b')
            print(f"  {i:>2}  {fv:08x}  {gv:08x}  {fv^gv:08x}  {fb}  {gb}")
    # Bits activos en fwd y bwd (si uno es 0 y el otro no → contradicción exacta)
    print("\n  Contradicciones bit a bit (uno activo, el otro cero):")
    any_c = False
    for i in range(8):
        for bit in range(32):
            fb = (f[3][i] >> bit) & 1
            gb = (g[3][i] >> bit) & 1
            if fb != gb and (fb == 0 or gb == 0):
                tag = "fwd" if fb else "bwd"
                print(f"    w{i}b{bit}: activo en {tag}, cero en el otro")
                any_c = True
    if not any_c:
        print("    (ninguna — el conflicto es más sutil, ambos activos en distintos bits)")


# =============================================================================
# Q10 — Deduplicar por período 31
# =============================================================================
def q10_dedup(results):
    seen = {}
    for c in results:
        f, g = c['fwd'], c['bwd']
        key = (c['total'], f[0] % 31, f[1], f[2],
               g[0] % 31, g[1], g[2])
        if key not in seen:
            seen[key] = c
    return list(seen.values())


# =============================================================================
# Extra — Multi-bit (pares adyacentes en palabras 0-3)
# =============================================================================
def multi_bit_explore():
    best_fwd = (0, None)
    for r0 in range(31):
        for w in range(4):
            for b in range(32):
                for d in range(1, 8):
                    if b + d >= 32: continue
                    m = [0]*8; m[w] = (1 << b) | (1 << (b + d))
                    k = fwd_chain_length(tuple(m), r0)
                    if k > best_fwd[0]:
                        best_fwd = (k, (r0, w, b, d))
    print(f"  forward: mejor = {best_fwd[0]} rondas en {best_fwd[1]}")

    best_bwd = (0, None)
    for r_end in range(1, 128):
        for w in range(4):
            for b in range(32):
                for d in range(1, 8):
                    if b + d >= 32: continue
                    m = [0]*8; m[w] = (1 << b) | (1 << (b + d))
                    k = bwd_chain_length(tuple(m), r_end)
                    if k > best_bwd[0]:
                        best_bwd = (k, (r_end, w, b, d))
    print(f"  backward: mejor = {best_bwd[0]} rondas en {best_bwd[1]}")
    return best_fwd, best_bwd


# =============================================================================
# Main
# =============================================================================
def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'all'
    t0 = time.time()

    test_round_dec()

    if mode in ('all', 'q1', 'q2', 'q3', 'q4', 'dedup'):
        print("\nReconstruyendo candidatos...")
        results = rebuild_candidates()
        print(f"  {len(results)} candidatos, top: total={results[0]['total']}, "
              f"diff_words={results[0]['diff_words']}")

    if mode in ('all', 'q1'):
        if not _LIN_OK:
            print("OMITIDO Q1 (sin modelo lineal)")
        else:
            print("\n" + "="*60)
            print(f"Q1 — R=10 con muestra del paper ({PAPER_KEYS}×{PAPER_PAIRS})")
            print("="*60)
            c = next(x for x in results if x['R'] == 10 and x['total'] == 15)
            verify_impossible(c, PAPER_KEYS, PAPER_PAIRS, label="Q1")

    if mode in ('all', 'q3'):
        print("\n" + "="*60)
        print("Q3 — Trazado del conflicto (bit a bit)")
        print("="*60)
        c = next(x for x in results if x['R'] == 10 and x['total'] == 15)
        q3_trace(c)

    if mode in ('all', 'q4'):
        if not _LIN_OK:
            print("OMITIDO Q4 (sin modelo lineal)")
        else:
            print("\n" + "="*60)
            print("Q4 — R=11 con diff_words=[0,5] (2 palabras incompatibles)")
            print("="*60)
            c = next(x for x in results
                     if x['R'] == 11 and x['total'] == 15
                     and set(x['diff_words']) == {0, 5})
            verify_impossible(c, FAST_KEYS, FAST_PAIRS, label="Q4")

    if mode in ('all', 'q2'):
        if not _LIN_OK:
            print("OMITIDO Q2 (sin modelo lineal)")
        else:
            print("\n" + "="*60)
            print("Q2 — Verificar cadenas individuales")
            print("="*60)
            # Forward 13 rondas: r0=10, w1b31 → w4b12 (paper §3.5)
            din  = list(single_bit(1, 31))
            dout = list(single_bit(4, 12))
            h, t = verify_fwd_chain(10, din, 23, dout, FAST_KEYS, FAST_PAIRS)
            print(f"  forward 13r (r0=10):    {h}/{t}  {'✓' if h==t else '✗'}")
            # Backward 12 rondas: r_end=22, w1b5 → estado en r=10
            c10 = next(x for x in results if x['R'] == 10 and x['total'] == 15)
            g = c10['bwd']
            din_b  = list(single_bit(g[1], g[2]))   # w1b5
            dout_b = list(g[3])                       # estado en r=10
            h, t = verify_bwd_chain(10, dout_b, 22, din_b, FAST_KEYS, FAST_PAIRS)
            print(f"  backward 12r (r_end=22): {h}/{t}  {'✓' if h==t else '✗'}")

    if mode in ('all', 'dedup'):
        print("\n" + "="*60)
        print("Q10 — Candidatos deduplicados por período 31")
        print("="*60)
        dd = q10_dedup(results)
        print(f"  {len(results)} → {len(dd)} únicos\n")
        print(f"  {'R':>3} {'total':>5} {'diff_words':<14} fwd / bwd (mod 31)")
        print("  " + "-"*70)
        for c in dd[:20]:
            f, g = c['fwd'], c['bwd']
            print(f"  {c['R']:>3} {c['total']:>5} {str(c['diff_words']):<14} "
                  f"r{f[0]%31:2d} w{f[1]}b{f[2]:<2d}  /  "
                  f"r{g[0]%31:2d} w{g[1]}b{g[2]}")

    if mode in ('all', 'multi'):
        print("\n" + "="*60)
        print("EXTRA — Multi-bit (pares adyacentes en palabras 0-3)")
        print("="*60)
        multi_bit_explore()

    print(f"\nTiempo total: {time.time() - t0:.1f}s")


if __name__ == '__main__':
    main()
