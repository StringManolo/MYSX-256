#!/usr/bin/env python3
"""
dmitm_impossible.py — Búsqueda de diferenciales imposibles en MYSX-256/512
por miss-in-the-middle sobre cadenas diferenciales de peso 0.

Estructura:
  TEST 1: lin_fwd / lin_bwd son inversas
  PASO 2: reproducir tabla §3.5 del paper (forward)
  PASO 3: tabla de cadenas inversas (NUEVO, no está en el paper)
  PASO 4: buscar cruces forward×backward con estado incompatible
  PASO 5: verificar empíricamente el mejor candidato contra el cifrado real

Requiere (solo para PASO 5):
  cryptanalysis/models/linear/mysx_linear_model.py
"""

import sys, os, random
from collections import defaultdict

# =============================================================================
# Carga del modelo lineal del cifrado (para el PASO 5)
# =============================================================================
_LIN_MODEL_AVAILABLE = False
_IMPORT_ERROR = None
try:
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    _repo_root  = os.path.abspath(os.path.join(_script_dir, '..', '..'))
    _lin_path   = os.path.join(_repo_root, 'cryptanalysis', 'models', 'linear')
    if os.path.isdir(_lin_path):
        sys.path.insert(0, _lin_path)
    sys.path.insert(0, os.path.normpath('cryptanalysis/models/linear'))
    from mysx_linear_model import key_schedule, round_enc, rand_key
    _LIN_MODEL_AVAILABLE = True
except Exception as e:
    _IMPORT_ERROR = str(e)


# =============================================================================
# Primitivas: capa lineal directa e inversa
# =============================================================================
MYZ_PERM = [4,12,20,28, 0,8,16,24, 5,13,21,29,
            2,7,10,15,18,23,26,31, 6,14,22,30,
            1,9,17,25, 3,11,19,27]


import os as _os
_ROT_CAL_STR = _os.environ.get('MYSX_ROT_CAL', '')
if _ROT_CAL_STR:
    ROT_CAL = [int(x) for x in _ROT_CAL_STR.split(',')]
    assert len(ROT_CAL) == 31, f"MYSX_ROT_CAL: 31 valores, tiene {len(ROT_CAL)}"
    assert sorted(ROT_CAL) == list(range(1, 32)), "MYSX_ROT_CAL: permutación de 1..31"
else:
    ROT_CAL = None

def shift_at(r):
    return ROT_CAL[r % 31] if ROT_CAL else ((r % 31) + 1)

def rotl(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def rotr(x, n):
    return rotl(x, (32 - n) % 32)


def words_to_bytes(ws):
    b = []
    for w in ws:
        b += [(w >> 24) & 0xFF, (w >> 16) & 0xFF, (w >> 8) & 0xFF, w & 0xFF]
    return b


def bytes_to_words(bs):
    return [(bs[4 * i] << 24) | (bs[4 * i + 1] << 16) |
            (bs[4 * i + 2] << 8) | bs[4 * i + 3] for i in range(8)]


def lin_fwd(s, r):
    """Transposición Myszkowski + rotación. s = estado s_mid."""
    bytes_ = words_to_bytes(s)
    permuted = [bytes_[MYZ_PERM[j]] for j in range(32)]
    s_perm = bytes_to_words(permuted)
    shift = shift_at(r)
    return [rotl(s_perm[i], shift) for i in range(8)]


def lin_bwd(s, r):
    """Inversa: rotación inversa + transposición inversa. s = estado s[r+1]."""
    shift = shift_at(r)
    unrot = [rotr(s[i], shift) for i in range(8)]
    bytes_ = words_to_bytes(unrot)
    unperm = [0] * 32
    for j in range(32):
        unperm[MYZ_PERM[j]] = bytes_[j]
    return bytes_to_words(unperm)


# =============================================================================
# Cadenas de peso 0 (una ronda peso-0 es la capa lineal pura)
# =============================================================================
def fwd_step(state, r):
    """Δs[r] (words 4-7 == 0) -> Δs[r+1]. None si la cadena se rompe."""
    if any(state[4:8]):
        return None
    mid = (0, 0, 0, 0, state[0], state[1], state[2], state[3])
    return tuple(lin_fwd(mid, r))


def bwd_step(state, r):
    """Δs[r+1] -> Δs[r] si la ronda r es peso-0, si no None."""
    n = lin_bwd(state, r)
    if any(n[0:4]):
        return None
    return (n[4], n[5], n[6], n[7], 0, 0, 0, 0)


def single_bit(word, bit):
    m = [0] * 8
    m[word] = 1 << bit
    return tuple(m)


# =============================================================================
# TEST 1 — lin_fwd / lin_bwd son inversas
# =============================================================================
def test_lin_inverse():
    print("=" * 60)
    print("TEST 1 — lin_fwd / lin_bwd son inversas")
    print("=" * 60)
    rng = random.Random(1)
    for r in range(128):
        for _ in range(1000):
            s = [rng.getrandbits(32) for _ in range(8)]
            assert lin_bwd(lin_fwd(s, r), r) == s, f"fallo r={r}"
    print("  OK: 128 rondas × 1000 estados, todos invertibles\n")


# =============================================================================
# PASO 2 — Tabla forward §3.5
# =============================================================================
def fwd_chain_length(m, r0, max_rounds=128):
    state = tuple(m)
    k = 0
    while k < max_rounds:
        if any(state[4:8]):
            break
        nxt = fwd_step(state, r0 + k)
        if nxt is None:
            break
        state = nxt
        k += 1
    return k


# Valores exactos de §3.5 del paper. Los offsets 19-26 y 30 no están
# tabulados en el paper; se marcan como "?" y no se comprueban.
_EXPECTED_FWD = {
    0: 3, 1: 3, 2: 3, 3: 3, 4: 3, 5: 3, 6: 3,
    10: 13, 11: 12, 12: 11, 13: 10, 14: 9,
    15: 8, 16: 7, 17: 6, 18: 5,
    27: 3, 28: 3, 29: 3,
}


def step2():
    print("=" * 60)
    print("PASO 2 — Tabla §3.5 del paper (forward)")
    print("=" * 60)
    print(f"{'r0':>3} | {'max_rounds':>10} | {'esperado':>8} | status")
    print("-" * 40)
    all_ok = True
    for r0 in range(31):
        best = max(fwd_chain_length(single_bit(w, b), r0)
                   for w in range(4) for b in range(32))
        exp = _EXPECTED_FWD.get(r0)
        if exp is None:
            status = "(no tabulado)"
        elif exp == best:
            status = "OK"
        else:
            status = f"MISMATCH (esperado {exp})"
            all_ok = False
        print(f"{r0:>3} | {best:>10} | {str(exp):>8} | {status}")
    print()
    return all_ok


# =============================================================================
# PASO 3 — Tabla inversa
# =============================================================================
def bwd_chain_length(m_end, r_end, max_rounds=128):
    state = tuple(m_end)
    k = 0
    r = r_end - 1
    while k < max_rounds and r >= 0:
        nxt = bwd_step(state, r)
        if nxt is None:
            break
        state = nxt
        k += 1
        r -= 1
    return k


def step3():
    print("=" * 60)
    print("PASO 3 — Tabla de cadenas inversas (NUEVO)")
    print("=" * 60)
    print(f"{'r_end':>5} | {'max_rounds':>10} | ejemplo")
    print("-" * 40)
    results = []
    for r_end in range(1, 128):
        best, bi = 0, None
        for w in range(4):
            for b in range(32):
                k = bwd_chain_length(single_bit(w, b), r_end)
                if k > best:
                    best, bi = k, (w, b)
        if best >= 5:
            results.append((r_end, best, bi))
            print(f"{r_end:>5} | {best:>10} | w{bi[0]}b{bi[1]}")
    print()
    return results


# =============================================================================
# PASO 4 — Miss-in-the-middle
# =============================================================================
def build_chains(min_len=4):
    fwd, bwd = {}, {}
    for r1 in range(128):
        for w in range(4):
            for b in range(32):
                traj = [(r1, single_bit(w, b))]
                state = single_bit(w, b)
                for k in range(1, 128 - r1 + 1):
                    if any(state[4:8]):
                        break
                    state = fwd_step(state, r1 + k - 1)
                    if state is None:
                        break
                    traj.append((r1 + k, state))
                if len(traj) - 1 >= min_len:
                    fwd[(r1, w, b)] = traj
    for r2 in range(1, 128):
        for w in range(4):
            for b in range(32):
                traj = [(r2, single_bit(w, b))]
                state = single_bit(w, b)
                r = r2 - 1
                while r >= 0:
                    state = bwd_step(state, r)
                    if state is None:
                        break
                    traj.append((r, state))
                    r -= 1
                if len(traj) - 1 >= min_len:
                    bwd[(r2, w, b)] = traj
    return fwd, bwd


def step4(fwd, bwd, min_total=12):
    print("=" * 60)
    print("PASO 4 — Miss-in-the-middle")
    print("=" * 60)
    print(f"  forward: {len(fwd)} cadenas")
    print(f"  backward: {len(bwd)} cadenas")

    fwd_at = defaultdict(list)
    bwd_at = defaultdict(list)
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
                total = f[4] + g[4]
                if total < min_total:
                    continue
                if f[3] != g[3]:
                    diff_words = [i for i in range(8) if f[3][i] != g[3][i]]
                    results.append({
                        'R': R, 'total': total,
                        'fwd': f, 'bwd': g,
                        'diff_words': diff_words,
                    })
    results.sort(key=lambda x: -x['total'])

    print(f"\n  {len(results)} candidatos con total >= {min_total} rondas\n")
    print(f"  {'R':>3} {'total':>5}  {'fwd (r1,Δ,len)':<22}  "
          f"{'bwd (r2,Δ,len)':<22}  diff_words")
    print("  " + "-" * 80)
    for x in results[:15]:
        f, g = x['fwd'], x['bwd']
        fwd_s = f"r{f[0]} w{f[1]}b{f[2]} len={f[4]}"
        bwd_s = f"r{g[0]} w{g[1]}b{g[2]} len={g[4]}"
        print(f"  {x['R']:>3} {x['total']:>5}  {fwd_s:<22}  {bwd_s:<22}  {x['diff_words']}")
    print()
    return results


# =============================================================================
# PASO 5 — Verificación empírica contra el cifrado real
# =============================================================================
def verify_impossible(candidate, n_keys=4, n_pairs=1 << 14, seed=1):
    """
    Comprueba que ningún par con Δs[r1] = w_fwd_b produce Δs[r2] = w_bwd_b.
    Devuelve (hits, total).
    """
    r1, w1, b1 = candidate['fwd'][0], candidate['fwd'][1], candidate['fwd'][2]
    r2, w2, b2 = candidate['bwd'][0], candidate['bwd'][1], candidate['bwd'][2]
    d_in  = list(single_bit(w1, b1))
    d_out = list(single_bit(w2, b2))

    rnd = random.Random(seed)
    hits = 0
    total = 0
    for k in range(n_keys):
        rks, _ = key_schedule(rand_key(seed + k))
        key_hits = 0
        for _ in range(n_pairs):
            P  = [rnd.getrandbits(32) for _ in range(8)]
            P2 = [P[i] ^ d_in[i] for i in range(8)]
            s1, s2 = list(P), list(P2)
            for r in range(r1, r2):
                s1 = round_enc(s1, rks[r], r)
                s2 = round_enc(s2, rks[r], r)
            if tuple(s1[i] ^ s2[i] for i in range(8)) == tuple(d_out):
                key_hits += 1
                hits += 1
            total += 1
        print(f"    key {k+1}/{n_keys}: {key_hits}/{n_pairs} hits")
    return hits, total


def step5(results):
    print("=" * 60)
    print("PASO 5 — Verificación empírica contra el cifrado real")
    print("=" * 60)
    if not _LIN_MODEL_AVAILABLE:
        print(f"  OMITIDO: mysx_linear_model no disponible ({_IMPORT_ERROR})")
        print("  Ejecuta este fichero desde /root/MYSX-256 o instala las deps.\n")
        return None

    if not results:
        print("  No hay candidatos que verificar.\n")
        return None

    # Buscar el mejor candidato con total == 15 (o el primero si no hay)
    target = next((c for c in results if c['total'] == 15), results[0])
    f, g = target['fwd'], target['bwd']
    print(f"  Candidato: R={target['R']} total={target['total']} rondas")
    print(f"    fwd: r1={f[0]} Δ=w{f[1]}b{f[2]} len={f[4]}")
    print(f"    bwd: r2={g[0]} Δ=w{g[1]}b{g[2]} len={g[4]}")
    print(f"    palabras con Δ incompatible: {target['diff_words']}")
    print(f"  Verificando sobre {4 * (1 << 14)} pares...\n")

    hits, total = verify_impossible(target, n_keys=4, n_pairs=1 << 14)
    print()
    if hits == 0:
        print(f"  RESULTADO: {hits}/{total} hits")
        print("  ✓ Diferencial imposible CONFIRMADO sobre el cifrado real.")
    else:
        print(f"  RESULTADO: {hits}/{total} hits (esperado 0)")
        print("  ✗ FALLO: el modelo lineal no capta la no-linealidad para")
        print("    esta combinación concreta. Investiga.")
    print()
    return hits, total


# =============================================================================
# MAIN
# =============================================================================
if __name__ == '__main__':
    test_lin_inverse()
    step2_ok = step2()
    if not step2_ok:
        print("AVISO: el paso 2 tuvo MISMATCH. Revisa antes de fiarte del paso 4.\n")
    step3()
    fwd, bwd = build_chains(min_len=4)
    results = step4(fwd, bwd, min_total=12)
    step5(results)
    print("=" * 60)
    print("FIN")
    print("=" * 60)
