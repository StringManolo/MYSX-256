#!/usr/bin/env python3
"""
dmitm_extra.py — Tests adicionales para el imposible de MYSX.

  T1  Cross-language KAT: Python round_enc vs mysx.prod.js
  T2  Tercera geografía: R=20 (r0=10, r_end=24)
  T3  Multi-seed: 16 × 16384 = 262144 pares
  T4  Densidad: cuántas forward chains chocan con w1b31 @ s[10]

Uso: python3 cryptanalysis/DMITM/dmitm_extra.py [all|t1|t2|t3|t4]
"""
import sys, os, json, random, time, subprocess, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dmitm_impossible import single_bit, build_chains
from dmitm_doubts import (
    _LIN_OK, key_schedule, round_enc, rand_key,
    verify_impossible, rebuild_candidates,
)


# =============================================================================
# T1 — Cross-language KAT check
# =============================================================================
def t1_kat():
    print("=" * 60)
    print("T1 — Cross-language KAT: Python vs mysx.prod.js")
    print("=" * 60)
    if not _LIN_OK:
        print("  OMITIDO:", _LIN_OK)
        return
    _here = os.path.dirname(os.path.abspath(__file__))
    kat_path = os.path.abspath(os.path.join(_here, '..', '..', 'KAT.json'))
    if not os.path.exists(kat_path):
        print(f"  KAT.json no encontrado en {kat_path}")
        return
    with open(kat_path) as f:
        kat = json.load(f)
    entries = kat.get('block', [])[:4]  # 4 entradas de bloque
    print(f"  {len(entries)} vectores de bloque a comprobar")
    ok = 0
    for i, e in enumerate(entries):
        key = bytes.fromhex(e['key'])
        pt  = bytes.fromhex(e['plaintext'])
        ct_expected = bytes.fromhex(e['ciphertext'])
        rks, rkFinal = key_schedule(key)
        s = [(pt[4*j] << 24) | (pt[4*j+1] << 16) |
             (pt[4*j+2] << 8) | pt[4*j+3] for j in range(8)]
        for r in range(128):
            s = round_enc(s, rks[r], r)
        s = [s[j] ^ rkFinal[j] for j in range(8)]
        ct = bytes()
        for w in s:
            ct += w.to_bytes(4, 'big')
        match = ct == ct_expected
        if match: ok += 1
        print(f"  KAT block #{i}: {'OK' if match else 'MISMATCH'}")
        if not match:
            print(f"    expected {ct_expected.hex()}")
            print(f"    got      {ct.hex()}")
    print(f"  → {ok}/{len(entries)} OK\n")
    return ok == len(entries)


# =============================================================================
# T2 — Tercera geografía (R=20)
# =============================================================================
def t2_r20():
    print("=" * 60)
    print("T2 — Tercera geografía: R=20 (r0=10, r_end=24)")
    print("=" * 60)
    if not _LIN_OK:
        print("  OMITIDO:", _LIN_OK)
        return
    results = rebuild_candidates()
    cands = [c for c in results if c['R'] == 20 and c['total'] == 14]
    if not cands:
        print("  No hay candidatos R=20 total=14")
        return
    c = cands[0]
    f, g = c['fwd'], c['bwd']
    print(f"  fwd: r1={f[0]} w{f[1]}b{f[2]} len={f[4]}")
    print(f"  bwd: r2={g[0]} w{g[1]}b{g[2]} len={g[4]}")
    print(f"  diff_words={c['diff_words']}")
    verify_impossible(c, n_keys=4, n_pairs=1 << 14, label="T2")


# =============================================================================
# T3 — Multi-seed
# =============================================================================
def t3_multiseed():
    print("=" * 60)
    print("T3 — Multi-seed: 16 × 16384 = 262144 pares")
    print("=" * 60)
    if not _LIN_OK:
        print("  OMITIDO:", _LIN_OK)
        return
    results = rebuild_candidates()
    c = next(x for x in results if x['R'] == 11 and x['total'] == 15
             and set(x['diff_words']) == {0, 5})
    print(f"  Candidato: R={c['R']} total={c['total']} diff_words={c['diff_words']}")
    total_hits = total_pairs = 0
    for seed in range(1, 17):
        hits, tot = verify_impossible(c, n_keys=1, n_pairs=16384,
                                      seed=seed * 1000, label=f"  seed {seed}")
        total_hits += hits
        total_pairs += tot
    print(f"  TOTAL: {total_hits}/{total_pairs} "
          f"{'✓ CONFIRMADO' if total_hits == 0 else '✗ FALLO'}")


# =============================================================================
# T4 — Densidad: cuántas forward chains chocan con w1b31 @ s[10]
# =============================================================================
def t4_density():
    print("=" * 60)
    print("T4 — Densidad del conflicto en s[10]")
    print("=" * 60)
    fwd, bwd = build_chains(min_len=2)
    # Estado objetivo: w1b31 en s[10]
    target = [0] * 8
    target[1] = 1 << 31
    target = tuple(target)
    # Forward chains que llegan a s[10] con estado != target
    conflicts = []
    for (r1, w, b), traj in fwd.items():
        for R, st in traj:
            if R == 10 and st != target:
                conflicts.append((r1, w, b, st))
                break
    print(f"  Forward chains que llegan a s[10] con estado != w1b31: {len(conflicts)}")
    # Distribución por r1
    from collections import Counter
    by_r1 = Counter(r1 for r1, _, _, _ in conflicts)
    print(f"  Distribución por r1:")
    for r1 in sorted(by_r1):
        print(f"    r1={r1:2d}: {by_r1[r1]:2d} chains")
    # ¿Cuántas backward chains llegan a s[10]?
    bwd_count = sum(1 for (_, _, _), traj in bwd.items()
                    if any(R == 10 for R, _ in traj))
    print(f"  Backward chains que llegan a s[10]: {bwd_count}")
    print(f"\n  Interpretación:")
    print(f"    - {len(conflicts)} forward chains conflictúan con w1b31 @ s[10]")
    print(f"    - La backward chain de w1b5 @ r_end=22 es UNA de {bwd_count}")
    print(f"    - Todas estas {len(conflicts)} forward chains son imposibles")
    print(f"      con la backward elegida → el conflicto es DENSO, no aislado.")


# =============================================================================
# Main
# =============================================================================
def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'all'
    t0 = time.time()
    if mode in ('all', 't1'): t1_kat()
    if mode in ('all', 't2'): t2_r20()
    if mode in ('all', 't3'): t3_multiseed()
    if mode in ('all', 't4'): t4_density()
    print(f"\nTiempo total: {time.time() - t0:.1f}s")


if __name__ == '__main__':
    main()
