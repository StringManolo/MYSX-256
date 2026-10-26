#!/usr/bin/env python3
"""
dmitm_trace.py — Traza w1b10 (forward) y w1b31 (backward) del diferencial
imposible de 15 rondas en MYSX-256/512, para argumentar estructuralmente
por qué no pueden coincidir en s[10].

Uso: python3 cryptanalysis/DMITM/dmitm_trace.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dmitm_impossible import rotl, rotr, words_to_bytes, bytes_to_words, MYZ_PERM


def unique_bit(state):
    """Devuelve (word, bit) del único bit activo, o None."""
    active = [(w, b) for w in range(8) for b in range(32) if (state[w] >> b) & 1]
    return active[0] if len(active) == 1 else None


def step_forward(state, r, verbose=True):
    """Una ronda forward: Feistel → Transpose → Rotl."""
    shift = (r % 31) + 1
    if verbose:
        print(f"\n  Ronda {r} (shift={shift}):")
    # Feistel (ΔR=0 → w0-3 a w4-7)
    mid = [0] * 8
    for i in range(4):
        mid[i + 4] = state[i]
    if verbose:
        p = unique_bit(mid); print(f"    {'Feistel:':<22s} w{p[0]}b{p[1]:2d}")
    # Transpose
    bs = words_to_bytes(mid)
    state = bytes_to_words([bs[MYZ_PERM[j]] for j in range(32)])
    if verbose:
        p = unique_bit(state); print(f"    {'Transpose:':<22s} w{p[0]}b{p[1]:2d}")
    # Rotl
    state = [rotl(state[i], shift) for i in range(8)]
    if verbose:
        p = unique_bit(state); print(f"    {f'Rotl({shift}):':<22s} w{p[0]}b{p[1]:2d}")
    return state


def step_backward(state, r, verbose=True):
    """Una ronda backward: Rotr → Transpose_inv → Feistel_inv."""
    shift = (r % 31) + 1
    if verbose:
        print(f"\n  Ronda {r} (shift={shift}):")
    # Rotr
    state = [rotr(state[i], shift) for i in range(8)]
    if verbose:
        p = unique_bit(state); print(f"    {f'Rotr({shift}):':<22s} w{p[0]}b{p[1]:2d}")
    # Transpose inv
    bs = words_to_bytes(state)
    unperm = [0] * 32
    for j in range(32):
        unperm[MYZ_PERM[j]] = bs[j]
    state = bytes_to_words(unperm)
    if verbose:
        p = unique_bit(state); print(f"    {'Transpose_inv:':<22s} w{p[0]}b{p[1]:2d}")
    # Feistel inv (necesita w0-3 == 0)
    if any(state[0:4]):
        if verbose: print("    BREAK: w0-3 activo")
        return None
    new = [0] * 8
    for i in range(4):
        new[i] = state[i + 4]
    if verbose:
        p = unique_bit(new); print(f"    {'Feistel_inv:':<22s} w{p[0]}b{p[1]:2d}")
    return new


def trace(w0, b0, r_start, n_rounds, direction, verbose=True):
    state = [0] * 8
    state[w0] = 1 << b0
    path = [(r_start, w0, b0)]
    print(f"\n{'=' * 60}")
    print(f"{direction.upper()}  s[{r_start}] w{w0}b{b0}  →  {n_rounds} rondas")
    print(f"{'=' * 60}")
    print(f"  s[{r_start}]: w{w0}b{b0}")
    for k in range(n_rounds):
        if direction == 'forward':
            r = r_start + k
            state = step_forward(state, r, verbose)
            new_r = r + 1
        else:
            r = r_start - 1 - k
            state = step_backward(state, r, verbose)
            new_r = r
        if state is None:
            break
        p = unique_bit(state)
        path.append((new_r, p[0], p[1]))
    return path


def main():
    # Forward: s[7] w0b31, 3 rondas → s[10] w1b10
    fwd = trace(0, 31, 7, 3, 'forward', verbose=True)
    # Backward: s[22] w1b5, 12 rondas → s[10] w1b31
    bwd = trace(1, 5, 22, 12, 'backward', verbose=True)

    print(f"\n{'=' * 60}")
    print("RESUMEN — trayectoria de los dos bits")
    print(f"{'=' * 60}")
    print(f"  {'s[r]':>6} | {'Forward':>12} | {'Backward':>12} | nota")
    print(f"  {'-' * 6}-+-{'-' * 12}-+-{'-' * 12}-+-{'-' * 25}")
    fwd_d = {r: (w, b) for r, w, b in fwd}
    bwd_d = {r: (w, b) for r, w, b in bwd}
    for r in sorted(set(fwd_d) | set(bwd_d)):
        f = f"w{fwd_d[r][0]}b{fwd_d[r][1]:2d}" if r in fwd_d else ""
        b = f"w{bwd_d[r][0]}b{bwd_d[r][1]:2d}" if r in bwd_d else ""
        if r == 7:     note = "← forward start"
        elif r == 10:  note = "← CONFLICTO (b10 vs b31)"
        elif r == 22:  note = "← backward start"
        else:          note = ""
        print(f"  {r:>6} | {f:>12} | {b:>12} | {note}")

    assert fwd[-1][1:] == (1, 10), f"forward inesperado: {fwd[-1]}"
    assert bwd[-1][1:] == (1, 31), f"backward inesperado: {bwd[-1]}"
    print(f"\n  ✓ Verificado: forward → w1b10, backward → w1b31 en s[10]")

    print(f"\n{'=' * 60}")
    print("ARGUMENTO DE DISEÑO")
    print(f"{'=' * 60}")
    print("""
  FORWARD (3 rondas, shifts 8, 9, 10):
    w0b31 → Feistel(w4b31) → Transpose(w1b15) → Rotl(8)  = w1b23
    w1b23 → Feistel(w5b23) → Transpose(w2b15) → Rotl(9)  = w2b24
    w2b24 → Feistel(w6b24) → Transpose(w1b0)  → Rotl(10) = w1b10

  BACKWARD (12 rondas, shifts 22, 21, ..., 11):
    Oscila por w4→w0→w5→w1→w6→w2→...→w1, terminando en w1b31.
    La traza detallada está arriba. Puntos clave:
      - ronda 21 (shift 22): w1b5  → w4b31  → w0b31  (s[21])
      - ronda 20 (shift 21): w0b31 → w5b26  → w1b26  (s[20])
      - ronda 19 (shift 20): w1b26 → w6b30  → w2b30  (s[19])
      - ... 9 rondas más ...
      - ronda 10 (shift 11): ... → w1b31 (s[10])

  POR QUÉ b10 vs b31:
    * Acumulación de rotaciones distinta en cada dirección:
        forward:  shifts 8+9+10 = 27  (3 transposes intermedias)
        backward: shifts 11+...+22 = 198 ≡ 6 (mod 32)  (12 transposes inv.)
    * Las transposiciones intermedias redirigen el bit a palabras distintas
      en cada paso (w0→w4→w1→w2→w6→w1 en forward; oscilación en backward).
    * El ciclo de longitud 19 de MYZ_PERM
      (1→12→2→20→6→16→18→26→17→23→30→19→31→27→25→9→13→7→24) hace que
      muchas trayectorias terminen en la palabra 1.
    * La composición final (shift+transpose) deja el bit forward en b10 y el
      backward en b31.

  POR QUÉ ES ESTRUCTURAL (no accidental):
    * MYSX usa el mismo schedule de rotación (period 31) en ambas direcciones.
      La contradicción no depende de una elección concreta de
      plaintext/ciphertext, sino de la asimetría entre 3 rondas forward
      (shifts 8,9,10) y 12 rondas backward (shifts 11..22).
    * El conflicto en la MISMA palabra (w1) hace el imposible "estrecho":
      solo 1 bit difiere entre las dos cadenas. Es más robusto que un
      conflicto en palabras distintas.
    * La F de Simon NO interviene en las cadenas de peso 0 (ΔR=0 ⇒ ΔF(R)=0).
      El resultado es una propiedad de Myszkowski + rotación de periodo 31,
      no de la no-linealidad.

  QUÉ CAMBIARÍA EL RESULTADO:
    * Otra permutación de bytes (e.g., una "óptima" para difusión, como
      sugiere §2.3.1 del paper) rompería las trayectorias.
    * Otro periodo de rotación (no 31) cambiaría la acumulación de shifts.
    * Más rondas forward antes de s[10] (e.g. r0=6 en vez de 7) cambiarían
      la cadena. De hecho, r0=7 es el ÚNICO offset que da 3 rondas forward
      llegando a R=10; cualquier otro r0 da menos o llega a otro R.
""")


if __name__ == '__main__':
    main()
