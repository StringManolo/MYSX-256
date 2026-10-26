#!/usr/bin/env python3
"""
mysx_milp.py -- Búsqueda de trails diferenciales por MILP para MYSX-256/512.

Requiere:  pip install pulp
Opcional:  pip install gurobipy  (mucho más rápido para 6+ rondas)

Uso:
    python3 mysx_milp.py --validate
    python3 mysx_milp.py --rounds 4 --input-bit 0 --trail
    python3 mysx_milp.py --rounds 1-8 --input-bit 0
    python3 mysx_milp.py --rounds 4 --all-inputs
    python3 mysx_milp.py --rounds 12-14 --input-bit 94 --solver gurobi --trail
    python3 mysx_milp.py --rounds 14 --input-bit 94 --cutoff 128
    python3 mysx_milp.py --rounds 14 --input-bit 94 --cutoff 128 --solver gurobi
    python3 mysx_milp.py --rounds 14 --input-bit 94 --r0 15 --solver cbc

Modos:
    --rounds N | A-B     Rondas (una o rango)
    --input-bit K        Bit de entrada (0-255): i*32 + j
    --input-bits L       Lista: '56,94'
    --all-inputs         Barre los 256 bits (lento; usa gapRel para acelerar)
    --r0 K               Offset de rotación: la ronda local r usa
                         shift = ((r + r0) mod 31) + 1.  Con --r0 0 el
                         resultado es idéntico al de versiones anteriores.
                         El trail modelado cubre las rondas del cifrador
                         K .. K+rounds-1 (si K+rounds > 128, el trail es
                         virtual: las shifts de las rondas >127 no
                         aparecen en el cifrador).
    --trail              Imprime el trail de cada ronda
    --cutoff W           Solo factibilidad: ¿existe trail con peso <= W?
    --solver cbc|gurobi  Solver (default cbc)
    --gap-rel G          gapRel para CBC/Gurobi (default 0.2)
    --time-limit S       segundos por solve (default 300)
    --threads T          hilos para CBC (default 4)

Interpretación:
    peso = nº de ANDs con al menos un input diferenciado.
    Probabilidad del trail ≈ 2^(-peso).
    peso=0 ⇒ trail determinista (distinguidor de prob. 1).
    Crecimiento ~lineal con rondas ⇒ sano.
    Plateau ⇒ debilidad estructural.
"""
import argparse
import sys

try:
    from pulp import (LpProblem, LpVariable, LpMinimize, LpStatus,
                      lpSum, value, PULP_CBC_CMD)
except ImportError:
    print("ERROR: falta PuLP. Instala con: pip install pulp", file=sys.stderr)
    sys.exit(1)

# Wrappers opcionales de Gurobi
try:
    from pulp import GUROBI, GUROBI_CMD
    HAS_GUROBI_WRAPPER = True
except ImportError:
    HAS_GUROBI_WRAPPER = False
    GUROBI = GUROBI_CMD = None


# =============================================================================
# Parámetros congelados del cifrador
# =============================================================================
WORD_BITS = 32
NUM_WORDS = 8
NUM_PAIRS = 4
SHIFT_MOD = 31

MYZ_PERM = [4,12,20,28, 0,8,16,24, 5,13,21,29,
            2,7,10,15,18,23,26,31, 6,14,22,30,
            1,9,17,25, 3,11,19,27]

MYZ_INV = [0] * 32
for _i, _p in enumerate(MYZ_PERM):
    MYZ_INV[_p] = _i


def mysz_map(i, j):
    """Mapeo bit-level de la transposición Myszkowski (mismo que _encryptBlockCore)."""
    byte_idx = i * 4 + (3 - (j // 8))
    bit_in_byte = j % 8
    new_byte = MYZ_INV[byte_idx]
    new_i = new_byte // 4
    new_k = new_byte % 4
    new_j = (3 - new_k) * 8 + bit_in_byte
    return (new_i, new_j)


# =============================================================================
# Primitivas de modelado
# =============================================================================
def xor2(prob, x, y, z, name):
    """z = x XOR y (binarias). x + y + z = 2u, u binaria."""
    u = LpVariable(f"u_{name}", cat='Binary')
    prob += x + y + z == 2 * u


def and_diff(prob, dx, dy, dz, name, a=None):
    """
    Diferencial de z = x & y.
    a = (dx OR dy): el AND puede ser no lineal aunque solo uno de los dos
    inputs difiera (la salida depende del valor del otro input).
    Esta es la cota correcta por arriba del peso del AND.
    """
    if a is None:
        a = LpVariable(f"a_{name}", cat='Binary')
    prob += a >= dx
    prob += a >= dy
    prob += a <= dx + dy
    prob += dz <= a
    return a


# =============================================================================
# Construcción del MILP
# =============================================================================
def build_milp(rounds, input_diff, solver_cmd, cutoff=None, r0=0):
    """
    input_diff: dict {(i, j): 1} con los bits activos en la entrada.
    cutoff: si no es None, modo factibilidad (peso <= cutoff).
    r0: offset de rotación (índice de la primera ronda mod 31).
        La ronda local r usa shift = ((r + r0) mod 31) + 1.
    Devuelve (prob, s, activities).
    """
    prob = LpProblem(f"MYSX_diff_{rounds}r_r0{r0}", LpMinimize)

    s = [[[LpVariable(f"s_{r}_{i}_{j}", cat='Binary')
           for j in range(WORD_BITS)] for i in range(NUM_WORDS)]
         for r in range(rounds + 1)]

    activities = []
    for r in range(rounds):
        ar = [[LpVariable(f"a_{r}_{p}_{j}", cat='Binary')
               for j in range(WORD_BITS)] for p in range(NUM_PAIRS)]
        activities.append(ar)

        s_mid = [[LpVariable(f"sm_{r}_{i}_{j}", cat='Binary')
                  for j in range(WORD_BITS)] for i in range(NUM_WORDS)]

        # --- Feistel por pareja ---
        for p in range(NUM_PAIRS):
            for j in range(WORD_BITS):
                prob += s_mid[p][j] == s[r][p + 4][j]

                dx = s[r][p + 4][(j - 1) % WORD_BITS]
                dy = s[r][p + 4][(j - 8) % WORD_BITS]
                w = LpVariable(f"w_{r}_{p}_{j}", cat='Binary')
                and_diff(prob, dx, dy, w, f"{r}_{p}_{j}", a=ar[p][j])

                fR = LpVariable(f"fR_{r}_{p}_{j}", cat='Binary')
                xor2(prob, w, s[r][p + 4][(j - 2) % WORD_BITS], fR,
                     f"fR_{r}_{p}_{j}")

                xor2(prob, s[r][p][j], fR, s_mid[p + 4][j], f"newR_{r}_{p}_{j}")

        # --- Myszkowski ---
        s_perm = [[LpVariable(f"sp_{r}_{i}_{j}", cat='Binary')
                   for j in range(WORD_BITS)] for i in range(NUM_WORDS)]
        for i in range(NUM_WORDS):
            for j in range(WORD_BITS):
                ni, nj = mysz_map(i, j)
                prob += s_perm[ni][nj] == s_mid[i][j]

        # --- Rotación por palabra ---
        shift = ((r + r0) % SHIFT_MOD) + 1
        for i in range(NUM_WORDS):
            for j in range(WORD_BITS):
                prob += s[r + 1][i][j] == s_perm[i][(j - shift) % WORD_BITS]

    # --- Entrada ---
    for i in range(NUM_WORDS):
        for j in range(WORD_BITS):
            prob += s[0][i][j] == (1 if (i, j) in input_diff else 0)

    # --- Salida no trivial ---
    out_active = LpVariable("out_active", cat='Binary')
    for i in range(NUM_WORDS):
        for j in range(WORD_BITS):
            prob += s[rounds][i][j] <= out_active
    prob += out_active == 1

    # --- Objetivo o cutoff ---
    total_weight = lpSum(activities[r][p][j]
                         for r in range(rounds)
                         for p in range(NUM_PAIRS)
                         for j in range(WORD_BITS))
    if cutoff is not None:
        prob += total_weight <= cutoff
    else:
        prob += total_weight

    prob.solve(solver_cmd)
    return prob, s, activities


# =============================================================================
# Extractores
# =============================================================================
def extract_trail(prob, s, rounds):
    trail = []
    for r in range(rounds + 1):
        active = []
        for i in range(NUM_WORDS):
            for j in range(WORD_BITS):
                v = value(s[r][i][j])
                if v is not None and v > 0.5:
                    active.append((i, j))
        trail.append(active)
    return trail


def print_trail(trail, rounds):
    print(f"\nTrail ({rounds} rondas):")
    for r, active in enumerate(trail):
        words = {}
        for (i, j) in active:
            words.setdefault(i, []).append(j)
        parts = []
        for i in sorted(words):
            bits = ",".join(str(b) for b in sorted(words[i]))
            parts.append(f"w{i}=[{bits}]")
        print(f"  r={r:2d}: {len(active):3d} bits  " + " ".join(parts))


# =============================================================================
# Validación interna
# =============================================================================
def validate():
    print("=== Validación interna del modelo ===")
    ok = True

    prob = LpProblem("t1", LpMinimize)
    dx = LpVariable("dx", cat='Binary'); prob += dx == 1
    dy = LpVariable("dy", cat='Binary'); prob += dy == 1
    dz = LpVariable("dz", cat='Binary')
    a = and_diff(prob, dx, dy, dz, "t1")
    prob += a == 1
    prob.solve(PULP_CBC_CMD(msg=False))
    if value(a) == 1:
        print("  OK   AND(1,1) -> a=1")
    else:
        print("  FAIL AND(1,1)"); ok = False

    prob = LpProblem("t2", LpMinimize)
    dx = LpVariable("dx", cat='Binary'); prob += dx == 0
    dy = LpVariable("dy", cat='Binary'); prob += dy == 0
    dz = LpVariable("dz", cat='Binary')
    and_diff(prob, dx, dy, dz, "t2")
    prob += dz == 1
    prob.solve(PULP_CBC_CMD(msg=False))
    if LpStatus[prob.status] != "Optimal":
        print("  OK   AND(0,0)+dz=1 -> infactible")
    else:
        print("  FAIL AND(0,0)"); ok = False

    prob = LpProblem("t3", LpMinimize)
    x = LpVariable("x", cat='Binary'); prob += x == 1
    y = LpVariable("y", cat='Binary'); prob += y == 1
    z = LpVariable("z", cat='Binary')
    xor2(prob, x, y, z, "t3")
    prob += z == 0
    prob.solve(PULP_CBC_CMD(msg=False))
    if LpStatus[prob.status] == "Optimal":
        print("  OK   XOR(1,1)=0")
    else:
        print("  FAIL XOR(1,1)"); ok = False

    try:
        prob, s, _ = build_milp(1, {(0, 0): 1},
                                PULP_CBC_CMD(msg=False))
        if LpStatus[prob.status] == "Optimal" and int(value(prob.objective)) == 0:
            print("  OK   1 ronda MYSX(0,0): peso 0")
        else:
            w = value(prob.objective) if LpStatus[prob.status] == "Optimal" else "infeasible"
            print(f"  FAIL 1 ronda MYSX(0,0): peso={w}"); ok = False
    except Exception as e:
        print(f"  FAIL 1 ronda MYSX(0,0): {e}"); ok = False

    return ok


# =============================================================================
# Construcción del solver
# =============================================================================
def make_solver(name, gap_rel, time_limit, threads):
    if name == "cbc":
        return PULP_CBC_CMD(
            msg=False,
            gapRel=gap_rel,
            timeLimit=time_limit,
            threads=threads
        )
    if name == "gurobi":
        if not HAS_GUROBI_WRAPPER:
            print("ERROR: wrapper de Gurobi no disponible en PuLP. "
                  "Instala gurobipy (pip install gurobipy) o usa --solver cbc.",
                  file=sys.stderr)
            sys.exit(1)
        # Preferir gurobipy nativo si está instalado; si no, gurobi_cl.
        try:
            import gurobipy  # noqa: F401
            return GUROBI(msg=False, gapRel=gap_rel, timeLimit=time_limit)
        except ImportError:
            print("AVISO: gurobipy no instalado, usando gurobi_cl (necesita licencia)",
                  file=sys.stderr)
            return GUROBI_CMD(msg=False, gapRel=gap_rel, timeLimit=time_limit)
    print(f"ERROR: solver desconocido: {name}", file=sys.stderr)
    sys.exit(1)


# =============================================================================
# Main
# =============================================================================
def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rounds", default="4",
                    help="Rondas: 'N' o 'A-B' (default 4)")
    ap.add_argument("--input-bit", type=int, default=0,
                    help="Bit de entrada (0-255): i*32 + j")
    ap.add_argument("--input-bits", default=None,
                    help="Lista de bits: '56,94' (sobreescribe --input-bit)")
    ap.add_argument("--all-inputs", action="store_true",
                    help="Barrer los 256 bits de entrada (lento)")
    ap.add_argument("--trail", action="store_true",
                    help="Imprimir el trail para cada número de rondas")
    ap.add_argument("--cutoff", type=int, default=None,
                    help="Solo factibilidad: ¿existe trail con peso <= cutoff?")
    ap.add_argument("--solver", default="cbc", choices=["cbc", "gurobi"],
                    help="Solver a usar (default cbc)")
    ap.add_argument("--gap-rel", type=float, default=0.2,
                    help="gapRel para CBC/Gurobi (default 0.2)")
    ap.add_argument("--time-limit", type=float, default=300.0,
                    help="timeLimit en segundos por solve (default 300)")
    ap.add_argument("--threads", type=int, default=4,
                    help="hilos para CBC (default 4)")
    ap.add_argument("--r0", type=int, default=0,
                    help="Rotation offset: la ronda local r usa shift "
                         "((r + r0) mod 31) + 1 (default 0)")
    ap.add_argument("--validate", action="store_true",
                    help="Solo ejecutar tests de validación")
    args = ap.parse_args()

    if args.validate:
        sys.exit(0 if validate() else 1)

    # Parser rounds
    if "-" in args.rounds:
        a, b = args.rounds.split("-")
        round_list = list(range(int(a), int(b) + 1))
    else:
        round_list = [int(args.rounds)]

    # Parser bits
    if args.input_bits:
        input_bits = [int(x) for x in args.input_bits.split(",")]
    elif args.all_inputs:
        input_bits = list(range(256))
    else:
        input_bits = [args.input_bit]

    solver_cmd = make_solver(args.solver, args.gap_rel,
                             args.time_limit, args.threads)

    print(f"Solver={args.solver} gapRel={args.gap_rel} "
          f"timeLimit={args.time_limit}s threads={args.threads} r0={args.r0}")
    if args.cutoff is not None:
        print(f"Modo factibilidad: peso <= {args.cutoff}")
    print()

    results = {}
    for rounds in round_list:
        best_weight = None
        best_input = None
        best_prob = None
        best_status = None
        n_infeasible = 0
        n_feasible = 0

        for input_bit in input_bits:
            i, j = divmod(input_bit, WORD_BITS)
            try:
                prob, s, _ = build_milp(rounds, {(i, j): 1},
                                        solver_cmd, cutoff=args.cutoff,
                                        r0=args.r0)
            except Exception as e:
                print(f"  Error rounds={rounds} input={input_bit}: {e}")
                continue

            status = LpStatus[prob.status]

            if args.cutoff is not None:
                # Modo factibilidad
                if status == "Optimal":
                    n_feasible += 1
                    if best_status is None:
                        best_status = "FEASIBLE"
                        best_input = input_bit
                        best_prob = (prob, s)
                elif status == "Infeasible":
                    n_infeasible += 1
                else:
                    print(f"  rounds={rounds} input={input_bit}: "
                          f"status={status} (timeout?)")
                continue

            # Modo optimización
            if status != "Optimal":
                print(f"  rounds={rounds} input={input_bit}: "
                      f"status={status} (timeout o infactible)")
                continue
            w = int(round(value(prob.objective)))
            if best_weight is None or w < best_weight:
                best_weight = w
                best_input = input_bit
                best_prob = (prob, s)

        # Reporte por ronda
        if args.cutoff is not None:
            if n_feasible > 0:
                bi, bj = divmod(best_input, WORD_BITS)
                print(f"rounds={rounds:3d}: cutoff={args.cutoff} → "
                      f"FACTIBLE ({n_feasible}/{len(input_bits)} inputs, "
                      f"ej. w{bi}b{bj})")
                results[rounds] = ("FEASIBLE", args.cutoff, best_input, best_prob)
                if args.trail and best_prob is not None:
                    trail = extract_trail(*best_prob, rounds)
                    print_trail(trail, rounds)
            else:
                print(f"rounds={rounds:3d}: cutoff={args.cutoff} → "
                      f"INFEASIBLE (peso > {args.cutoff} para todos los inputs)")
                results[rounds] = ("INFEASIBLE", args.cutoff, None, None)
        else:
            if best_weight is None:
                print(f"rounds={rounds}: sin solución")
                continue
            results[rounds] = ("OPTIMAL", best_weight, best_input, best_prob)
            bi, bj = divmod(best_input, WORD_BITS)
            print(f"rounds={rounds:3d}: peso mínimo={best_weight:4d} "
                  f"(prob ≈ 2^-{best_weight}), input=w{bi}b{bj}")
            if args.trail:
                trail = extract_trail(*best_prob, rounds)
                print_trail(trail, rounds)

    # Resumen
    print("\n=== Resumen ===")
    for rounds in sorted(results):
        entry = results[rounds]
        if entry[0] == "INFEASIBLE":
            print(f"  r={rounds:3d}: peso > {entry[1]} (cutoff)")
        elif entry[0] == "FEASIBLE":
            print(f"  r={rounds:3d}: peso <= {entry[1]} (cutoff)")
        else:
            _, w, b, _ = entry
            bi, bj = divmod(b, WORD_BITS)
            print(f"  r={rounds:3d}: {w:4d} ANDs (prob ≈ 2^-{w}), "
                  f"mejor input w{bi}b{bj}")


if __name__ == "__main__":
    main()
