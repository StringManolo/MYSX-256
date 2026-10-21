#!/usr/bin/env python3
"""
mysx_linear_milp.py -- Trails lineales por MILP para MYSX-256/512.

Modelo estricto:
  - AND: gamma = alpha OR beta (correlación 1/2, coste 1).
  - XOR: x = y = z = w (correlación 1, coste 0). Prohíbe
    combinaciones con correlación 0 que el solver usaría para
    inventar trails inexistentes.
  - Resultado: si da pesos, son trails con correlación 2^-peso
    REALES (verificables empíricamente). Si da INFEASIBLE, no hay
    trail de correlación 1 para esa máscara/rondas.

Solver por defecto: HiGHS.

Instalación:
    pip install pulp highspy

Uso:
    python3 mysx_linear_milp.py --validate
    python3 mysx_linear_milp.py --rounds 2 --trail
    python3 mysx_linear_milp.py --rounds 4 --trail
    python3 mysx_linear_milp.py --rounds 1-10
"""
import argparse
import os
import sys

try:
    from pulp import (LpProblem, LpVariable, LpMinimize, LpStatus,
                      lpSum, value, PULP_CBC_CMD)
except ImportError:
    print("ERROR: falta PuLP. pip install pulp", file=sys.stderr)
    sys.exit(1)

try:
    from pulp import HiGHS
    HAS_HIGHS = True
except ImportError:
    HiGHS = None
    try:
        from pulp import HiGHS_CMD
        HAS_HIGHS = True
    except ImportError:
        HiGHS_CMD = None
        HAS_HIGHS = False

try:
    from pulp import GUROBI, GUROBI_CMD
    HAS_GUROBI = True
except ImportError:
    GUROBI = GUROBI_CMD = None
    HAS_GUROBI = False


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
    byte_idx = i * 4 + (3 - (j // 8))
    bit_in_byte = j % 8
    new_byte = MYZ_INV[byte_idx]
    return (new_byte // 4, (3 - (new_byte % 4)) * 8 + bit_in_byte)


def xor2(prob, x, y, z, name):
    """z = x XOR y. Correlación 1 solo si x = y = z."""
    prob += x == y
    prob += x == z


def xor3(prob, x, y, z, w, name):
    """w = x XOR y XOR z. Correlación 1 solo si x = y = z = w."""
    prob += x == y
    prob += x == z
    prob += x == w


def and_linear_hybrid(prob, alpha, beta, gamma, name):
    """
    AND: gamma = alpha OR beta. Correlación 1/2, coste 1.
    Prohíbe (1,0,0), (0,1,0), (1,1,0) y permite (0,0,1), (0,1,1),
    (1,0,1), (1,1,1). El coste es gamma.
    """
    prob += gamma >= alpha
    prob += gamma >= beta
    prob += gamma <= alpha + beta
    return gamma


def build_linear_milp(rounds, input_mask_bits, solver_cmd, cutoff=None):
    prob = LpProblem(f"MYSX_lin_{rounds}r", LpMinimize)

    s = [[[LpVariable(f"s_{r}_{i}_{j}", cat='Binary')
           for j in range(WORD_BITS)] for i in range(NUM_WORDS)]
         for r in range(rounds + 1)]

    activities = []
    for r in range(rounds):
        ar = [[LpVariable(f"act_{r}_{p}_{j}", cat='Binary')
               for j in range(WORD_BITS)] for p in range(NUM_PAIRS)]
        activities.append(ar)

        s_mid = [[LpVariable(f"sm_{r}_{i}_{j}", cat='Binary')
                  for j in range(WORD_BITS)] for i in range(NUM_WORDS)]

        for p in range(NUM_PAIRS):
            for j in range(WORD_BITS):
                # newL = R
                prob += s_mid[p][j] == s[r][p + 4][j]

                # AND: inputs R[j-1], R[j-8]; salida g
                alpha = s[r][p + 4][(j - 1) % WORD_BITS]
                beta  = s[r][p + 4][(j - 8) % WORD_BITS]
                g     = LpVariable(f"g_{r}_{p}_{j}", cat='Binary')
                and_linear_hybrid(prob, alpha, beta, g, f"{r}_{p}_{j}")
                prob += g == ar[p][j]

                # newR = L XOR rot(R,2) XOR g (correlación 1: x=y=z=w)
                xor3(prob, s[r][p][j], s[r][p + 4][(j - 2) % WORD_BITS],
                     g, s_mid[p + 4][j], f"newR_{r}_{p}_{j}")

        # Myszkowski
        s_perm = [[LpVariable(f"sp_{r}_{i}_{j}", cat='Binary')
                   for j in range(WORD_BITS)] for i in range(NUM_WORDS)]
        for i in range(NUM_WORDS):
            for j in range(WORD_BITS):
                ni, nj = mysz_map(i, j)
                prob += s_perm[ni][nj] == s_mid[i][j]

        # Rotación
        shift = (r % SHIFT_MOD) + 1
        for i in range(NUM_WORDS):
            for j in range(WORD_BITS):
                prob += s[r + 1][i][j] == s_perm[i][(j - shift) % WORD_BITS]

    # Máscara de entrada
    for i in range(NUM_WORDS):
        for j in range(WORD_BITS):
            prob += s[0][i][j] == (1 if (i, j) in input_mask_bits else 0)

    # Salida no trivial
    prob += lpSum(s[rounds][i][j]
                  for i in range(NUM_WORDS)
                  for j in range(WORD_BITS)) >= 1

    total = lpSum(activities[r][p][j]
                  for r in range(rounds)
                  for p in range(NUM_PAIRS)
                  for j in range(WORD_BITS))

    if cutoff is not None:
        prob += total <= cutoff
        prob += 0
    else:
        prob += total

    prob.solve(solver_cmd)
    return prob, s, activities


def print_trail(prob, s, rounds):
    print(f"\nTrail ({rounds} rondas):")
    for r in range(rounds + 1):
        words = {}
        for i in range(NUM_WORDS):
            for j in range(WORD_BITS):
                v = value(s[r][i][j])
                if v is not None and v > 0.5:
                    words.setdefault(i, []).append(j)
        parts = [f"w{i}=[{','.join(str(b) for b in sorted(words[i]))}]"
                 for i in sorted(words)]
        total = sum(len(v) for v in words.values())
        print(f"  r={r:2d}: {total:3d} bits  " + " ".join(parts))


def validate(solver_cmd):
    print("=== Validación del modelo lineal (XOR estricto) ===")
    ok = True

    for bit in [0, 5, 16, 31]:
        prob, s, _ = build_linear_milp(1, {(0, bit)}, solver_cmd)
        status = LpStatus[prob.status]
        if status == "Optimal":
            w = int(value(prob.objective))
            if w == 0:
                print(f"  OK   1 ronda (0,{bit}): peso 0")
            else:
                print(f"  FAIL 1 ronda (0,{bit}): peso {w} (esperado 0)")
                ok = False
        elif status == "Infeasible":
            print(f"  OK   1 ronda (0,{bit}): INFEASIBLE (sin trail corr-1)")
        else:
            print(f"  FAIL 1 ronda (0,{bit}): status {status}")
            ok = False

    # 2 rondas: puede ser INFEASIBLE u Optimal
    prob, s, _ = build_linear_milp(2, {(0, 0)}, solver_cmd)
    status = LpStatus[prob.status]
    if status == "Optimal":
        w = int(value(prob.objective))
        print(f"  OK   2 rondas (0,0): peso {w}")
    elif status == "Infeasible":
        print(f"  OK   2 rondas (0,0): INFEASIBLE (sin trail corr-1)")
    else:
        print(f"  FAIL 2 rondas (0,0): status {status}")
        ok = False

    return ok


def make_solver(kind, gap, time_limit):
    if kind == "highs":
        if not HAS_HIGHS:
            print("ERROR: HiGHS no disponible. pip install highspy",
                  file=sys.stderr)
            sys.exit(1)
        try:
            return HiGHS(msg=False, gapRel=gap, timeLimit=time_limit)
        except Exception:
            return HiGHS_CMD(msg=False, gapRel=gap, timeLimit=time_limit)

    if kind == "cbc":
        sys_cbc = "/usr/bin/cbc"
        kwargs = dict(msg=False, gapRel=gap, timeLimit=time_limit, threads=4)
        if os.path.exists(sys_cbc):
            kwargs["path"] = sys_cbc
        return PULP_CBC_CMD(**kwargs)

    if kind == "gurobi":
        if not HAS_GUROBI:
            print("ERROR: Gurobi no disponible", file=sys.stderr)
            sys.exit(1)
        try:
            return GUROBI(msg=False, gapRel=gap, timeLimit=time_limit)
        except Exception:
            return GUROBI_CMD(msg=False, gapRel=gap, timeLimit=time_limit)

    print(f"ERROR: solver desconocido: {kind}", file=sys.stderr)
    sys.exit(1)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rounds", default="1-10")
    ap.add_argument("--mask-bit", type=int, default=0)
    ap.add_argument("--mask-bits", default=None)
    ap.add_argument("--trail", action="store_true")
    ap.add_argument("--cutoff", type=int, default=None)
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--solver", default="highs",
                    choices=["highs", "cbc", "gurobi"])
    ap.add_argument("--gap", type=float, default=0.3)
    ap.add_argument("--time-limit", type=int, default=60)
    args = ap.parse_args()

    solver_cmd = make_solver(args.solver, args.gap, args.time_limit)

    if args.validate:
        sys.exit(0 if validate(solver_cmd) else 1)

    if "-" in args.rounds:
        a, b = args.rounds.split("-")
        round_list = list(range(int(a), int(b) + 1))
    else:
        round_list = [int(args.rounds)]

    mask_bits = ([int(x) for x in args.mask_bits.split(",")]
                 if args.mask_bits else [args.mask_bit])

    print(f"Solver={args.solver} gap={args.gap} timeLimit={args.time_limit}s")
    print("Modelo: XOR estricto (x=y=z=w), AND correcto (γ = α OR β)")
    if args.cutoff is not None:
        print(f"Modo factibilidad: peso <= {args.cutoff}\n")

    results = {}
    for rounds in round_list:
        best = None
        all_infeasible = True
        for bit in mask_bits:
            i, j = divmod(bit, WORD_BITS)
            try:
                prob, s, _ = build_linear_milp(
                    rounds, {(i, j)}, solver_cmd, cutoff=args.cutoff
                )
            except Exception as e:
                print(f"  Error r={rounds} bit={bit}: {e}")
                continue

            status = LpStatus[prob.status]

            if args.cutoff is not None:
                if status == "Optimal":
                    print(f"rounds={rounds:3d} input=w{i}b{j}: "
                          f"FACTIBLE (peso <= {args.cutoff})")
                    if best is None:
                        best = ("feasible", bit, (prob, s))
                    all_infeasible = False
                    break
                elif status == "Infeasible":
                    print(f"rounds={rounds:3d} input=w{i}b{j}: "
                          f"INFEASIBLE (peso > {args.cutoff})")
                    if best is None:
                        best = ("infeasible", bit, (prob, s))
                else:
                    print(f"rounds={rounds:3d} input=w{i}b{j}: "
                          f"UNKNOWN (status={status})")
                continue

            if status != "Optimal":
                continue
            all_infeasible = False
            obj = value(prob.objective)
            if obj is None:
                continue
            w = int(obj)
            if best is None or best[0] is None or \
               (isinstance(best[0], int) and w < best[0]):
                best = (w, bit, (prob, s))

        if best is None:
            print(f"rounds={rounds:3d}: INFEASIBLE (sin trail corr-1)")
            results[rounds] = None
            continue

        if args.cutoff is not None:
            if args.trail and best[0] == "feasible":
                print_trail(*best[2], rounds)
            continue

        w, b, bp = best
        bi, bj = divmod(b, WORD_BITS)
        results[rounds] = (w, b)
        print(f"rounds={rounds:3d}: peso mínimo={w:4d}, input=w{bi}b{bj}")
        if args.trail:
            print_trail(*bp, rounds)

    if args.cutoff is None and results:
        print("\n=== Resumen (XOR estricto) ===")
        for rounds in sorted(results):
            r = results[rounds]
            if r is None:
                print(f"  r={rounds:3d}: INFEASIBLE")
            else:
                w, b = r
                bi, bj = divmod(b, WORD_BITS)
                print(f"  r={rounds:3d}: {w:4d} ANDs, máscara w{bi}b{bj}")


if __name__ == "__main__":
    main()
