#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mysx_division_property.py -- Bit-based division property MILP for MYSX-256/512.

Finds integral distinguishers (balanced output bits). Batch-solving strategy:
each MILP solve marks several active bits at once, drastically reducing the
number of solves (the bottleneck with PuLP is per-solve overhead).

Propagation rules:
    COPY  a -> (b,c)  : k_a = k_b = k_c
    AND   c = a AND b : k_c = k_a OR k_b
    XOR   c = a XOR b : k_c = k_a XOR k_b   (Todo 2015, default)
                        k_c = k_a OR  k_b   (sound, conservative, --xor-rule or)

Solvers (order of recommendation):
    scip   : SCIP   (pip install pyscipopt). Open source, robust, fast.
    highs  : HiGHS  (pip install highspy). Open source, fast.
    cbc    : CBC    (PuLP bundle). Slow but always available.
    gurobi : Gurobi (needs license; trial is size-limited and won't fit R >= 5).

Usage:
    python3 mysx_division_property.py --rounds 1-40 --start-bit 0 --solver scip
    python3 mysx_division_property.py --rounds 1-40 --start-bit 0 --solver scip --xor-rule or
    python3 mysx_division_property.py --rounds 20-80 --start-bit 0 --solver scip
    python3 mysx_division_property.py --rounds 1-12 --start-word 0 --words-only
"""

import argparse
import sys
import time

from pulp import (
    LpProblem, LpVariable, LpMinimize, LpStatus,
    PULP_CBC_CMD, lpSum,
)

MYZ_PERM = [4, 12, 20, 28, 0, 8, 16, 24, 5, 13, 21, 29,
            2, 7, 10, 15, 18, 23, 26, 31, 6, 14, 22, 30,
            1, 9, 17, 25, 3, 11, 19, 27]

# Global XOR rule: "xor" (Todo 2015) or "or" (sound, conservative)
XOR_RULE = "xor"


def add_xor(model, z, x, y, name):
    """z = propagation of k through c = a XOR b.

    xor: k_c = k_a XOR k_b  (Todo 2015; may overestimate balanced bits
         via coincidental cancellations)
    or : k_c = k_a OR  k_b  (sound; always monotone, never overestimates)
    """
    if XOR_RULE == "or":
        model += z >= x, f"{name}_1"
        model += z >= y, f"{name}_2"
        model += z <= x + y, f"{name}_3"
    else:
        model += z <= x + y, f"{name}_1"
        model += z >= x - y, f"{name}_2"
        model += z >= y - x, f"{name}_3"
        model += z <= 2 - x - y, f"{name}_4"


def add_and(model, z, x, y, name):
    """z = k through c = a AND b: k_c = k_a OR k_b."""
    model += z >= x, f"{name}_1"
    model += z >= y, f"{name}_2"
    model += z <= x + y, f"{name}_3"


def build(R, k_in, r0=0):
    """Build MILP for R rounds. Returns (model, k)."""
    model = LpProblem("MYSX_DP", LpMinimize)
    model += 0

    k = {}
    for r in range(R + 1):
        for i in range(8):
            for b in range(32):
                k[(r, i, b)] = LpVariable(f"k_{r}_{i}_{b}", cat="Binary")

    for i in range(8):
        for b in range(32):
            model += k[(0, i, b)] == k_in.get((i, b), 0)

    for r in range(R):
        s_mid = {}
        for i in range(4):
            for b in range(32):
                # COPY: s_mid[p] = R (word p+4)
                s_mid[(i, b)] = LpVariable(f"sm_{r}_{i}_{b}", cat="Binary")
                model += s_mid[(i, b)] == k[(r, i + 4, b)]

                # F(R) = (rotl(R,1) AND rotl(R,8)) XOR rotl(R,2)
                kA = k[(r, i + 4, (b - 1) % 32)]
                kB = k[(r, i + 4, (b - 8) % 32)]
                kD = k[(r, i + 4, (b - 2) % 32)]
                kC = LpVariable(f"kC_{r}_{i}_{b}", cat="Binary")
                add_and(model, kC, kA, kB, f"C_{r}_{i}_{b}")
                kF = LpVariable(f"kF_{r}_{i}_{b}", cat="Binary")
                add_xor(model, kF, kC, kD, f"F_{r}_{i}_{b}")

                # s_mid[p+4] = L XOR F(R)
                sm4 = LpVariable(f"sm4_{r}_{i}_{b}", cat="Binary")
                s_mid[(i + 4, b)] = sm4
                add_xor(model, sm4, k[(r, i, b)], kF, f"sm4_{r}_{i}_{b}")

        # Linear layer: transposition then rotation
        shift = ((r + r0) % 31) + 1
        for i in range(8):
            for b in range(32):
                b_rot = (b - shift) % 32
                byte_idx = 4 * i + (3 - b_rot // 8)   # big-endian: byte 0 = MSB
                bit_in_byte = b_rot % 8
                src_byte = MYZ_PERM[byte_idx]
                src_word = src_byte // 4
                src_byte_in_word = src_byte % 4
                src_bit = 8 * (3 - src_byte_in_word) + bit_in_byte
                model += k[(r + 1, i, b)] == s_mid[(src_word, src_bit)]

    return model, k


def make_solver(kind, time_limit):
    tl = int(time_limit)

    if kind == "gurobi":
        try:
            from pulp import GUROBI
            print("Solver: Gurobi", file=sys.stderr)
            return GUROBI(msg=0, TimeLimit=tl)
        except Exception as e:
            print(f"Gurobi no disponible ({e}); probando SCIP", file=sys.stderr)
            kind = "scip"

    if kind == "scip":
        try:
            from pulp import SCIP_PY
            print("Solver: SCIP", file=sys.stderr)
            return SCIP_PY(msg=0, timeLimit=tl)
        except Exception as e:
            print(f"SCIP no disponible ({e}); probando HiGHS", file=sys.stderr)
            kind = "highs"

    if kind == "highs":
        try:
            from pulp import HiGHS
            print("Solver: HiGHS", file=sys.stderr)
            return HiGHS(msg=0, timeLimit=tl)
        except Exception as e:
            print(f"HiGHS no disponible ({e}); usando CBC", file=sys.stderr)

    print("Solver: CBC", file=sys.stderr)
    return PULP_CBC_CMD(msg=0, timeLimit=tl)


def find_balanced_bits_batch(model, k, R, solver, max_iterations=500, verbose=True):
    """Batch-solve to find all balanced output bits.

    Returns (balanced_set, active_set, undetermined_set, iterations, partial).
    When the loop ends by infeasibility, ALL of `remaining` are balanced.
    """
    all_bits = [(w, b) for w in range(8) for b in range(32)]
    active = set()
    remaining = set(all_bits)
    iterations = 0
    infeasible_reached = False

    while remaining and iterations < max_iterations:
        iterations += 1
        cname = f"batch_{R}_{iterations}"
        expr = lpSum(k[(R, w, b)] for (w, b) in remaining) >= 1
        model.addConstraint(expr, cname)

        try:
            status = model.solve(solver)
        except Exception as e:
            del model.constraints[cname]
            if verbose:
                print(f"    iter {iterations}: exception: {e}", file=sys.stderr)
            break

        lpstatus = LpStatus[status]

        if lpstatus == "Infeasible":
            del model.constraints[cname]
            infeasible_reached = True
            if verbose:
                print(f"    iter {iterations}: infeasible -> "
                      f"{len(remaining)} bits balanced", file=sys.stderr)
            break
        elif lpstatus != "Optimal":
            del model.constraints[cname]
            if verbose:
                print(f"    iter {iterations}: status={lpstatus} (timeout?)",
                      file=sys.stderr)
            break

        new_active = {
            (w, b) for (w, b) in remaining
            if k[(R, w, b)].value() is not None and k[(R, w, b)].value() > 0.5
        }
        del model.constraints[cname]

        if not new_active:
            if verbose:
                print(f"    iter {iterations}: no active bits extracted",
                      file=sys.stderr)
            break

        active.update(new_active)
        remaining -= new_active

        if verbose and (iterations <= 3 or iterations % 10 == 0):
            print(f"    iter {iterations}: +{len(new_active)} active, "
                  f"{len(remaining)} left", file=sys.stderr)

    if infeasible_reached:
        balanced = set(all_bits) - active
        undetermined = set()
        partial = False
    else:
        balanced = set(all_bits) - active - remaining
        undetermined = remaining
        partial = bool(remaining)

    return balanced, active, undetermined, iterations, partial


def main():
    global XOR_RULE
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", default="1-20",
                    help="Round range, e.g. '1-40' or '5,10,15'")
    ap.add_argument("--start-bit", type=int, default=0)
    ap.add_argument("--start-word", type=int, default=None)
    ap.add_argument("--r0", type=int, default=0)
    ap.add_argument("--time", type=int, default=120,
                    help="Solver time limit per solve, seconds")
    ap.add_argument("--solver", default="scip",
                    choices=["cbc", "gurobi", "highs", "scip"])
    ap.add_argument("--words-only", action="store_true")
    ap.add_argument("--max-iterations", type=int, default=500)
    ap.add_argument("--xor-rule", default="xor", choices=["xor", "or"],
                    help="XOR propagation: 'xor' (Todo 2015) or 'or' (sound, conservative)")
    ap.add_argument("--stop-when-zero", action="store_true",
                    help="Stop as soon as a round has 0 balanced bits")
    args = ap.parse_args()

    XOR_RULE = args.xor_rule

    if "-" in args.rounds:
        lo, hi = args.rounds.split("-")
        rounds = list(range(int(lo), int(hi) + 1))
    else:
        rounds = [int(x) for x in args.rounds.split(",")]

    k_in = {}
    if args.start_word is not None:
        for b in range(32):
            k_in[(args.start_word, b)] = 1
    else:
        k_in[(args.start_bit // 32, args.start_bit % 32)] = 1

    solver = make_solver(args.solver, args.time)

    print(f"Input DP: {sorted(k_in)}", file=sys.stderr)
    print(f"r0 = {args.r0}, XOR rule = {XOR_RULE}", file=sys.stderr)
    print(f"Mode: {'words-only' if args.words_only else 'per-bit (batch)'}",
          file=sys.stderr)

    summary = []

    for R in rounds:
        t0 = time.time()
        print(f"\n[R={R}] Building...", file=sys.stderr)
        model, k = build(R, k_in, r0=args.r0)
        print(f"  vars={len(model.variables())} cons={len(model.constraints)}",
              file=sys.stderr)

        # Full state check
        cname = f"full_{R}"
        expr = lpSum(k[(R, i, b)] for i in range(8) for b in range(32)) >= 1
        model.addConstraint(expr, cname)
        try:
            status = model.solve(solver)
        except Exception as e:
            del model.constraints[cname]
            print(f"  full solve exception: {e}", file=sys.stderr)
            continue
        lpstatus = LpStatus[status]
        del model.constraints[cname]

        if lpstatus == "Infeasible":
            print(f"[R={R}] *** FULL STATE BALANCED *** (256 bits, "
                  f"{time.time()-t0:.1f}s)")
            summary.append((R, 256, "full"))
            if args.stop_when_zero:
                print(f"\nStopping: full-state balanced at R={R}", file=sys.stderr)
                break
            continue

        if args.words_only:
            balanced_words = []
            for i in range(8):
                cn = f"w_{R}_{i}"
                model.addConstraint(lpSum(k[(R, i, b)] for b in range(32)) >= 1, cn)
                try:
                    st = model.solve(solver)
                except Exception:
                    del model.constraints[cn]
                    continue
                if LpStatus[st] == "Infeasible":
                    balanced_words.append(i)
                del model.constraints[cn]
            n_bits = len(balanced_words) * 32
            print(f"[R={R}] Balanced words: {balanced_words} (~{n_bits} bits, "
                  f"{time.time()-t0:.1f}s)")
            summary.append((R, n_bits, "words"))
            if args.stop_when_zero and n_bits == 0:
                print(f"\nStopping: 0 balanced words at R={R}", file=sys.stderr)
                break
            continue

        # Batch per-bit
        print(f"[R={R}] Batch per-bit (max {args.max_iterations} iters)...",
              file=sys.stderr)
        balanced, active, undetermined, iters, partial = find_balanced_bits_batch(
            model, k, R, solver, max_iterations=args.max_iterations, verbose=True
        )

        by_w = {}
        for (w, bit) in sorted(balanced):
            by_w.setdefault(w, []).append(bit)

        status_str = "PARTIAL" if partial else "complete"
        print(f"[R={R}] Balanced bits: {len(balanced)}/256 "
              f"({iters} iters, {status_str}, {time.time()-t0:.1f}s)")
        for w in sorted(by_w):
            # print(f"       word {w}: {len(by_w[w])}/32 balanced")
            print(f"       word {w}: {len(by_w[w])}/32 balanced -> {by_w[w]}")

        if partial and undetermined:
            print(f"       undetermined: {len(undetermined)} bits "
                  f"(raise --max-iterations)")

        summary.append((R, len(balanced), status_str))

        if args.stop_when_zero and len(balanced) == 0:
            print(f"\nStopping: 0 balanced bits at R={R}", file=sys.stderr)
            break

    print("\n=== SUMMARY ===")
    print("R | balanced | note")
    for R, n, note in summary:
        bar = "#" * (n // 4)
        print(f"{R:2d} | {n:3d} {bar} {note}")


if __name__ == "__main__":
    main()
