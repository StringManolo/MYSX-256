#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mysx_division_property_v2.py -- Corrected bit-based division property.

Uses standard rules (Todo-Morii FSE 2016):
  COPY: k_a = k_b + k_c (integer sum; at most one copy carries the trace)
  XOR:  k_c = k_a + k_b (integer), (1,1) INVALID
  AND:  k_c = k_a + k_b (integer), (1,1) -> 1  (i.e., k_c = k_a OR k_b)

Input specification:
  --active bit0          : single bit (word 0, bit 0)
  --active word0         : all 32 bits of word 0
  --active word0,word4   : 64 bits (words 0 and 4)
  --active all           : all 256 bits
  --active 0:0,0:5,3:6   : specific bits
  --inactive 0:0         : all bits except (word 0, bit 0)

Usage:
  python3 mysx_division_property_v2.py --rounds 1-20 --active word0 --solver scip --stop-when-zero
  python3 mysx_division_property_v2.py --rounds 1-15 --inactive 0:0 --solver scip --stop-when-zero
  python3 mysx_division_property_v2.py --rounds 1-20 --active bit0 --solver scip --r0-sweep
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


import os as _os
_ROT_CAL_STR = _os.environ.get('MYSX_ROT_CAL', '')
if _ROT_CAL_STR:
    ROT_CAL = [int(x) for x in _ROT_CAL_STR.split(',')]
    assert len(ROT_CAL) == 31, f"MYSX_ROT_CAL: 31 valores, tiene {len(ROT_CAL)}"
    assert sorted(ROT_CAL) == list(range(1, 32)), "MYSX_ROT_CAL: permutación de 1..31"
else:
    ROT_CAL = None

def add_xor(model, z, x, y, name):
    """Standard DP: z = x + y (integer), with (1,1) invalid."""
    model += z <= x + y, f"{name}_1"
    model += z >= x, f"{name}_2"
    model += z >= y, f"{name}_3"
    model += x + y <= 1, f"{name}_4"


def add_and(model, z, x, y, name):
    """Standard DP: z = x OR y (i.e., z = x + y if (x,y) != (1,1), else z=1)."""
    model += z >= x, f"{name}_1"
    model += z >= y, f"{name}_2"
    model += z <= x + y, f"{name}_3"


def build(R, active_set, r0=0):
    model = LpProblem("MYSX_DP", LpMinimize)
    model += 0

    k = {}
    for r in range(R + 1):
        for i in range(8):
            for b in range(32):
                k[(r, i, b)] = LpVariable(f"k_{r}_{i}_{b}", cat="Binary")

    for i in range(8):
        for b in range(32):
            model += k[(0, i, b)] == (1 if (i, b) in active_set else 0)

    for r in range(R):
        s_mid = {}
        kA_use = {}
        kB_use = {}
        kD_use = {}
        for i in range(4):
            for b in range(32):
                s_mid[(i, b)] = LpVariable(f"sm_{r}_{i}_{b}", cat="Binary")
                kA_use[(i, b)] = LpVariable(f"kA_{r}_{i}_{b}", cat="Binary")
                kB_use[(i, b)] = LpVariable(f"kB_{r}_{i}_{b}", cat="Binary")
                kD_use[(i, b)] = LpVariable(f"kD_{r}_{i}_{b}", cat="Binary")

        # COPY (trace): k_R[b] = sum of 4 uses
        for i in range(4):
            for b in range(32):
                model += (k[(r, i + 4, b)] ==
                          s_mid[(i, b)] +
                          kA_use[(i, (b + 1) % 32)] +
                          kB_use[(i, (b + 8) % 32)] +
                          kD_use[(i, (b + 2) % 32)])

        for i in range(4):
            for b in range(32):
                kC = LpVariable(f"kC_{r}_{i}_{b}", cat="Binary")
                add_and(model, kC, kA_use[(i, b)], kB_use[(i, b)], f"C_{r}_{i}_{b}")
                kF = LpVariable(f"kF_{r}_{i}_{b}", cat="Binary")
                add_xor(model, kF, kC, kD_use[(i, b)], f"F_{r}_{i}_{b}")
                sm4 = LpVariable(f"sm4_{r}_{i}_{b}", cat="Binary")
                s_mid[(i + 4, b)] = sm4
                add_xor(model, sm4, k[(r, i, b)], kF, f"sm4_{r}_{i}_{b}")

        shift = ROT_CAL[r % 31] if ROT_CAL is not None else ((r + r0) % 31) + 1
        for i in range(8):
            for b in range(32):
                b_rot = (b - shift) % 32
                byte_idx = 4 * i + (3 - b_rot // 8)
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
            return GUROBI(msg=0, TimeLimit=tl)
        except Exception:
            kind = "scip"
    if kind == "scip":
        try:
            from pulp import SCIP_PY
            print("Solver: SCIP", file=sys.stderr)
            return SCIP_PY(msg=0, timeLimit=tl)
        except Exception:
            kind = "highs"
    if kind == "highs":
        try:
            from pulp import HiGHS
            print("Solver: HiGHS", file=sys.stderr)
            return HiGHS(msg=0, timeLimit=tl)
        except Exception:
            pass
    print("Solver: CBC", file=sys.stderr)
    return PULP_CBC_CMD(msg=0, timeLimit=tl)


def find_balanced_bits(model, k, R, solver, max_iterations=2000, verbose=False):
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
        except Exception:
            del model.constraints[cname]
            break
        lpstatus = LpStatus[status]
        if lpstatus == "Infeasible":
            del model.constraints[cname]
            infeasible_reached = True
            break
        elif lpstatus != "Optimal":
            del model.constraints[cname]
            break
        new_active = {
            (w, b) for (w, b) in remaining
            if k[(R, w, b)].value() is not None and k[(R, w, b)].value() > 0.5
        }
        del model.constraints[cname]
        if not new_active:
            break
        active.update(new_active)
        remaining -= new_active
        if verbose and iterations % 5 == 0:
            print(f"    iter {iterations}: {len(remaining)} left", file=sys.stderr)

    if infeasible_reached:
        balanced = set(all_bits) - active
    else:
        balanced = set(all_bits) - active - remaining
    return balanced, iterations


def parse_active(spec):
    if spec == "all":
        return set((i, b) for i in range(8) for b in range(32))
    if spec.startswith("word") and "," not in spec:
        w = int(spec[4:])
        return set((w, b) for b in range(32))
    if spec.startswith("word"):
        words = [int(w[4:]) for w in spec.split(",")]
        return set((w, b) for w in words for b in range(32))
    if spec.startswith("bit"):
        n = int(spec[3:])
        return set([(n // 32, n % 32)])
    result = set()
    for tok in spec.split(","):
        w, b = tok.split(":")
        result.add((int(w), int(b)))
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", default="1-20")
    ap.add_argument("--active", default="bit0",
                    help="Active bits: bit0, word0, word0,word4, all, or 'w:b,...'")
    ap.add_argument("--inactive", default=None,
                    help="Bits to keep inactive (complements --active)")
    ap.add_argument("--r0", type=int, default=0)
    ap.add_argument("--r0-sweep", action="store_true")
    ap.add_argument("--time", type=int, default=120)
    ap.add_argument("--solver", default="scip",
                    choices=["cbc", "gurobi", "highs", "scip"])
    ap.add_argument("--stop-when-zero", action="store_true")
    ap.add_argument("--max-iterations", type=int, default=2000)
    args = ap.parse_args()

    if "-" in args.rounds:
        lo, hi = args.rounds.split("-")
        rounds = list(range(int(lo), int(hi) + 1))
    else:
        rounds = [int(x) for x in args.rounds.split(",")]

    if args.inactive is not None:
        inactive = parse_active(args.inactive)
        active = set((i, b) for i in range(8) for b in range(32)) - inactive
    else:
        active = parse_active(args.active)

    print(f"Input: {len(active)} active bits", file=sys.stderr)

    solver = make_solver(args.solver, args.time)

    if args.r0_sweep:
        for r0 in range(31):
            print(f"\n=== r0 = {r0} ===", file=sys.stderr)
            max_R = 0
            for R in rounds:
                t0 = time.time()
                model, k = build(R, active, r0=r0)
                balanced, iters = find_balanced_bits(
                    model, k, R, solver, args.max_iterations
                )
                n = len(balanced)
                print(f"  R={R}: {n} balanced ({iters} iters, "
                      f"{time.time()-t0:.1f}s)", file=sys.stderr)
                if n > 0:
                    max_R = R
                elif args.stop_when_zero:
                    break
            print(f"  r0={r0}: max R with balanced bits = {max_R}", file=sys.stderr)
        return

    summary = []
    for R in rounds:
        t0 = time.time()
        model, k = build(R, active, r0=args.r0)
        balanced, iters = find_balanced_bits(
            model, k, R, solver, args.max_iterations, verbose=True
        )
        n = len(balanced)
        print(f"[R={R}] Balanced: {n}/256 ({iters} iters, "
              f"{time.time()-t0:.1f}s)")
        summary.append((R, n))
        if args.stop_when_zero and n == 0:
            break

    print("\n=== SUMMARY ===")
    print("R | balanced")
    for R, n in summary:
        bar = "#" * (n // 4)
        print(f"{R:2d} | {n:3d} {bar}")


if __name__ == "__main__":
    main()
