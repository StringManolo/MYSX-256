#!/usr/bin/env python3
"""apply_cal_patch.py — Añade --cal_file/--cal_idx a mysx_linear_beam.py y mysx_milp2.py."""

def patch_beam(path):
    src = open(path).read()
    src = src.replace(
        'def beam_run(o, rounds, starts, beam, hmax, rcap, gkeep, want_paths=(), direction="forward"):',
        'def beam_run(o, rounds, starts, beam, hmax, rcap, gkeep, want_paths=(), direction="forward", cal=None):')
    src = src.replace(
        'sh = ((o - r) % PERIOD) + 1\n            gen = expand_backward',
        'sh = cal[(o - r) % PERIOD] if cal else ((o - r) % PERIOD) + 1\n            gen = expand_backward')
    src = src.replace(
        'sh = ((o + r) % PERIOD) + 1\n            gen = expand',
        'sh = cal[(o + r) % PERIOD] if cal else ((o + r) % PERIOD) + 1\n            gen = expand')
    src = src.replace(
        'jobs = [(o, args.rounds, starts, args.beam, args.cell_h, args.round_cost, args.g_keep, want,\n             args.direction) for o in offsets]',
        'cal = None\n'
        '    if args.cal_file:\n'
        '        cands = json.load(open(args.cal_file))\n'
        '        c = cands[args.cal_idx]\n'
        '        cal = [c["cal"][r % 31] for r in range(31)]\n'
        '        print(f"cal: {c.get(\'name\', args.cal_idx)}")\n'
        '    jobs = [(o, args.rounds, starts, args.beam, args.cell_h, args.round_cost, args.g_keep, want,\n'
        '             args.direction, cal) for o in offsets]')
    src = src.replace(
        'p.add_argument("--out", default="beam_results.json")',
        'p.add_argument("--out", default="beam_results.json")\n'
        '    p.add_argument("--cal_file", default=None)\n'
        '    p.add_argument("--cal_idx", type=int, default=0)')
    open(path, "w").write(src)
    print(f"patched {path}")


def patch_milp(path):
    src = open(path).read()
    if "import json" not in src:
        src = src.replace("import argparse\nimport sys", "import argparse\nimport json\nimport sys")
    src = src.replace(
        'def build_milp(rounds, input_diff, solver_cmd, cutoff=None, r0=0):',
        'def build_milp(rounds, input_diff, solver_cmd, cutoff=None, r0=0, cal=None):')
    src = src.replace(
        'shift = ((r + r0) % SHIFT_MOD) + 1',
        'shift = cal[(r + r0) % SHIFT_MOD] if cal else ((r + r0) % SHIFT_MOD) + 1')
    src = src.replace(
        'prob, s, _ = build_milp(rounds, {(i, j): 1},\n                                        solver_cmd, cutoff=args.cutoff,\n                                        r0=args.r0)',
        'prob, s, _ = build_milp(rounds, {(i, j): 1},\n                                        solver_cmd, cutoff=args.cutoff,\n                                        r0=args.r0, cal=cal)')
    src = src.replace(
        'ap.add_argument("--validate", action="store_true",\n                    help="Solo ejecutar tests de validación")',
        'ap.add_argument("--validate", action="store_true",\n                    help="Solo ejecutar tests de validación")\n'
        '    ap.add_argument("--cal_file", default=None)\n'
        '    ap.add_argument("--cal_idx", type=int, default=0)')
    src = src.replace(
        'solver_cmd = make_solver(args.solver, args.gap_rel,\n                             args.time_limit, args.threads)',
        'cal = None\n'
        '    if args.cal_file:\n'
        '        cands = json.load(open(args.cal_file))\n'
        '        c = cands[args.cal_idx]\n'
        '        cal = [c["cal"][r % 31] for r in range(31)]\n'
        '        print(f"cal: {c.get(\'name\', args.cal_idx)}")\n'
        '    solver_cmd = make_solver(args.solver, args.gap_rel,\n'
        '                             args.time_limit, args.threads)')
    open(path, "w").write(src)
    print(f"patched {path}")


if __name__ == "__main__":
    patch_beam("misc/mysx_linear_beam.py")
    patch_milp("misc/mysx_milp2.py")
