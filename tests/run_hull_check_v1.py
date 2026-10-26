#!/usr/bin/env python3
"""run_hull_check_v1.py — Hull checks from PAPER.md §4.10.3 / §4.10.5 (v0.1).

Verifies:
  1. offset-20 backward R=14 is isolated in its hull (hull_count=1)
  2. its empirical correlation matches 2^-5 (via verify_beam_trail.py)
  3. r0=23 forward cancels from R=8
  4. R=17 best pairs cancel (scan_endpairs.py)
"""
import sys, os, subprocess

os.environ.pop('MYSX_ROT_CAL', None)

# Required inputs
required = ["misc/beam_bwd.json", "misc/beam_full.json",
            "misc/beam_paths_bwd20.json", "misc/beam_paths_fwd23.json"]
missing = [f for f in required if not os.path.exists(f)]
if missing:
    print(f"ERROR: missing files: {missing}", file=sys.stderr)
    print("  These should be in misc/ if the paper's beam runs were committed.", file=sys.stderr)
    sys.exit(1)

checks = [
    ("offset-20 backward R=14 (isolated, corr ~ 2^-5)",
     "python3 misc/verify_beam_trail.py misc/beam_bwd.json 20 --R 14 --n 17"),
    ("offset-20 backward R=14 hull_count (expect 1)",
     "python3 misc/hull_count.py misc/beam_bwd.json 20 --R 14 --wmax 5"),
    ("r0=23 forward cancels from R=8",
     "python3 misc/verify_beam_trail.py misc/beam_full.json 23 --R 14 --n 17"),
    ("hull_bidir offset-20 bwd R=16 (exact hull ~ 2^-11)",
     "python3 misc/hull_bidir.py misc/beam_paths_bwd20.json 20 --R 16 --wmax 14 --keys 2"),
    ("hull_bidir offset-20 bwd R=17 (cancel within budget)",
     "python3 misc/hull_bidir.py misc/beam_paths_bwd20.json 20 --R 17 --wmax 18 --keys 2"),
    ("scan_endpairs R=17 (best pairs cancel)",
     "python3 misc/scan_endpairs.py --R 17 --cells 20:backward,23:forward --topk 8"),
]

failed = []
for name, cmd in checks:
    print(f"\n=== {name} ===")
    r = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=1800)
    print(r.stdout)
    if r.returncode != 0:
        print(f"FAIL: {name}", file=sys.stderr)
        print(f"  stderr: {r.stderr[-500:]}", file=sys.stderr)
        failed.append(name)

if failed:
    print(f"\nFAILED: {failed}", file=sys.stderr); sys.exit(1)
print("\nOK: all hull checks passed")
