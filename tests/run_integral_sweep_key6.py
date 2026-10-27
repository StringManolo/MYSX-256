#!/usr/bin/env python3
"""run_integral_sweep_key6.py — 6 key offsets, R=5-6, one subprocess per offset."""
import subprocess, sys

OFFSETS = [0, 5, 10, 15, 20, 27]
succeeded, failed = 0, []
for r0 in OFFSETS:
    print(f"\n=== r0={r0} ===", flush=True)
    r = subprocess.run(
        ["python3", "misc/mysx_division_property_v2.py",
         "--rounds", "5-6", "--active", "word0",
         "--r0", str(r0), "--solver", "highs"],
        capture_output=True, text=True)
    print(r.stdout)
    if r.returncode != 0:
        print(r.stderr, file=sys.stderr)
        failed.append(r0)
    else:
        succeeded += 1

print(f"\nSummary: {succeeded}/{len(OFFSETS)} offsets")
if failed:
    print(f"Failed: {failed}", file=sys.stderr)
    sys.exit(1)
print(f"OK: all {len(OFFSETS)} offsets measured")
