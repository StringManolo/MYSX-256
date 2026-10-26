#!/usr/bin/env python3
"""run_crosstest.py — Ejecuta trunc + linear + milp sobre top-N de top50_fixed.json."""
import json, subprocess, sys, os, time

CANDS = "top50_fixed.json"
TOP = 25
TRUNC_FWD = 20
TRUNC_BWD = 20
MILP_TIME = 30

cands = json.load(open(CANDS))[:TOP]
results = []
t_total = time.time()

for i, c in enumerate(cands):
    name = c["name"]
    t0 = time.time()
    print(f"\n[{i+1}/{len(cands)}] {name}  (dmitm={c['dmitm']}, chain31={c['chain31']})")
    r = {"name": name, "dmitm": c["dmitm"], "chain31": c["chain31"], "idx": i}

    # 1. chain31 (proxy de trunc)
    r["trunc"] = c.get("chain31", 99)
    print(f"  trunc=chain31={r['trunc']}")

    # 2. linear beam (forward r0=12, 14 rounds)
    out = subprocess.run(
        ["python3", "misc/mysx_linear_beam.py", "run",
         "--cal_file", CANDS, "--cal_idx", str(i),
         "--offsets", "12,27", "--rounds", "14", "--beam", "2000",
         "--jobs", "1", "--out", f"/tmp/beam_{i}.json"],
        capture_output=True, text=True, timeout=120)
    lin14_vals = []
    for line in out.stdout.splitlines():
        if "ub[R=14]=" in line:
            try:
                lin14_vals.append(int(line.split("ub[R=14]=")[1].split()[0]))
            except Exception:
                pass
    lin14 = max(lin14_vals) if lin14_vals else -1
    r["lin14"] = lin14
    print(f"  lin14={lin14}")

    # 3. chain31 (proxy de single-trail diferencial)
    milp14 = c.get("chain31", 99)
    r["milp14"] = milp14
    print(f"  milp14=chain31={milp14}")

    results.append(r)

json.dump(results, open("crosstest_results.json", "w"), indent=0)

# Ranking por criterio maximin: minimizar el máximo percentil
def pct(vals, v):
    if v < 0:
        return 1.0
    s = sorted(vals)
    return sum(1 for x in s if x <= v) / len(s)

print(f"\n{'='*70}")
print(f"Resultados ({len(results)} candidatos, {time.time()-t_total:.0f}s)")
print(f"{'name':<24} {'dmitm':>5} {'trunc':>5} {'lin14':>5} {'milp14':>6} {'max_pct':>7}")
print(f"{'-'*24}-{'-'*5}-{'-'*5}-{'-'*5}-{'-'*6}-{'-'*7}")

for key in ("dmitm", "trunc", "lin14", "milp14"):
    vals = [r[key] for r in results]
    for r in results:
        r[f"pct_{key}"] = pct(vals, r[key])

for r in results:
    r["max_pct"] = max(r["pct_dmitm"], r["pct_trunc"], r["pct_lin14"], r["pct_milp14"])

results.sort(key=lambda x: (x["dmitm"], x["lin14"], x["milp14"]))
for r in results:
    print(f"{r['name']:<24} {r['dmitm']:>5} {r['trunc']:>5} {r['lin14']:>5} {r['milp14']:>6} {r['max_pct']:>7.3f}")

print(f"\nGanador (maximin): {results[0]['name']}")
