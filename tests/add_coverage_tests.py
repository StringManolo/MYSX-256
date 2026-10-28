#!/usr/bin/env python3
"""
tests/add_coverage_tests.py - Anade/actualiza entradas del manifest (idempotente). Hace copia .bak.
Uso (raiz del repo): python3 tests/add_coverage_tests.py
"""
import copy, json, os, shutil, sys
P = 'tests/manifest.json'
m = json.load(open(P)); T = m['tests']
shutil.copy(P, P + '.bak')
PIP = ["pip install -q pulp highspy"]
def rc(): return {"type": "returncode_zero"}
def has(v): return {"type": "output_contains", "value": v}
def rx(p, f=None):
    d = {"type": "regex", "pattern": p}
    if f: d["flags"] = f
    return d
def new(i, name, group, script, assertions, minutes=10, env=None, setup=None, notes=None):
    e = {"name": name, "group": group, "status": "ready"}
    if setup: e["setup"] = setup
    e["script"] = script
    if env: e["env"] = env
    e["timeout_minutes"] = minutes; e["deterministic"] = True
    if notes: e["notes"] = notes
    e["assertions"] = assertions
    T[i] = e

new("avalanche_reach_v1", "Structural min-reach ladder, v0.1 (matches paper avalanche column)", "differential",
    "python3 tests/run_avalanche_reach.py --cal k1", [rc(), has("OK: v0.1 structural min-reach matches the paper table"), has("full reach (256) at r=15")], 3)
new("avalanche_reach_v02", "Structural min-reach ladder, v0.2 (must differ from v0.1)", "differential",
    "python3 tests/run_avalanche_reach.py --cal v02", [rc(), has("OK: v0.2 min-reach table matches the expected values"),
    rx(r"OK: v0\.2 differs from v0\.1 at (1[0-5]|[89]) of 15 rounds"), has("full reach (256) at r=15")], 3, env={"MYSX_ROT_CAL": "${v02_cal}"})
new("cal_consistency", "v0.2 calendar identical across code, manifest, workflows, KAT, paper", "basic",
    "python3 tests/run_cal_consistency.py", [rc(), rx(r"OK: calendar consistent \(\d+ occurrences")], 2)
new("cal_percentile_v1", "v0.1 vs v0.2 against 3000 random calendars (exact DMITM / chain)", "impossible",
    "python3 tests/run_cal_percentile.py", [rc(), has("exact DMITM min/median/max = 10/13/21"), has("weight-0 chain min/median/max = 5/8/14"),
    has("fraction of random calendars with DMITM >= 17: 2.3%"), has("fraction of random calendars with chain >= 13: 0.2%"),
    has("v0.2: DMITM=9 chain=5")], 20, setup=PIP)
new("design_control", "Control: 40 random byte permutations and (k*r mod 31) schedules", "impossible",
    "python3 cryptanalysis/DMITM/dmitm_verify.py design --perms 40",
    [rc(), has("max cadena media 13.0 (rango 5-24), imposible medio 21.4 (rango 10-34)"),
     has("MYZ_PERM, periodo 31 : max cadena peso0 = 13,  mejor imposible exacto = 17"),
     has("shift=(2*r mod 31)+1 : max cadena = 9,  mejor imposible = 12"), has("shift=(3*r mod 31)+1 : max cadena = 7,  mejor imposible = 11"),
     has("shift=(5*r mod 31)+1 : max cadena = 7,  mejor imposible = 13"), has("shift=(7*r mod 31)+1 : max cadena = 6,  mejor imposible = 11")], 10, setup=PIP)
new("wf2_consistency", "Paper s4.13 table == wf2_deep_summary.json (and metric directions)", "impossible",
    "python3 tests/run_wf2_consistency.py", [rc(), has("OK: wf2 table matches the paper")], 2)
new("coverage_map", "Coverage map paper->tests is consistent with the manifest", "basic",
    "python3 tests/check_coverage.py", [rc(), has("OK: coverage map is consistent with the manifest")], 2)
new("integral_v1_R5_w0", "Integral DP R=5 word0, v0.1 (paper dp5 = 21/256)", "integral",
    "python3 misc/mysx_division_property_v2.py --rounds 5 --active word0 --r0 0 --solver highs",
    [rc(), rx(r"\[R=5\]\s+Balanced:\s+21/256")], 30, setup=PIP,
    notes="Valor 21 tomado del paper v2/wf2; si falla, el paper esta mal (no el test).")
for nm, act, vals in (("w0", "word0", [26, 12, 6, 3, 1, 0]), ("w04", "word0,word4", [15, 9, 4, 2, 1, 0])):
    new(f"integral_v1_trace_r15_{nm}", f"Integral DP trace R=6..11 at r0=15, {act}, v0.1", "integral",
        f"python3 misc/mysx_division_property_v2.py --rounds 6-11 --active {act} --r0 15 --solver highs",
        [rc()] + [rx(rf"\[R={R}\]\s+Balanced:\s+{v}/256") for R, v in zip(range(6, 12), vals)], 60, setup=PIP)

# refuerzo de tests existentes con los valores del paper
V1_CHAIN = [3,3,3,3,3,3,3,4,4,5,13,12,11,10,9,8,7,6,5,5,5,4,4,4,4,4,4,3,3,3,4]
V02_CHAIN = {5: [3,4,13,16,17,20,24,27,28], 4: [0,5,6,8,9,12,14,15,18,19,21,22,25,29,30], 3: [1,2,7,10,11,23,26]}
def rows(pairs): return [rx(rf"^\s*{r0}\s+{n}\b", "MULTILINE") for r0, n in pairs]
for tid, pairs in (("diff_free_chain_full_v1", list(enumerate(V1_CHAIN))),
                   ("diff_free_chain_v02", [(r0, n) for n, rs in V02_CHAIN.items() for r0 in rs])):
    have = {json.dumps(a, sort_keys=True) for a in T[tid]["assertions"]}
    for a in rows(sorted(pairs)):
        if json.dumps(a, sort_keys=True) not in have: T[tid]["assertions"].append(a)
json.dump(m, open(P, "w"), indent=2)
print(f"manifest actualizado: {len(T)} tests (copia en {P}.bak)")
