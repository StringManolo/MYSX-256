#!/usr/bin/env python3
"""
tests/check_coverage.py - Cobertura paper -> tests.

tests/coverage_map.json lista cada afirmacion de los papers (v1 y v2) con los tests que la respaldan y
una calidad: ok (el test asierta el valor del paper), weak (el test corre pero no asierta el valor),
missing (sin test). Este script comprueba la integridad (todos los IDs existen en el manifest) y
resume el estado. Con --strict falla si queda algun 'missing'; con --strict-weak tambien con 'weak'.
"""
import argparse, json, os, sys
ap = argparse.ArgumentParser(); ap.add_argument('--strict', action='store_true'); ap.add_argument('--strict-weak', action='store_true')
ap.add_argument('--manifest', default='tests/manifest.json'); ap.add_argument('--map', default='tests/coverage_map.json')
a = ap.parse_args()
manifest = json.load(open(a.manifest))['tests']; cov = json.load(open(a.map))
errors, by = [], {'ok': [], 'weak': [], 'missing': []}
for c in cov:
    by[c['quality']].append(c)
    for t in c['tests']:
        if t not in manifest: errors.append(f"{c['id']}: test '{t}' no existe en el manifest")
    if c['quality'] == 'missing' and c['tests']: errors.append(f"{c['id']}: 'missing' con tests asignados")
    if c['quality'] != 'missing' and not c['tests']: errors.append(f"{c['id']}: sin tests pero calidad {c['quality']}")
n = len(cov)
print(f"COVERAGE: {len(by['ok'])}/{n} ok, {len(by['weak'])} weak, {len(by['missing'])} missing")
for q in ('missing', 'weak'):
    if by[q]:
        print(f"\n[{q.upper()}]")
        for c in by[q]: print(f"  - {c['id']:24s} {c['paper']:14s} {c['claim'][:70]}\n      -> {c['note']}")
if errors:
    print("\nERRORES DE INTEGRIDAD:"); [print("  -", e) for e in errors]; sys.exit(1)
if a.strict and by['missing']: print("\nFAIL (--strict): hay afirmaciones sin test"); sys.exit(1)
if a.strict_weak and (by['missing'] or by['weak']): print("\nFAIL (--strict-weak)"); sys.exit(1)
print("\nOK: coverage map is consistent with the manifest")
