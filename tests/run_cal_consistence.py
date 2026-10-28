#!/usr/bin/env python3
"""
tests/run_cal_consistency.py - El calendario v0.2 es IDENTICO en todo el repositorio.

Referencia: tests/manifest.json["v02_cal"]. Busca en los ficheros listados (y en todos los
workflows) cualquier secuencia de 31 enteros que sea una permutacion de 1..31 distinta de la
consecutiva; TODAS deben coincidir con la referencia. Exige ademas que las fuentes
obligatorias contengan la secuencia: mysx.prod.js, CALENDAR_v02.txt, PAPER.md.
"""
import glob, json, os, re, sys

ROOT = os.environ.get('MYSX_REPO_ROOT', '.')
SEQ = re.compile(r'\d+(?:\s*,\s*\d+){30}')
MANDATORY = ['mysx.prod.js', 'calendar/CALENDAR_v02.txt', 'PAPER.md']
OPTIONAL = ['SPEC.md', 'README.md', 'SECURITY.md', 'misc/mysx.prod.js',
            'cryptanalysis/DMITM/dmitm_trunc_v2.py', 'cryptanalysis/DMITM/dmitm_trunc_v3.py',
            'tests/run_trunc_witness.py', 'tests/gen_v2_kat.py', 'tests/mysx_v2.test.js',
            'tests/run_avalanche_reach.py', 'verify_v2_usage.js', 'KAT_v2.json'] + \
           [os.path.relpath(p, ROOT) for p in glob.glob(os.path.join(ROOT, '.github/workflows/*.yml'))]

def seqs(path):
    try: txt = open(os.path.join(ROOT, path), encoding='utf-8', errors='replace').read()
    except FileNotFoundError: return None
    out = []
    for m in SEQ.finditer(txt):
        v = [int(x) for x in re.split(r'\s*,\s*', m.group(0))]
        if sorted(v) == list(range(1, 32)) and v != list(range(1, 32)): out.append(v)
    return out

def main():
    ref = [int(x) for x in json.load(open(os.path.join(ROOT, 'tests/manifest.json')))['v02_cal'].split(',')]
    if sorted(ref) != list(range(1, 32)):
        print('FAIL: manifest v02_cal no es una permutacion de 1..31'); sys.exit(1)
    bad, checked = [], 0
    for f in MANDATORY + OPTIONAL:
        s = seqs(f)
        if s is None:
            if f in MANDATORY: bad.append(f'{f}: fichero obligatorio ausente')
            continue
        if f in MANDATORY and not s: bad.append(f'{f}: no contiene el calendario')
        for v in s:
            checked += 1
            if v != ref: bad.append(f'{f}: calendario DISTINTO {v}')
    if bad:
        print('FAIL:'); [print('  -', b) for b in bad]; sys.exit(1)
    print(f'OK: calendar consistent ({checked} occurrences, reference = manifest v02_cal)')

if __name__ == '__main__':
    main()
