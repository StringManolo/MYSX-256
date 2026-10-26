#!/usr/bin/env python3
"""
run_5round_test.py — Screening R=5 + DP R=4.
Compara: 10 mejores randoms + affine_k22 + affine_k1 + affine_k2.

Métricas:
  milp_w5       min differential weight a R=5 (r0∈{0,10,20}).  Alto=seguro.
  lin_w5        min linear weight a R=5 (31 offsets, beam 1200). Alto=seguro.
  dmitm_len     mejor imposible global.                         Bajo=seguro.
  dp3_balanced  balanced bits en R=3 (word0, r0=0).             Bajo=seguro.
"""
import json, subprocess, sys, os, time, tempfile, re

CANDS = "top50_fixed.json"
OUT = "test5_results.json"
N_RANDOM = 10
MILP_INPUT = 63
MILP_R0S = (0, 10, 20)
MILP_TIMEOUT = 30
BEAM_TIMEOUT = 300
DMITM_TIMEOUT = 60
DP_TIMEOUT = 900       # generoso: R=3 puede tardar 50-200s en P40
DP_ROUNDS = 4
DP_ACTIVE = "word0"


def make_candidate_list():
    cands = json.load(open(CANDS))
    selected = list(cands[:N_RANDOM])
    k22 = next((c for c in cands if 'affine_k22' in c['name']), None)
    if k22 and k22 not in selected:
        selected.append(k22)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from search_mysx_deep import cal_affine_k
    for k in (1, 2):
        name = f'affine_k{k}'
        stored = next((c for c in cands if c['name'] == name), None)
        selected.append(stored if stored else {'name': name, 'cal': cal_affine_k(k)})
    return selected


def write_temp(cand):
    f = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    json.dump([cand], f); f.close()
    return f.name


def run_milp(cand_file):
    min_w = 999
    for r0 in MILP_R0S:
        try:
            out = subprocess.run(
                ['python3', 'misc/mysx_milp2.py',
                 '--cal_file', cand_file, '--cal_idx', '0',
                 '--rounds', '5', '--input-bit', str(MILP_INPUT),
                 '--r0', str(r0), '--solver', 'cbc',
                 '--gap-rel', '0.2', '--time-limit', '15'],
                capture_output=True, text=True, timeout=MILP_TIMEOUT)
            for line in out.stdout.splitlines():
                if 'peso mínimo' in line:
                    try:
                        w = int(line.split('peso mínimo=')[1].split()[0])
                        min_w = min(min_w, w)
                    except ValueError:
                        pass
        except subprocess.TimeoutExpired:
            pass
    return min_w if min_w < 999 else -1


def run_linear(cand_file):
    try:
        out = subprocess.run(
            ['python3', 'misc/mysx_linear_beam.py', 'run',
             '--cal_file', cand_file, '--cal_idx', '0',
             '--offsets', '0-30', '--rounds', '5', '--beam', '1200',
             '--jobs', '1', '--out', '/tmp/beam5.json'],
            capture_output=True, text=True, timeout=BEAM_TIMEOUT)
    except subprocess.TimeoutExpired:
        return -1
    vals = []
    for line in out.stdout.splitlines():
        if 'ub[R=5]=' in line:
            try:
                vals.append(int(line.split('ub[R=5]=')[1].split()[0]))
            except ValueError:
                pass
    return min(vals) if vals else -1


def run_dmitm(cand):
    env = os.environ.copy()
    env['MYSX_ROT_CAL'] = ','.join(str(x) for x in cand['cal'][:31])
    try:
        out = subprocess.run(
            ['python3', 'cryptanalysis/DMITM/dmitm_verify.py', 'exact'],
            capture_output=True, text=True, timeout=DMITM_TIMEOUT, env=env)
    except subprocess.TimeoutExpired:
        return -1
    for line in out.stdout.splitlines():
        if 'total=' in line and 'dim_in=' in line:
            try:
                return int(line.split('total=')[1].split()[0])
            except ValueError:
                pass
    return -1


def run_dp(cand):
    """Division property: balanced bits at R=3, word0, r0=0."""
    env = os.environ.copy()
    env['MYSX_ROT_CAL'] = ','.join(str(x) for x in cand['cal'][:31])
    try:
        out = subprocess.run(
            ['python3', 'misc/mysx_division_property_v2.py',
             '--rounds', str(DP_ROUNDS), '--active', DP_ACTIVE,
             '--r0', '0', '--solver', 'scip'],
            capture_output=True, text=True, timeout=DP_TIMEOUT, env=env)
    except subprocess.TimeoutExpired:
        return -1
    m = re.search(rf'\[R={DP_ROUNDS}\]\s+Balanced:\s+(\d+)/256', out.stdout)
    if m:
        return int(m.group(1))
    for line in out.stdout.splitlines():
        if line.strip().startswith(f'{DP_ROUNDS} |'):
            try:
                return int(line.split('|')[1].split()[0])
            except (ValueError, IndexError):
                pass
    return -1


def main():
    cands = make_candidate_list()
    print(f"Testing {len(cands)} candidates (milp R=5, linear R=5, DP R=3, DMITM exact)\n")
    results = []
    t_start = time.time()
    for i, c in enumerate(cands):
        t0 = time.time()
        print(f"[{i+1}/{len(cands)}] {c['name']} "
              f"(dmitm14={c.get('dmitm')}, chain31={c.get('chain31')})")
        cand_file = write_temp(c)
        try:
            milp_w = run_milp(cand_file)
            t1 = time.time()
            print(f"  milp_w5       = {milp_w}    ({t1-t0:.0f}s)")
            lin_w = run_linear(cand_file)
            t2 = time.time()
            print(f"  lin_w5        = {lin_w}    ({t2-t1:.0f}s)")
            dmitm_len = run_dmitm(c)
            t3 = time.time()
            print(f"  dmitm_len     = {dmitm_len}    ({t3-t2:.0f}s)")
            dp3 = run_dp(c)
            t4 = time.time()
            print(f"  dp3_balanced  = {dp3}    ({t4-t3:.0f}s)")
            results.append({
                'name': c['name'],
                'dmitm14': c.get('dmitm'),
                'chain31': c.get('chain31'),
                'milp_w5': milp_w,
                'lin_w5': lin_w,
                'dmitm_len': dmitm_len,
                'dp3_balanced': dp3,
            })
        finally:
            os.unlink(cand_file)
        print(f"  TOTAL {time.time()-t0:.1f}s\n")

    json.dump(results, open(OUT, 'w'), indent=0)
    rank_and_print(results, t_start)


def rank_and_print(results, t_start):
    n = len(results)
    valid = [r for r in results if r['milp_w5'] >= 0 and r['lin_w5'] >= 0
             and r['dmitm_len'] >= 0 and r['dp3_balanced'] >= 0]

    def pct_higher(r, key):
        if r['milp_w5'] < 0: return 0
        sorted_vals = sorted(x[key] for x in valid)
        rank = sum(1 for v in sorted_vals if v < r[key])
        ties = sum(1 for v in sorted_vals if v == r[key])
        return (rank + ties/2) / max(1, len(valid) - 1)

    def pct_lower(r, key):
        if r[key] < 0: return 0
        sorted_vals = sorted(x[key] for x in valid)
        rank = sum(1 for v in sorted_vals if v > r[key])
        ties = sum(1 for v in sorted_vals if v == r[key])
        return (rank + ties/2) / max(1, len(valid) - 1)

    for r in results:
        if r in valid:
            r['score'] = (pct_higher(r, 'milp_w5') + pct_higher(r, 'lin_w5')
                          + pct_lower(r, 'dmitm_len') + pct_lower(r, 'dp3_balanced'))
        else:
            r['score'] = -1

    results.sort(key=lambda r: r['score'], reverse=True)

    print('='*100)
    print(f"{'name':<20} {'dm14':>5} {'ch31':>5} {'milp5':>6} {'lin5':>5} "
          f"{'dmlen':>6} {'dp3':>5} {'score':>6}")
    print('-'*100)
    for r in results:
        marker = ' ←' if r['name'] in ('affine_k1', 'affine_k2', 'affine_k22') else ''
        print(f"{r['name']:<20} {str(r['dmitm14']):>5} {str(r['chain31']):>5} "
              f"{str(r['milp_w5']):>6} {str(r['lin_w5']):>5} "
              f"{str(r['dmitm_len']):>6} {str(r['dp3_balanced']):>5} "
              f"{r['score']:>6.2f}{marker}")
    print(f"\nTotal: {time.time()-t_start:.0f}s")
    print(f"Guardado: {OUT}")
    print("\nScore = percentil medio. 1.00 = mejor en todas, 0.00 = peor. "
          "Alto=seguro.")


if __name__ == '__main__':
    main()
