#!/usr/bin/env python3
"""
run_full_analysis.py — Análisis completo forward + backward de un calendario.
Usado por WF2 (deep_dive). Lee --cal_file / --cal_idx o MYSX_ROT_CAL.
"""
import json, subprocess, sys, os, time, tempfile, re

def write_temp(cal):
    f = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    json.dump([{'name': 'cand', 'cal': cal}], f); f.close()
    return f.name

def run_cmd(cmd, timeout, env=None):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout, env=env)
        return out.stdout
    except subprocess.TimeoutExpired:
        return ''

def main():
    cand_file = sys.argv[1]
    name = sys.argv[2] if len(sys.argv) > 2 else 'cand'
    cands = json.load(open(cand_file))
    cal = cands[0]['cal']
    env = os.environ.copy()
    env['MYSX_ROT_CAL'] = ','.join(str(x) for x in cal[:31])

    tmp = write_temp(cal)
    results = {'name': name}
    t_start = time.time()

    print(f"\n=== {name} ===\n")

    # 1. DMITM exact
    t0 = time.time()
    out = run_cmd(['python3', 'cryptanalysis/DMITM/dmitm_verify.py', 'exact'], 180, env)
    m = re.findall(r'total=(\d+)', out)
    results['dmitm_exact'] = int(m[-1]) if m else -1
    print(f"dmitm_exact    = {results['dmitm_exact']:>3}  ({time.time()-t0:.0f}s)")

    # 2. DMITM trunc
    t0 = time.time()
    out = run_cmd(['python3', 'cryptanalysis/DMITM/dmitm_trunc.py', 'search',
                   '--cal_file', tmp, '--cal_idx', '0',
                   '--max_fwd', '20', '--max_bwd', '20', '--n_bits', '64', '--top', '1'], 900, env)
    m = re.search(r'(\d+) imposibles', out)
    results['dmitm_trunc'] = int(m.group(1)) if m else -1
    print(f"dmitm_trunc    = {results['dmitm_trunc']:>3}  ({time.time()-t0:.0f}s)")

    # 3. Linear beam forward R=10, R=14
    for R in (10, 14):
        t0 = time.time()
        out = run_cmd(['python3', 'misc/mysx_linear_beam.py', 'run',
                       '--cal_file', tmp, '--cal_idx', '0',
                       '--offsets', '0-30', '--rounds', str(R), '--beam', '2000',
                       '--jobs', '1', '--out', f'/tmp/beam_fwd_{R}.json'], 900, env)
        vals = [int(x) for x in re.findall(rf'ub\[R={R}\]=(\d+)', out)]
        results[f'lin_fwd_{R}'] = min(vals) if vals else -1
        print(f"lin_fwd_{R:<2}     = {results[f'lin_fwd_{R}']:>3}  ({time.time()-t0:.0f}s)")

    # 4. Linear beam backward R=10, R=14
    for R in (10, 14):
        t0 = time.time()
        out = run_cmd(['python3', 'misc/mysx_linear_beam.py', 'run',
                       '--cal_file', tmp, '--cal_idx', '0',
                       '--offsets', '0-30', '--rounds', str(R), '--beam', '2000',
                       '--direction', 'backward',
                       '--jobs', '1', '--out', f'/tmp/beam_bwd_{R}.json'], 900, env)
        vals = [int(x) for x in re.findall(rf'ub\[R={R}\]=(\d+)', out)]
        results[f'lin_bwd_{R}'] = min(vals) if vals else -1
        print(f"lin_bwd_{R:<2}     = {results[f'lin_bwd_{R}']:>3}  ({time.time()-t0:.0f}s)")

    # 5. MILP forward R=8, R=10, R=12 (r0=0,10)
    for R in (8, 10, 12):
        for r0 in (0, 10):
            t0 = time.time()
            out = run_cmd(['python3', 'misc/mysx_milp2.py',
                           '--cal_file', tmp, '--cal_idx', '0',
                           '--rounds', str(R), '--input-bit', '63',
                           '--r0', str(r0), '--solver', 'cbc',
                           '--gap-rel', '0.2', '--time-limit', '120'], 200, env)
            m = re.search(r'peso mínimo=\s*(\d+)', out)
            results[f'milp_R{R}_r0{r0}'] = int(m.group(1)) if m else -1
            print(f"milp_R{R}_r0{r0:<2}   = {results[f'milp_R{R}_r0{r0}']:>3}  ({time.time()-t0:.0f}s)")

    os.unlink(tmp)
    json.dump(results, open(f'full_{name}.json', 'w'), indent=2)
    print(f"\nTotal: {time.time()-t_start:.0f}s")
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
