#!/usr/bin/env python3
"""
search_mysx_cal.py — Búsqueda de calendarios de rotación óptimos para MYSX.
La permutación Myszkowski (MYZ_PERM) queda FIJA; solo varía el calendario.

Tipos de calendario:
  affine_k      (k·r mod 31)+1                k ∈ 1..30
  power_e       (r^e mod 31)+1                e ∈ {7,11,13,17,19,23,29}
  bitrev        bit-reverse(5 bits)
  inverse       (r^{-1} mod 31)+1
  interleaved   0,16,1,17,2,18,...,14,30,15
  composition   (k · r^e mod 31)+1            k∈{2,3,5,7}, e∈{7,13}
  random        permutación aleatoria de 0..30
  original      (r mod 31)+1                  baseline

Uso:
  python3 search_mysx_cal.py all --mode structured                    # 48 cal, ~1 min
  python3 search_mysx_cal.py all --mode all --n_random 200 --top_k 50 # 248 cal, ~6 min
  python3 search_mysx_cal.py stage1 --mode structured                 # solo stage1
  python3 search_mysx_cal.py stage2 --top_k 50                        # refina stage1
  python3 search_mysx_cal.py stage3 --top_k 20                        # exacto
"""
import sys, os, json, random, math, time, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dmitm_verify import Lin, fwd_spaces, exact_ids, MYZ_PERM

N_ROUNDS = 128
PERIOD = 31


# ============================================================
# Generadores de calendario (listas de 128 valores, 1..31)
# ============================================================
def _from_perm31(seq31):
    """Valida que seq31 sea permutación de 0..30 y expande a 128 rondas."""
    assert len(seq31) == PERIOD, f"esperado {PERIOD}, got {len(seq31)}"
    assert sorted(seq31) == list(range(PERIOD)), "no es permutación de 0..30"
    return [(seq31[r % PERIOD] + 1) for r in range(N_ROUNDS)]


def cal_affine_k(k):
    return _from_perm31([(k * r) % PERIOD for r in range(PERIOD)])


def cal_power_e(e):
    if math.gcd(e, PERIOD - 1) != 1:
        return None
    return _from_perm31([pow(r, e, PERIOD) for r in range(PERIOD)])


def cal_bitrev():
    def rev5(x):
        return int(f'{x:05b}'[::-1], 2)
    return _from_perm31([rev5(r) for r in range(PERIOD)])


def cal_inverse():
    def inv(x):
        return 0 if x == 0 else pow(x, PERIOD - 2, PERIOD)
    return _from_perm31([inv(r) for r in range(PERIOD)])


def cal_interleaved():
    seq = []
    for i in range(16):
        seq.append(i)
        if 16 + i < PERIOD:
            seq.append(16 + i)
    return _from_perm31(seq)


def cal_affine_power(k, e):
    if math.gcd(e, PERIOD - 1) != 1:
        return None
    return _from_perm31([(k * pow(r, e, PERIOD)) % PERIOD for r in range(PERIOD)])


def cal_random(rng):
    seq = list(range(PERIOD))
    rng.shuffle(seq)
    return _from_perm31(seq)


def gen_calendars(mode, n_random=200, seed=0):
    out = []
    if mode in ('affine', 'structured', 'all'):
        for k in range(1, PERIOD):
            out.append((f"affine_k{k}", cal_affine_k(k)))
    if mode in ('power', 'structured', 'all'):
        for e in (7, 11, 13, 17, 19, 23, 29):
            c = cal_power_e(e)
            if c:
                out.append((f"power_e{e}", c))
    if mode in ('bitrev', 'structured', 'all'):
        out.append(("bitrev", cal_bitrev()))
    if mode in ('inverse', 'structured', 'all'):
        out.append(("inverse", cal_inverse()))
    if mode in ('interleaved', 'structured', 'all'):
        out.append(("interleaved", cal_interleaved()))
    if mode in ('composition', 'structured', 'all'):
        for k in (2, 3, 5, 7):
            for e in (7, 13):
                c = cal_affine_power(k, e)
                if c:
                    out.append((f"affine{k}_power{e}", c))
    if mode in ('random', 'all'):
        rng = random.Random(seed)
        for i in range(n_random):
            out.append((f"random_{i}", cal_random(rng)))
    if mode == 'original':
        out.append(("original_seq", cal_affine_k(1)))
    return out


# ============================================================
# Lin con calendario explícito (permutación fija = MYZ_PERM)
# ============================================================
class LinCal(Lin):
    def __init__(self, cal):
        super().__init__(MYZ_PERM, period=PERIOD)
        self.cal = cal

    def sh(self, r):
        return self.cal[r]


# ============================================================
# Scoring
# ============================================================
def score_cheap(lin):
    """Chain max en offset 10 (el del paper §3.5). Rápido."""
    S = fwd_spaces(lin, 10)
    if not S:
        return 0
    return max(S)  # max de claves (rondas), NO de valores (listas)


def score_medium(lin):
    """Chain max en los 31 offsets."""
    S = {r0: fwd_spaces(lin, r0) for r0 in range(PERIOD)}
    vals = [max(S[r0]) for r0 in S if S[r0]]
    return max(vals) if vals else 0


def score_exact(lin):
    """DMITM exacto (multi-bit, álgebra lineal). Más caro."""
    S = {r0: fwd_spaces(lin, r0) for r0 in range(PERIOD)}
    try:
        _, ids = exact_ids(lin, S)
        return ids[0][0] if ids else 0
    except Exception:
        return 0


# ============================================================
# Stages
# ============================================================
def stage1(cals, out_path):
    t0 = time.time()
    results = []
    for i, (name, cal) in enumerate(cals):
        lin = LinCal(cal)
        try:
            s = score_cheap(lin)
        except Exception as e:
            print(f"  skip {name}: {e}")
            continue
        results.append({'cal': name, 'cal_list': cal, 'chain10': s})
        if (i + 1) % 25 == 0:
            print(f"  [{i+1}/{len(cals)}] {time.time()-t0:.0f}s")
    results.sort(key=lambda x: x['chain10'])
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=0)
    print(f"\n{'chain10':>7}  calendar")
    print('-' * 35)
    for r in results[:30]:
        print(f"{r['chain10']:>7}  {r['cal']}")
    print(f"\n{len(results)} candidatos → {out_path}  ({time.time()-t0:.1f}s)")
    return results


def stage2(in_file, top_k, out_path):
    t0 = time.time()
    with open(in_file) as f:
        cands = json.load(f)[:top_k]
    print(f"Etapa 2 sobre {len(cands)} candidatos")
    out = []
    for i, c in enumerate(cands):
        lin = LinCal(c['cal_list'])
        try:
            s = score_medium(lin)
        except Exception as e:
            print(f"  skip {c['cal']}: {e}")
            continue
        out.append({**c, 'chain31': s})
        if (i + 1) % 10 == 0:
            print(f"  [{i+1}/{len(cands)}] {time.time()-t0:.0f}s")
    out.sort(key=lambda x: (x['chain31'], x['chain10']))
    with open(out_path, 'w') as f:
        json.dump(out, f, indent=0)
    print(f"\n{'chain10':>7}  {'chain31':>7}  calendar")
    print('-' * 40)
    for r in out[:20]:
        print(f"{r['chain10']:>7}  {r['chain31']:>7}  {r['cal']}")
    print(f"\n→ {out_path}  ({time.time()-t0:.1f}s)")
    return out


def stage3(in_file, top_k, out_path):
    t0 = time.time()
    with open(in_file) as f:
        cands = json.load(f)[:top_k]
    print(f"Etapa 3 sobre {len(cands)} candidatos (DMITM exacto)")
    out = []
    for i, c in enumerate(cands):
        lin = LinCal(c['cal_list'])
        try:
            s = score_exact(lin)
        except Exception as e:
            print(f"  skip {c['cal']}: {e}")
            continue
        out.append({**c, 'dmitm': s})
        print(f"  [{i+1}/{len(cands)}] {c['cal']:<22} dmitm={s}  "
              f"{time.time()-t0:.0f}s")
    out.sort(key=lambda x: (x['dmitm'], x['chain31'], x['chain10']))
    with open(out_path, 'w') as f:
        json.dump(out, f, indent=0)
    print(f"\n{'chain31':>7}  {'dmitm':>6}  calendar")
    print('-' * 40)
    for r in out[:20]:
        print(f"{r['chain31']:>7}  {r['dmitm']:>6}  {r['cal']}")
    print(f"\n→ {out_path}  ({time.time()-t0:.1f}s)")
    return out


# ============================================================
# Main
# ============================================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('stage', choices=['stage1', 'stage2', 'stage3', 'all'])
    ap.add_argument('--mode', default='structured',
                    choices=['original', 'affine', 'power', 'bitrev',
                             'inverse', 'interleaved', 'composition',
                             'random', 'structured', 'all'])
    ap.add_argument('--n_random', type=int, default=200)
    ap.add_argument('--seed', type=int, default=0)
    ap.add_argument('--top_k', type=int, default=50)
    a = ap.parse_args()

    if a.stage == 'stage1':
        cals = gen_calendars(a.mode, a.n_random, a.seed)
        print(f"Generados {len(cals)} calendarios (mode={a.mode})")
        stage1(cals, 'cal_stage1.json')

    elif a.stage == 'stage2':
        stage2('cal_stage1.json', a.top_k, 'cal_stage2.json')

    elif a.stage == 'stage3':
        stage3('cal_stage2.json', a.top_k, 'cal_stage3.json')

    elif a.stage == 'all':
        cals = gen_calendars(a.mode, a.n_random, a.seed)
        print(f"Generados {len(cals)} calendarios (mode={a.mode})")
        stage1(cals, 'cal_stage1.json')
        stage2('cal_stage1.json', a.top_k, 'cal_stage2.json')
        stage3('cal_stage2.json', min(a.top_k, 20), 'cal_stage3.json')


if __name__ == '__main__':
    main()
