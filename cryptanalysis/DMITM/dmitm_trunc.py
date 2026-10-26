#!/usr/bin/env python3
"""
dmitm_trunc.py — Búsqueda de diferenciales imposibles por propagación truncada.
Autocontenido: importa Lin de dmitm_verify. Acepta calendario arbitrario.

Uso:
  python3 dmitm_trunc.py search --cal_file top50_fixed.json --cal_idx 0
  python3 dmitm_trunc.py search --cal 1,2,3,...,31 --max_fwd 24 --max_bwd 24
  python3 dmitm_trunc.py verify --cal_file top50_fixed.json --cal_idx 0 --top 3
"""
import sys, os, json, argparse, time, random, heapq
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dmitm_verify import (
    Lin, MYZ_PERM, rotl, rotr, simonF,
    key_schedule, round_enc, round_dec, rand_key
)
PERIOD = 31

MASK256 = (1 << 256) - 1


class LinCal(Lin):
    """Lin con calendario explícito (lista de 31 o 128 enteros, 1..31)."""
    def __init__(self, cal):
        super().__init__()
        self.cal = list(cal)

    def sh(self, r):
        return self.cal[r % len(self.cal)]


def to_int(val):
    return sum(v << (32 * i) for i, v in enumerate(val))


def conflict(vf, uf, vb, ub):
    """Bits seguros opuestos entre fwd y bwd."""
    a = vf & ~uf & ~ub & ~vb      # fwd dice 1, bwd dice 0
    b = vb & ~ub & ~uf & ~vf      # bwd dice 1, fwd dice 0
    return (a | b) != 0


def search(lin, max_fwd=24, max_bwd=24, n_bits=256, verbose=True):
    F = [[] for _ in range(128)]
    B = [[] for _ in range(128)]
    t0 = time.time()

    # Forward: desde cada bit de inicio, propagar truncado
    for r_start in range(128):
        for b_in in range(n_bits):
            delta = [0] * 8
            delta[b_in // 32] = 1 << (b_in % 32)
            val, unk = delta[:], [0] * 8
            for k in range(max_fwd):
                r = r_start + k
                if r >= 128:
                    break
                F[r].append((r_start, b_in, to_int(val), to_int(unk)))
                val, unk = lin.fwd_trunc(val, unk, r)
        if (r_start + 1) % 32 == 0 and verbose:
            print(f"  fwd {r_start+1}/128  {time.time()-t0:.1f}s", flush=True)

    # Backward: desde cada bit de fin, propagar truncado hacia atrás
    for r_end in range(128):
        for b_out in range(n_bits):
            delta = [0] * 8
            delta[b_out // 32] = 1 << (b_out % 32)
            val, unk = delta[:], [0] * 8
            for k in range(max_bwd):
                r = r_end - k
                if r < 0:
                    break
                B[r].append((r_end, b_out, to_int(val), to_int(unk)))
                if r > 0:
                    val, unk = lin.bwd_trunc(val, unk, r - 1)
                else:
                    break
        if (r_end + 1) % 32 == 0 and verbose:
            print(f"  bwd {r_end+1}/128  {time.time()-t0:.1f}s", flush=True)

    # Deduplicar por (val, unk), quedarse con el r_start mínimo / r_end máximo
    Fd = [dict() for _ in range(128)]
    Bd = [dict() for _ in range(128)]
    for r in range(128):
        for rs, bi, v, u in F[r]:
            key = (v, u)
            if key not in Fd[r] or rs < Fd[r][key][0]:
                Fd[r][key] = (rs, bi)
        for re, bo, v, u in B[r]:
            key = (v, u)
            if key not in Bd[r] or re > Bd[r][key][0]:
                Bd[r][key] = (re, bo)

    # Buscar conflictos
    best = []
    for r in range(128):
        for (vf, uf), (rs, bi) in Fd[r].items():
            for (vb, ub), (re, bo) in Bd[r].items():
                if rs >= re:
                    continue
                if conflict(vf, uf, vb, ub):
                    if len(best) < 200:
                        best.append((re - rs, r, rs, bi, re, bo, vf, uf, vb, ub))
    best.sort(key=lambda x: -x[0])
    best = best[:200]

    # Deduplicar por (rs, bi, re, bo)
    seen, out = set(), []
    for w in best:
        key = (w[2], w[3], w[4], w[5])
        if key not in seen:
            seen.add(key)
            out.append(w)
    return out


def desc(bit_idx):
    """Formatea un índice de bit o una máscara de 256 bits."""
    if bit_idx >= 256:  # es una máscara, no un índice
        return ",".join(f"w{i//32}b{i%32}" for i in range(256) if (bit_idx >> i) & 1) or "0"
    return f"w{bit_idx // 32}b{bit_idx % 32}"


def round_enc_cal(st, rk, r, lin):
    """round_enc con calendario arbitrario."""
    st = [st[i] ^ rk[i] for i in range(8)]
    mid = [0] * 8
    for p in range(4):
        L, R = st[p], st[p + 4]
        mid[p] = R
        mid[p + 4] = L ^ simonF(R)
    return lin.fwd(mid, r)


def round_dec_cal(st, rk, r, lin):
    """round_dec con calendario arbitrario."""
    mid = lin.bwd(st, r)
    o = [0] * 8
    for p in range(4):
        R = mid[p]
        L = mid[p + 4] ^ simonF(R)
        o[p] = L
        o[p + 4] = R
    return [o[i] ^ rk[i] for i in range(8)]


def verify(lin, wit, n_keys=4, n_pairs=2000, seed=1, verbose=True):
    length, r_mid, rs, bi, re, bo, vf, uf, vb, ub = wit
    din = [0] * 8
    din[bi // 32] = 1 << (bi % 32)
    dout = [0] * 8
    dout[bo // 32] = 1 << (bo % 32)

    rnd = random.Random(seed)
    ok_f = ok_b = 0
    total = n_keys * n_pairs

    for k in range(n_keys):
        rks, _ = key_schedule(rand_key(seed + k))
        for _ in range(n_pairs):
            P = [rnd.getrandbits(32) for _ in range(8)]

            # Forward: din en s[rs] -> bits seguros vf/uf en s[r_mid]
            s1, s2 = list(P), [P[i] ^ din[i] for i in range(8)]
            for r in range(rs, r_mid):
                s1 = round_enc_cal(s1, rks[r], r, lin)
                s2 = round_enc_cal(s2, rks[r], r, lin)
            d = to_int([s1[i] ^ s2[i] for i in range(8)])
            if (d & ~uf) == (vf & ~uf):
                ok_f += 1

            # Backward: dout en s[re] -> bits seguros vb/ub en s[r_mid]
            s1, s2 = list(P), [P[i] ^ dout[i] for i in range(8)]
            for r in range(re - 1, r_mid - 1, -1):
                s1 = round_dec_cal(s1, rks[r], r, lin)
                s2 = round_dec_cal(s2, rks[r], r, lin)
            d2 = to_int([s1[i] ^ s2[i] for i in range(8)])
            if (d2 & ~ub) == (vb & ~ub):
                ok_b += 1

    if verbose:
        print(f"  forward:  {ok_f}/{total} ({100*ok_f/total:.2f}%)")
        print(f"  backward: {ok_b}/{total} ({100*ok_b/total:.2f}%)")
    return ok_f, ok_b, total


def load_cal(args):
    if args.cal_file:
        cands = json.load(open(args.cal_file))
        c = cands[args.cal_idx]
        cal = [c["cal"][r % 31] for r in range(31)]
        return cal, c.get("name", f"idx{args.cal_idx}")
    if args.cal:
        return [int(x) for x in args.cal.split(",")], "custom"
    return [((r) % 31) + 1 for r in range(31)], "k=1"


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for cmd in ("search", "verify"):
        p = sub.add_parser(cmd)
        p.add_argument("--cal_file", default=None)
        p.add_argument("--cal_idx", type=int, default=0)
        p.add_argument("--cal", default=None)
        p.add_argument("--max_fwd", type=int, default=24)
        p.add_argument("--max_bwd", type=int, default=24)
        p.add_argument("--n_bits", type=int, default=256)
        p.add_argument("--n_keys", type=int, default=4)
        p.add_argument("--n_pairs", type=int, default=2000)
        p.add_argument("--seed", type=int, default=1)
        p.add_argument("--top", type=int, default=10)
        p.add_argument("--out", default=None)
    a = ap.parse_args()

    cal, name = load_cal(a)
    lin = LinCal(cal)
    print(f"cal={name}  max_fwd={a.max_fwd} max_bwd={a.max_bwd} n_bits={a.n_bits}")

    if a.cmd == "search":
        t0 = time.time()
        results = search(lin, a.max_fwd, a.max_bwd, a.n_bits)
        print(f"\n{len(results)} imposibles en {time.time()-t0:.1f}s")
        print(f"{'len':>4}  {'R':>4}  {'rs':>4}  {'bi':>8}  {'re':>4}  {'bo':>8}  conflicto")
        for w in results[:a.top]:
            length, r_mid, rs, bi, re, bo, vf, uf, vb, ub = w
            print(f"{length:>4}  {r_mid:>4}  {rs:>4}  {desc(bi):>8}  {re:>4}  {desc(bo):>8}  {desc((vf & ~uf) ^ (vb & ~ub))}")
        if a.out:
            json.dump([list(w) for w in results], open(a.out, "w"), indent=0)
            print(f"saved {a.out}")

    elif a.cmd == "verify":
        results = search(lin, a.max_fwd, a.max_bwd, a.n_bits, verbose=False)
        if not results:
            print("no hay imposibles para verificar")
            return
        for i, w in enumerate(results[:a.top]):
            print(f"\nWitness {i}: len={w[0]} R={w[1]} rs={w[2]} bi={desc(w[3])} re={w[4]} bo={desc(w[5])}")
            verify(lin, w, a.n_keys, a.n_pairs, a.seed)


if __name__ == "__main__":
    main()
