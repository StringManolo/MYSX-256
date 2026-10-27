#!/usr/bin/env python3
"""
dmitm_trunc_v3.py - Busqueda de imposibles TRUNCADOS (miss-in-the-middle con bits seguros).

Corrige dmitm_trunc_v2.py:
  * v2 limitaba a 100 cadenas por ronda ordenadas por "menos bits desconocidos", lo que
    descarta justo las cadenas largas (un testigo de 39 rondas tiene ~250/256 bits
    desconocidos). Resultado: v2 solo encontraba ~13 rondas. v3 NO recorta; poda por
    longitud (recorre de mayor a menor f+g y se detiene en cuanto no puede mejorar).
  * Aprovecha el periodo 31 del calendario: solo se consideran 31 rondas de cruce.
  * --verify N: comprueba contra la ronda REAL (round_enc/round_dec del SPEC) que los
    bits "seguros" de ambos lados se cumplen en N pares x 4 claves (0x00, 0xFF y 2 al azar).

Salida compatible con v2: linea final  "BEST: <n> rounds (...)".
Uso:
  python3 dmitm_trunc_v3.py --cal v02 --verify 500
  python3 dmitm_trunc_v3.py --cal k1
  python3 dmitm_trunc_v3.py --cal_file cal_stage3.json --cal_idx 0
Requiere dmitm_verify.py (Lin con fwd_trunc/bwd_trunc, round_enc, round_dec, key_schedule).
"""
import sys, os, json, argparse, time, random

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dmitm_verify as dv
from dmitm_verify import Lin

M32 = 0xFFFFFFFF
FULL = (1 << 256) - 1
V02_CAL = [22,5,8,7,17,10,30,1,11,26,6,3,12,23,25,13,28,20,21,19,24,2,18,9,4,15,29,27,16,14,31]
K1_CAL = list(range(1, 32))
R_LO, R_HI = 62, 93            # 31 residuos de cruce; deja holgura a ambos lados dentro de [0,128)


class LinCal(Lin):
    def __init__(self, cal):
        super().__init__()
        self.cal = list(cal)
    def sh(self, r):
        return self.cal[r % 31]


def to_int(ws):
    return sum(w << (32 * i) for i, w in enumerate(ws))


def masks(val, unk):
    V, U = to_int(val), to_int(unk)
    return (V & ~U) & FULL, (~(V | U)) & FULL       # seguro-1, seguro-0


def bit(pos):
    w = [0] * 8
    w[pos // 32] = 1 << (pos % 32)
    return w


def fwd_states(lin, fmax, n_bits):
    F = {R: [] for R in range(R_LO, R_HI)}
    for rs in range(R_LO - fmax, R_HI):
        for pos in range(n_bits):
            val, unk = bit(pos), [0] * 8
            if R_LO <= rs < R_HI:
                O, Z = masks(val, unk); F[rs].append((0, O, Z, rs, pos))
            for f in range(1, fmax + 1):
                R = rs + f
                if R >= R_HI: break
                val, unk = lin.fwd_trunc(val, unk, R - 1)
                if R >= R_LO:
                    O, Z = masks(val, unk); F[R].append((f, O, Z, rs, pos))
    return F


def bwd_states(lin, gmax, n_bits):
    G = {R: [] for R in range(R_LO, R_HI)}
    for re in range(R_LO, R_HI + gmax):
        for pos in range(n_bits):
            val, unk = bit(pos), [0] * 8
            if R_LO <= re < R_HI:
                O, Z = masks(val, unk); G[re].append((0, O, Z, re, pos))
            for g in range(1, gmax + 1):
                R = re - g
                if R < 0: break
                val, unk = lin.bwd_trunc(val, unk, R)
                if R_LO <= R < R_HI:
                    O, Z = masks(val, unk); G[R].append((g, O, Z, re, pos))
    return G


def search(lin, fmax, gmax, n_bits, keep=5000):
    t0 = time.time()
    F = fwd_states(lin, fmax, n_bits)
    print(f"  fwd listo ({time.time()-t0:.0f}s)", file=sys.stderr)
    G = bwd_states(lin, gmax, n_bits)
    print(f"  bwd listo ({time.time()-t0:.0f}s)", file=sys.stderr)
    best, found = 0, []
    for R in range(R_LO, R_HI):
        Fl = sorted(F[R], key=lambda x: -x[0]); Gl = sorted(G[R], key=lambda x: -x[0])
        if not Fl or not Gl: continue
        for f in Fl:
            if f[0] + Gl[0][0] < best: break
            for g in Gl:
                tot = f[0] + g[0]
                if tot < best: break
                c = (f[1] & g[2]) | (f[2] & g[1])
                if c:
                    if tot > best: best, found = tot, []
                    if len(found) < keep: found.append((tot, R, f, g, c))
    print(f"  busqueda lista ({time.time()-t0:.0f}s)", file=sys.stderr)
    return best, found


def bits_of(c, n=3):
    pos = [p for p in range(256) if (c >> p) & 1]
    return ",".join(f"w{p // 32}b{p % 32}" for p in pos[:n]) + ("..." if len(pos) > n else ""), len(pos)


def describe(item):
    tot, R, f, g, c = item
    cs, nc = bits_of(c)
    return dict(total=tot, R=R, f=f[0], g=g[0], rs=f[3], re=g[3],
                pin=f[4], pout=g[4], conflict=cs, nconf=nc)


def verify(lin, d, npairs, seed=7):
    """Premisas contra la ronda real: los bits seguros de cada lado se cumplen siempre."""
    dv.LIN.sh = lin.sh                       # round_enc/round_dec usan dv.LIN
    rs, re, R = d['rs'], d['re'], d['R']
    val, unk = bit(d['pin']), [0] * 8
    for r in range(rs, R): val, unk = lin.fwd_trunc(val, unk, r)
    fv, fu = val, unk
    val, unk = bit(d['pout']), [0] * 8
    for r in range(re - 1, R - 1, -1): val, unk = lin.bwd_trunc(val, unk, r)
    gv, gu = val, unk
    keys = [bytes(64), b'\xff' * 64, dv.rand_key(11), dv.rand_key(12)]
    rnd = random.Random(seed)
    okf = okb = n = 0
    for key in keys:
        rks, _ = dv.key_schedule(key)
        for _ in range(npairs):
            n += 1
            P = [rnd.getrandbits(32) for _ in range(8)]
            a, b = list(P), list(P); b[d['pin'] // 32] ^= 1 << (d['pin'] % 32)
            for r in range(rs, R):
                a = dv.round_enc(a, rks[r], r); b = dv.round_enc(b, rks[r], r)
            if all(((a[i] ^ b[i]) ^ fv[i]) & ~fu[i] & M32 == 0 for i in range(8)): okf += 1
            c, e = list(P), list(P); e[d['pout'] // 32] ^= 1 << (d['pout'] % 32)
            for r in range(re - 1, R - 1, -1):
                c = dv.round_dec(c, rks[r], r); e = dv.round_dec(e, rks[r], r)
            if all(((c[i] ^ e[i]) ^ gv[i]) & ~gu[i] & M32 == 0 for i in range(8)): okb += 1
    return okf, okb, n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cal", default="v02", choices=["k1", "v02"])
    ap.add_argument("--cal_file", default=None)
    ap.add_argument("--cal_idx", type=int, default=0)
    ap.add_argument("--max_fwd", type=int, default=24)
    ap.add_argument("--max_bwd", type=int, default=24)
    ap.add_argument("--n_bits", type=int, default=256)
    ap.add_argument("--top", type=int, default=5)
    ap.add_argument("--verify", type=int, default=0, help="pares por clave (x4 claves); 0 = no verificar")
    a = ap.parse_args()
    if a.max_fwd > 60 or a.max_bwd > 34:
        sys.exit("max_fwd <= 60 y max_bwd <= 34 (ventana de cruce fija dentro de 128 rondas)")

    if a.cal_file:
        c = json.load(open(a.cal_file))[a.cal_idx]
        cal = [c["cal"][r % 31] for r in range(31)]; name = c.get("name", f"idx{a.cal_idx}")
    elif a.cal == "k1":
        cal, name = K1_CAL, "k1 (consecutive)"
    else:
        cal, name = V02_CAL, "v02 (rand_s9_45430)"
    assert sorted(cal) == list(range(1, 32)), "calendario no es permutacion de 1..31"

    print(f"cal={name}  max_fwd={a.max_fwd} max_bwd={a.max_bwd} n_bits={a.n_bits}")
    lin = LinCal(cal)
    best, found = search(lin, a.max_fwd, a.max_bwd, a.n_bits)
    if not found:
        print("\nNo truncated impossible found in this search space."); sys.exit(1)

    seen, rows = set(), []
    for it in found:
        d = describe(it); k = (d['rs'] % 31, d['pin'], d['pout'], d['total'])
        if k in seen: continue
        seen.add(k); rows.append(d)
    print(f"\nTop {min(a.top, len(rows))} of {len(rows)} distinct candidates at the maximum length:")
    print(f"{'len':>4} {'R':>3} {'rs':>3} {'bi':>8} {'f':>3} {'re':>4} {'bo':>8} {'g':>3}  conflict")
    for d in rows[:a.top]:
        print(f"{d['total']:>4} {d['R']:>3} {d['rs']:>3} {'w%db%d' % (d['pin']//32, d['pin']%32):>8} {d['f']:>3} "
              f"{d['re']:>4} {'w%db%d' % (d['pout']//32, d['pout']%32):>8} {d['g']:>3}  {d['conflict']} ({d['nconf']} bits)")

    w = rows[0]
    if a.verify:
        okf, okb, n = verify(lin, w, a.verify)
        status = "OK" if okf == n and okb == n else "FAIL"
        print(f"\nVERIFY: fwd {okf}/{n}  bwd {okb}/{n}  {status}  (premisas contra la ronda real)")
        if status != "OK": sys.exit(2)
    print(f"\nBEST: {best} rounds (R={w['R']}, w{w['pin']//32}b{w['pin']%32} -> w{w['pout']//32}b{w['pout']%32})")


if __name__ == "__main__":
    main()
