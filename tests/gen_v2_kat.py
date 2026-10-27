#!/usr/bin/env python3
"""
tests/gen_v2_kat.py - Referencia INDEPENDIENTE (solo stdlib) de MYSX v2.

Reimplementa desde el SPEC: cifrado en bloque con calendario por tabla, CTR, derivacion
(HKDF-SHA512, PBKDF2-SHA512, scrypt) y el formato de paquete v2. Genera tests/_v2_kat_cross.json
con PAQUETES COMPLETOS que mysx.prod.js debe reproducir byte a byte (seal) y abrir (open).

Autocomprobacion: antes de generar nada verifica que ESTE cifrado reproduce los digests KAT
publicos de ambos calendarios; si no coinciden, aborta (no se generan vectores con una
referencia incorrecta).
Uso: python3 tests/gen_v2_kat.py [ruta_salida]
"""
import hashlib, hmac, json, os, struct, sys, unicodedata

M = 0xFFFFFFFF
MYZ = [4,12,20,28, 0,8,16,24, 5,13,21,29, 2,7,10,15,18,23,26,31, 6,14,22,30, 1,9,17,25, 3,11,19,27]
CONST = [0x243f6a88,0x85a308d3,0x13198a2e,0x03707344,0xa4093822,0x299f31d0,0x082efa98,0xec4e6c89]
CAL0 = list(range(1, 32))
CAL1 = [22,5,8,7,17,10,30,1,11,26,6,3,12,23,25,13,28,20,21,19,24,2,18,9,4,15,29,27,16,14,31]
KAT_DIGEST = {0: '3a8084d0b7df7eb691cfb54494410a5222652c219a336ee58bde48a64524a8b3',
              1: 'd1b3e268af1c7422e38c8af6db1cc2be6c01b7c335423a7e5cd53a578171444a'}


def rotl(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & M

def F(x): return ((rotl(x, 1) & rotl(x, 8)) ^ rotl(x, 2)) & M

def key_schedule(key):
    s = [int.from_bytes(key[4*i:4*i+4], 'big') for i in range(16)]
    rks = []
    for r in range(128):
        spread = ((r + 1) * 0x9E3779B9) & M
        rk = [s[i] ^ s[(i+5) % 16] ^ s[(i+11) % 16] ^ CONST[(r+i) % 8] ^ spread for i in range(8)]
        for i in range(4): rk[i] ^= s[(i+8) % 16] ^ CONST[(r+i+3) % 8]
        L, R = s[0:8], s[8:16]; ns = [0] * 16
        for i in range(8):
            a, b, c = R[i], R[(i+1) % 8], R[(i+3) % 8]
            ns[i] = R[i]
            ns[i+8] = L[i] ^ (rotl((a + b) & M, 7) ^ rotl(c, 13) ^ CONST[i] ^ spread)
        s = ns; rks.append(rk)
    return rks, [s[i] ^ s[(i+8) % 16] ^ CONST[(128+i) % 8] for i in range(8)]

def enc_block(block, rks, fin, cal):
    s = [int.from_bytes(block[4*i:4*i+4], 'big') for i in range(8)]
    for r in range(128):
        s = [s[i] ^ rks[r][i] for i in range(8)]
        for p in range(4):
            L, R = s[p], s[p+4]; s[p], s[p+4] = R, L ^ F(R)
        b = b''.join(w.to_bytes(4, 'big') for w in s)
        b = bytes(b[MYZ[j]] for j in range(32))
        s = [rotl(int.from_bytes(b[4*i:4*i+4], 'big'), cal[r % 31]) for i in range(8)]
    s = [s[i] ^ fin[i] for i in range(8)]
    return b''.join(w.to_bytes(4, 'big') for w in s)

def ctr_xor(data, key, nonce, cal):
    rks, fin = key_schedule(key)
    ctr = bytearray(nonce + bytes(16)); out = bytearray()
    for off in range(0, len(data), 32):
        ks = enc_block(bytes(ctr), rks, fin, cal)
        chunk = data[off:off+32]
        out += bytes(x ^ y for x, y in zip(chunk, ks))
        for k in range(31, 15, -1):
            ctr[k] = (ctr[k] + 1) & 0xff
            if ctr[k]: break
    return bytes(out)

def kat_digest(cal):
    rks, fin = key_schedule(bytes(range(64))); buf = b''
    for t in range(16):
        pt = bytes((t*32 + i) & 0xff for i in range(32))
        buf += pt + enc_block(pt, rks, fin, cal)
    return hashlib.sha256(buf).hexdigest()

# ---------------------------------------------------------------- formato v2
def lp(x): return struct.pack('>H', len(x)) + x
def u64(n): return struct.pack('>Q', n)

def hkdf_sha512(ikm, salt, info, length=64):
    prk = hmac.new(salt, ikm, hashlib.sha512).digest()
    okm, t, i = b'', b'', 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha512).digest(); okm += t; i += 1
    return okm[:length]

def info(cal_id, kdf, context, label):
    return lp(b'MYSX-256/512 v2') + bytes([cal_id, kdf]) + lp(context) + lp(label)

def build_packet(pt, cal_id, kdf, params, salt, nonce, aad, context, secret=None, password=None, keyfile=b''):
    cal = {0: CAL0, 1: CAL1}[cal_id]
    header = bytes([2, cal_id, kdf])
    if kdf == 2: header += struct.pack('>I', params['iterations'])
    if kdf == 3: header += bytes([params['logN'], params['r'], params['p']])
    header += salt + nonce
    if kdf == 0:
        ikm = secret
    else:
        pw = unicodedata.normalize('NFKC', password).encode()
        if kdf == 2: out = hashlib.pbkdf2_hmac('sha512', pw, salt, params['iterations'], 64)
        else: out = hashlib.scrypt(pw, salt=salt, n=2**params['logN'], r=params['r'], p=params['p'],
                                   maxmem=2**28, dklen=64)
        ikm = lp(out) + lp(keyfile)
    enc = hkdf_sha512(ikm, salt, info(cal_id, kdf, context, b'enc'))
    mac = hkdf_sha512(ikm, salt, info(cal_id, kdf, context, b'mac'))
    ct = ctr_xor(pt, enc, nonce, cal)
    tag = hmac.new(mac, header + u64(len(aad)) + aad + u64(len(ct)) + ct, hashlib.sha512).digest()
    return header + ct + tag, enc, mac


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), '_v2_kat_cross.json')
    for cid, cal in ((0, CAL0), (1, CAL1)):
        d = kat_digest(cal)
        if d != KAT_DIGEST[cid]:
            sys.exit(f"ABORTO: la referencia no reproduce el KAT del calendario {cid}: {d}")
    print("referencia Python: KAT de ambos calendarios OK")
    salt = bytes(range(32)); nonce = bytes(range(100, 116)); aad = b'aad-v2'
    V = []
    def add(name, pt, cal_id, kdf, params, **kw):
        pkt, enc, mac = build_packet(pt, cal_id, kdf, params, salt, nonce, aad, b'ctx', **kw)
        V.append(dict(name=name, plaintext=pt.hex(), cal=cal_id, kdf=kdf, params=params,
                      salt=salt.hex(), nonce=nonce.hex(), aad=aad.hex(), context='ctx',
                      secret=kw.get('secret', b'').hex() or None, password=kw.get('password'),
                      keyfile=(kw.get('keyfile') or b'').hex() or None,
                      packet=pkt.hex(), encKey=enc.hex(), macKey=mac.hex()))
    add('raw64 cal1 vacio',   b'',                       1, 0, None, secret=bytes([0xA5]) * 64)
    add('raw64 cal1 1 byte',  b'\x42',                   1, 0, None, secret=bytes([0xA5]) * 64)
    add('raw64 cal1 100 B',   bytes(range(100)),         1, 0, None, secret=bytes([0xA5]) * 64)
    add('raw32 cal0 33 B',    bytes(range(33)),          0, 0, None, secret=bytes([0x5A]) * 32)
    add('pbkdf2 cal1 + keyfile', bytes(range(70)),       1, 2, {'iterations': 210000},
        password='p\u00e4ssw\u00f6rd \u2460', keyfile=bytes([9]) * 64)
    add('scrypt cal1 sin keyfile', bytes(range(40)),     1, 3, {'logN': 15, 'r': 8, 'p': 1}, password='simple')
    json.dump({'spec': 'MYSX v2 cross KAT', 'vectors': V}, open(out, 'w'), indent=1)
    print(f"{len(V)} vectores -> {out}")


if __name__ == '__main__':
    main()
