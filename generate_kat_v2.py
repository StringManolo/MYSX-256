#!/usr/bin/env python3
"""
generate_kat_v2.py -- Genera KAT_v2.json para MYSX-256/512 v0.2-experimental.

Captura:
  - block_v02:      cifrado de bloque con cal=1 (nuevo calendario)
  - v2_raw:         v2.seal/open con secret 64B (KDF.RAW)
  - v2_password_*:  v2.seal/open con password (Argon2id, scrypt, PBKDF2)
  - v2_kdf:         derivación de encKey/macKey directamente
  - v2_parse:       parsing del header de packets
  - security_level: securityLevel() para varios creds

Requiere:
  - node (para mysx.prod.js)
  - @noble/hashes (opcional, para Argon2id determinista)
    npm install @noble/hashes
"""
import argparse
import hashlib
import json
import subprocess
import sys

JS_SCRIPT = r"""
'use strict';
process.env.MYSX_ENABLE_TEST = '1';
const MYSX = require('./mysx.prod.js');
const { TEST, v2 } = MYSX;
const { _v2 } = TEST;

if (!TEST) {
  console.error('TEST no disponible. Carga con MYSX_ENABLE_TEST=1');
  process.exit(1);
}
const { generateKAT, CAL_TABLES } = TEST;

function hex(arr) {
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}
function unhex(s) {
  return new Uint8Array(Buffer.from(s, 'hex'));
}

// Salt/nonce fijos para determinismo del KAT
function fixedBytes(n, v) { return new Uint8Array(n).fill(v); }

async function tryArgon2() {
  try {
    const { argon2idAsync } = await import('@noble/hashes/argon2.js');
    v2.setArgon2Provider(v2.argon2FromNoble(argon2idAsync));
    return 'noble';
  } catch (e) {
    return null;
  }
}

async function main() {
  const out = {};
  const argon2Provider = await tryArgon2();
  out.argon2_provider = argon2Provider || 'none';

  // --- 1) Block cipher con cal=1 (nuevo calendario) ---
  const blockV02 = [];
  if (CAL_TABLES[1]) {
    const key = new Uint8Array(64);
    for (let i = 0; i < 64; i++) key[i] = i;
    const sch = TEST._keySchedule(key);
    for (let t = 0; t < 8; t++) {
      const pt = new Uint8Array(32);
      for (let i = 0; i < 32; i++) pt[i] = (t * 32 + i) & 0xff;
      const ct = TEST._encryptBlockCore(pt, sch, 128, TEST._makeScratch(), true, CAL_TABLES[1]).slice();
      blockV02.push({ key: hex(key), plaintext: hex(pt), ciphertext: hex(ct) });
    }
    out.block_v02 = blockV02;
  } else {
    out.block_v02 = null;
    console.error('WARNING: V02_CALENDAR not injected in mysx.prod.js');
  }

  // --- 2) v2.seal/open con secret (KDF.RAW) ---
  const secret = fixedBytes(64, 0xA5);
  const salt = fixedBytes(32, 0x11);
  const nonce = fixedBytes(16, 0x22);
  const aad = new Uint8Array([0xAA, 0xBB, 0xCC]);
  const plaintext = new TextEncoder().encode('KAT v2 test message');
  const ctx = 'kat-v2';

  const packet = await v2.seal(plaintext, { secret }, {
    aad, context: ctx, salt, nonce, _salt: salt, _nonce: nonce
  });
  // Note: opts uses `_salt`/`_nonce` internally; keep both keys to be safe.
  const recovered = await v2.open(packet, { secret }, { aad, context: ctx });
  const rtOk = hex(recovered) === hex(plaintext);

  out.v2_raw = [{
    secret: hex(secret),
    aad: hex(aad),
    context: ctx,
    salt: hex(salt),
    nonce: hex(nonce),
    plaintext: hex(plaintext),
    packet: hex(packet),
    roundtrip_ok: rtOk,
  }];

  // --- 3) v2.seal/open con password (Argon2id, determinista) ---
  const pwAad = new Uint8Array(0);
  const pwSalt = fixedBytes(32, 0x33);
  const pwNonce = fixedBytes(16, 0x44);
  const pwText = 'correct horse battery staple';

  if (argon2Provider) {
    try {
      const packetArgon = await v2.seal(plaintext, { password: pwText }, {
        aad: pwAad, context: ctx, _salt: pwSalt, _nonce: pwNonce,
        kdf: v2.KDF.ARGON2ID,
        kdfParams: { memKiB: 65536, passes: 3, lanes: 4 },
        argon2Provider: v2._argon2Provider || undefined,
      });
      out.v2_password_argon2 = [{
        password: pwText,
        aad: hex(pwAad),
        context: ctx,
        salt: hex(pwSalt),
        nonce: hex(pwNonce),
        kdf_params: { memKiB: 65536, passes: 3, lanes: 4 },
        plaintext: hex(plaintext),
        packet: hex(packetArgon),
      }];
    } catch (e) {
      out.v2_password_argon2 = null;
      out.v2_password_argon2_error = String(e);
    }
  } else {
    out.v2_password_argon2 = null;
  }

  // --- 4) v2.seal/open con password (scrypt, determinista) ---
  try {
    const packetScrypt = await v2.seal(plaintext, { password: pwText }, {
      aad: pwAad, context: ctx, _salt: pwSalt, _nonce: pwNonce,
      kdf: v2.KDF.SCRYPT,
      kdfParams: { logN: 15, r: 8, p: 1 },   // bajo para que el KAT sea rápido
    });
    out.v2_password_scrypt = [{
      password: pwText,
      aad: hex(pwAad),
      context: ctx,
      salt: hex(pwSalt),
      nonce: hex(pwNonce),
      kdf_params: { logN: 15, r: 8, p: 1 },
      plaintext: hex(plaintext),
      packet: hex(packetScrypt),
    }];
  } catch (e) {
    out.v2_password_scrypt = null;
    out.v2_password_scrypt_error = String(e);
  }

  // --- 5) v2.seal/open con password (PBKDF2, determinista) ---
  try {
    const packetPbkdf2 = await v2.seal(plaintext, { password: pwText }, {
      aad: pwAad, context: ctx, _salt: pwSalt, _nonce: pwNonce,
      kdf: v2.KDF.PBKDF2_SHA512,
      kdfParams: { iterations: 210000 },
    });
    out.v2_password_pbkdf2 = [{
      password: pwText,
      aad: hex(pwAad),
      context: ctx,
      salt: hex(pwSalt),
      nonce: hex(pwNonce),
      kdf_params: { iterations: 210000 },
      plaintext: hex(plaintext),
      packet: hex(packetPbkdf2),
    }];
  } catch (e) {
    out.v2_password_pbkdf2 = null;
    out.v2_password_pbkdf2_error = String(e);
  }

  // --- 6) v2_kdf: derive keys directamente ---
  const kdfSecret = fixedBytes(64, 0x55);
  const kdfSalt = fixedBytes(32, 0x66);
  const { encKey, macKey } = await _v2.deriveKeys(
    kdfSecret, kdfSalt, 1, 0, 'kat-kdf-context'
  );
  out.v2_kdf = [{
    secret: hex(kdfSecret),
    salt: hex(kdfSalt),
    cal: 1,
    kdf: 0,
    context: 'kat-kdf-context',
    encKey: hex(encKey),
    macKey: hex(macKey),
  }];

  // --- 7) v2_parse: parsing del header ---
  const parsed = _v2.parseHeader(packet);
  out.v2_parse = [{
    packet_hex: hex(packet),
    version: parsed.version,
    cal: parsed.cal,
    kdf: parsed.kdf,
    kdf_params: parsed.kdfParams,
    salt: hex(parsed.salt),
    nonce: hex(parsed.nonce),
    header_len: parsed.headerLen,
  }];

  // --- 8) securityLevel ---
  out.security_level = [
    v2.securityLevel({ secret: fixedBytes(64, 0) }),
    v2.securityLevel({ secret: fixedBytes(32, 0) }),
    v2.securityLevel({ password: 'x', keyfile: fixedBytes(16, 0) }),
    v2.securityLevel({ password: 'x', keyfile: fixedBytes(64, 0) }),
  ];

  // --- 9) block cipher digest con cal=0 y cal=1 (regresión) ---
  out.block_digest_cal0 = await generateKAT(0);
  if (CAL_TABLES[1]) {
    out.block_digest_cal1 = await generateKAT(1);
  } else {
    out.block_digest_cal1 = null;
  }

  console.log(JSON.stringify(out, null, 2));
}

main().catch(e => { console.error(e); process.exit(1); });
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="-")
    ap.add_argument("--kat-version", dest="kat_version", default=None)
    args = ap.parse_args()

    try:
        result = subprocess.run(
            ["node", "-e", JS_SCRIPT],
            capture_output=True, text=True, check=True, timeout=600
        )
    except FileNotFoundError:
        print("ERROR: node no encontrado", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"ERROR ejecutando Node:\n{e.stderr}", file=sys.stderr)
        sys.exit(1)

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"ERROR: salida no es JSON: {e}", file=sys.stderr)
        print("Salida cruda:", result.stdout[:1000], file=sys.stderr)
        sys.exit(1)

    version = args.kat_version or "0.2-experimental"
    out = {
        "algorithm": "MYSX-256/512",
        "version": version,
        "block_size_bits": 256,
        "key_size_bits": 512,
        "rounds": 128,
        "v2_format": "VERSION(1)=2 | CAL(1) | KDF(1) | KDF_PARAMS(var) | SALT(32) | NONCE(16) | CT(n) | TAG(64)",
        **data,
    }

    body = json.dumps({k: v for k, v in out.items() if k != "digest"},
                      sort_keys=True).encode("utf-8")
    out["digest"] = hashlib.sha256(body).hexdigest()

    text = json.dumps(out, indent=2)
    if args.output == "-":
        print(text)
    else:
        with open(args.output, "w") as f:
            f.write(text + "\n")
        print(f"Escrito {args.output} ({len(text)} bytes)", file=sys.stderr)


if __name__ == "__main__":
    main()
