#!/usr/bin/env python3
"""
generate_kat.py -- Genera KAT.json para MYSX-256/512.

Ejecuta la implementación de referencia (via Node.js) y produce
vectores reproducibles en formato JSON.

Uso:
    python3 generate_kat.py > KAT.json
    # o
    python3 generate_kat.py --output KAT.json

Requiere: node (para ejecutar mysx.prod.js) y que mysx.prod.js
esté en el mismo directorio.
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
const { TEST, deriveAeadKeys, deriveAeadKeysFromPassword } = MYSX;

if (!TEST) {
    console.error('TEST no disponible. Carga con MYSX_ENABLE_TEST=1');
    process.exit(1);
}

const {
    _keySchedule,
    _encryptBlockCore,
    _makeScratch,
    _unsafeAeadEncryptWithNonce,
    CONFIG
} = TEST;
const { KEY_BYTES, NONCE_BYTES } = CONFIG;

function hex(arr) {
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function main() {
    const out = {};

    // --- 1) Vectores de bloque ---
    const blockTests = [];
    for (let t = 0; t < 8; t++) {
        const key = new Uint8Array(KEY_BYTES);
        const pt  = new Uint8Array(32);
        for (let i = 0; i < KEY_BYTES; i++) key[i] = (t * 17 + i) & 0xff;
        for (let i = 0; i < 32; i++) pt[i] = (t * 31 + i * 7) & 0xff;
        const sch = _keySchedule(key);
        const ct = _encryptBlockCore(pt, sch, 128, _makeScratch(), true).slice();
        blockTests.push({
            key: hex(key),
            plaintext: hex(pt),
            ciphertext: hex(ct)
        });
    }
    out.block = blockTests;

    // --- 2) Vectores AEAD (nonce fijo, deterministico) ---
    const aeadTests = [];
    for (let t = 0; t < 4; t++) {
        const master = new Uint8Array(32);
        for (let i = 0; i < 32; i++) master[i] = (t * 11 + i) & 0xff;
        const { encKey, macKey } = await deriveAeadKeys(master, { context: 'kat' });
        const nonce = new Uint8Array(NONCE_BYTES);
        for (let i = 0; i < NONCE_BYTES; i++) nonce[i] = (t * 7 + i) & 0xff;
        const pt = new Uint8Array(16 + t * 8);
        for (let i = 0; i < pt.length; i++) pt[i] = (i * 13) & 0xff;
        const aad = new Uint8Array([0xAA, t]);
        const packet = await _unsafeAeadEncryptWithNonce(pt, encKey, macKey, nonce, aad);
        aeadTests.push({
            master_secret: hex(master),
            nonce: hex(nonce),
            aad: hex(aad),
            plaintext: hex(pt),
            packet: hex(packet)
        });
    }
    out.aead = aeadTests;

    // --- 3) Vectores de derivación ---
    const kdfTests = [];
    for (let t = 0; t < 3; t++) {
        const secret = new Uint8Array(32);
        for (let i = 0; i < 32; i++) secret[i] = (t * 19 + i) & 0xff;
        const salt = new Uint8Array(16);
        for (let i = 0; i < 16; i++) salt[i] = (t * 23 + i) & 0xff;
        const { encKey, macKey } = await deriveAeadKeys(secret, { salt, context: 'kat' });
        kdfTests.push({
            type: 'hkdf',
            secret: hex(secret),
            salt: hex(salt),
            context: 'kat',
            encKey: hex(encKey),
            macKey: hex(macKey)
        });
    }
    {
        const password = 'correct horse battery staple';
        const salt = new Uint8Array(16);
        for (let i = 0; i < 16; i++) salt[i] = i;
        const { encKey, macKey } = await deriveAeadKeysFromPassword(
            password, salt, { iterations: 1000, context: 'kat' }
        );
        kdfTests.push({
            type: 'pbkdf2',
            password: password,
            salt: hex(salt),
            iterations: 1000,
            context: 'kat',
            encKey: hex(encKey),
            macKey: hex(macKey)
        });
    }
    out.kdf = kdfTests;

    console.log(JSON.stringify(out, null, 2));
}

main().catch(e => { console.error(e); process.exit(1); });
"""


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--output", default="-",
                    help="Archivo de salida (default stdout)")
    args = ap.parse_args()

    # Ejecutar Node con el script embebido
    try:
        result = subprocess.run(
            ["node", "-e", JS_SCRIPT],
            capture_output=True, text=True, check=True, timeout=120
        )
    except FileNotFoundError:
        print("ERROR: node no encontrado en PATH", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"ERROR ejecutando Node:\n{e.stderr}", file=sys.stderr)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("ERROR: timeout ejecutando Node", file=sys.stderr)
        sys.exit(1)

    # Validar JSON
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"ERROR: salida no es JSON válido: {e}", file=sys.stderr)
        print("Salida cruda:", result.stdout[:500], file=sys.stderr)
        sys.exit(1)

    # Añadir metadatos (fijos para reproducibilidad)
    data = {
        "algorithm": "MYSX-256/512",
        "version": "0.1-experimental",
        "block_size_bits": 256,
        "key_size_bits": 512,
        "rounds": 128,
        **data
    }

    # Digest global (SHA-256 del JSON sin el propio digest)
    body = json.dumps(data, sort_keys=True).encode('utf-8')
    data["digest"] = hashlib.sha256(body).hexdigest()

    # Escribir
    output = json.dumps(data, indent=2)
    if args.output == "-":
        print(output)
    else:
        with open(args.output, "w") as f:
            f.write(output + "\n")
        print(f"Escrito {args.output} ({len(output)} bytes)", file=sys.stderr)


if __name__ == "__main__":
    main()
