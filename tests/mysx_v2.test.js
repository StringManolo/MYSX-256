'use strict';
// =============================================================================
// tests/mysx_v2.test.js - Tests de seguridad de la capa MYSX v2.
// Requiere:  python3 tests/gen_v2_kat.py   (genera tests/_v2_kat_cross.json)
// Uso:       MYSX_ENABLE_TEST=1 node tests/mysx_v2.test.js
// Salida:    "V2 TESTS: N pass, 0 fail"  (exit 1 si hay algun fallo)
// =============================================================================
process.env.MYSX_ENABLE_TEST = '1';
const fs = require('fs');
const path = require('path');
const mysx = require('../mysx.prod.js');
const v2 = mysx.v2, T = mysx.TEST;

const EXPECTED_V02_CAL = [22,5,8,7,17,10,30,1,11,26,6,3,12,23,25,13,28,20,21,19,24,2,18,9,4,15,29,27,16,14,31];
const KAT = {
  0: '3a8084d0b7df7eb691cfb54494410a5222652c219a336ee58bde48a64524a8b3',
  1: 'd1b3e268af1c7422e38c8af6db1cc2be6c01b7c335423a7e5cd53a578171444a'
};
const hex = (u8) => Buffer.from(u8).toString('hex');
const fromHex = (h) => new Uint8Array(Buffer.from(h, 'hex'));
const bytes = (n, f = (i) => i & 0xff) => Uint8Array.from({ length: n }, (_, i) => f(i));

let pass = 0, fail = 0, skipped = 0;
async function t(name, fn) {
  try { const r = await fn(); if (r === false) throw new Error('false'); pass++; console.log('  [OK]   ' + name); }
  catch (e) { fail++; console.log('  [FAIL] ' + name + '  -> ' + (e && e.message)); }
}
const rejects = async (p) => { try { await p; return false; } catch (e) { return true; } };
const throwsSync = (f) => { try { f(); return false; } catch (e) { return true; } };

(async () => {
  const secret64 = bytes(64, (i) => 0x11 + i), secret32 = bytes(32, (i) => 0x77 - i);
  const pt = new TextEncoder().encode('MYSX v2 test message');

  console.log('--- regresion del calendario y del cifrado ---');
  await t('calendario v0.2 hardcodeado == tabla esperada', () =>
    JSON.stringify(Array.from(T.CAL_TABLES[1])) === JSON.stringify(EXPECTED_V02_CAL));
  await t('calendario v0.2 es una permutacion de 1..31', () =>
    [...T.CAL_TABLES[1]].sort((a, b) => a - b).every((v, i) => v === i + 1));
  await t('KAT cal0 (consecutivo) == digest publico', async () => (await T.generateKAT(0)) === KAT[0]);
  await t('KAT cal1 (v0.2) == digest de la referencia Python', async () => (await T.generateKAT(1)) === KAT[1]);

  console.log('--- KAT cruzado con la referencia Python independiente ---');
  const katPath = path.join(__dirname, '_v2_kat_cross.json');
  if (!fs.existsSync(katPath)) {
    fail++; console.log('  [FAIL] falta ' + katPath + ' (ejecuta: python3 tests/gen_v2_kat.py)');
  } else {
    const kat = JSON.parse(fs.readFileSync(katPath, 'utf8'));
    for (const v of kat.vectors) {
      const creds = v.kdf === 0 ? { secret: fromHex(v.secret) }
        : { password: v.password, keyfile: v.keyfile ? fromHex(v.keyfile) : undefined };
      const opts = { cal: v.cal, kdf: v.kdf === 0 ? undefined : v.kdf, kdfParams: v.params || undefined,
                     aad: fromHex(v.aad), context: v.context, _salt: fromHex(v.salt), _nonce: fromHex(v.nonce) };
      await t('paquete completo identico a Python: ' + v.name, async () =>
        hex(await v2.seal(fromHex(v.plaintext), creds, opts)) === v.packet);
      await t('abre el paquete generado por Python: ' + v.name, async () =>
        hex(await v2.open(fromHex(v.packet), creds, { aad: fromHex(v.aad), context: v.context })) === v.plaintext);
      await t('encKey/macKey identicas a Python: ' + v.name, async () => {
        const salt = fromHex(v.salt);
        const ikm = await T._v2.ikm(v.kdf, v.params, salt, creds, {});
        const k = await T._v2.deriveKeys(ikm, salt, v.cal, v.kdf, v.context);
        return hex(k.encKey) === v.encKey && hex(k.macKey) === v.macKey;
      });
    }
  }

  console.log('--- roundtrip ---');
  for (const n of [0, 1, 31, 32, 33, 64, 1000]) {
    await t(`secreto 64 B, mensaje de ${n} bytes`, async () => {
      const m = bytes(n, (i) => (i * 7) & 0xff);
      return hex(await v2.open(await v2.seal(m, { secret: secret64 }), { secret: secret64 })) === hex(m);
    });
  }
  await t('secreto 32 B (2^128 Grover) sigue funcionando', async () =>
    hex(await v2.open(await v2.seal(pt, { secret: secret32 }), { secret: secret32 })) === hex(pt));
  await t('rechaza secretos de longitud invalida', async () =>
    await rejects(v2.seal(pt, { secret: bytes(40) })));

  console.log('--- integridad: cualquier byte alterado invalida el paquete ---');
  await t('bit-flip en TODAS las posiciones (cabecera, sal, nonce, CT, tag)', async () => {
    const p = await v2.seal(bytes(40), { secret: secret64 });
    for (let i = 0; i < p.length; i++) {
      const q = Uint8Array.from(p); q[i] ^= 1;
      if (!(await rejects(v2.open(q, { secret: secret64 })))) throw new Error('abrio con el byte ' + i + ' alterado');
    }
    return true;
  });
  await t('truncar o alargar el paquete falla', async () => {
    const p = await v2.seal(pt, { secret: secret64 });
    return (await rejects(v2.open(p.slice(0, p.length - 1), { secret: secret64 }))) &&
           (await rejects(v2.open(Uint8Array.from([...p, 0]), { secret: secret64 })));
  });
  await t('AAD distinto => no abre', async () => {
    const p = await v2.seal(pt, { secret: secret64 }, { aad: bytes(3) });
    return await rejects(v2.open(p, { secret: secret64 }, { aad: bytes(4) })) &&
           !(await rejects(v2.open(p, { secret: secret64 }, { aad: bytes(3) })));
  });
  await t('contexto distinto => no abre', async () => {
    const p = await v2.seal(pt, { secret: secret64 }, { context: 'A' });
    return await rejects(v2.open(p, { secret: secret64 }, { context: 'B' }));
  });
  await t('secreto distinto (1 bit) => no abre', async () => {
    const p = await v2.seal(pt, { secret: secret64 });
    const s2 = Uint8Array.from(secret64); s2[63] ^= 1;
    return await rejects(v2.open(p, { secret: s2 }));
  });

  console.log('--- claves por mensaje y calendario ---');
  await t('dos cifrados iguales: sal, nonce, CT y claves distintos', async () => {
    const a = await v2.seal(pt, { secret: secret64 }), b = await v2.seal(pt, { secret: secret64 });
    const ha = T._v2.parseHeader(a), hb = T._v2.parseHeader(b);
    const ka = await T._v2.deriveKeys(secret64, ha.salt, ha.cal, ha.kdf, '');
    const kb = await T._v2.deriveKeys(secret64, hb.salt, hb.cal, hb.kdf, '');
    return hex(ha.salt) !== hex(hb.salt) && hex(ha.nonce) !== hex(hb.nonce) &&
           hex(a) !== hex(b) && hex(ka.encKey) !== hex(kb.encKey) && hex(ka.macKey) !== hex(kb.macKey);
  });
  await t('encKey y macKey son distintas entre si (separacion de claves)', async () => {
    const k = await T._v2.deriveKeys(secret64, bytes(32), 1, 0, '');
    return hex(k.encKey) !== hex(k.macKey) && k.encKey.length === 64 && k.macKey.length === 64;
  });
  await t('cambiar el byte CAL (1->0) invalida el paquete', async () => {
    const p = await v2.seal(pt, { secret: secret64 }); p[1] = 0;
    return await rejects(v2.open(p, { secret: secret64 }));
  });
  await t('el calendario cambia el cifrado (cal0 != cal1, misma sal/nonce)', async () => {
    const o = { _salt: bytes(32), _nonce: bytes(16, (i) => 200 - i) };
    const a = await v2.seal(pt, { secret: secret64 }, { ...o, cal: 0 });
    const b = await v2.seal(pt, { secret: secret64 }, { ...o, cal: 1 });
    return hex(a.slice(51, 51 + pt.length)) !== hex(b.slice(51, 51 + pt.length));
  });
  await t('version/calendario desconocidos rechazados', async () => {
    const p = await v2.seal(pt, { secret: secret64 });
    const a = Uint8Array.from(p); a[0] = 3; const b = Uint8Array.from(p); b[1] = 9;
    return (await rejects(v2.open(a, { secret: secret64 }))) && (await rejects(v2.open(b, { secret: secret64 })));
  });

  console.log('--- KDF: limites y anti-downgrade ---');
  const S = bytes(32), N = bytes(16);
  const hdr = (kdf, params) => { try { return T._v2.buildHeader({ cal: 1, kdf, kdfParams: params, salt: S, nonce: N }); } catch (e) { return null; } };
  const tagPad = new Uint8Array(64);
  const cat = (h) => Uint8Array.from([...h, ...tagPad]);
  await t('Argon2 con memoria/pasadas insuficientes: rechazado', () =>
    throwsSync(() => T._v2.parseHeader(cat(hdr(1, { memKiB: 8, passes: 1, lanes: 1 })))) &&
    throwsSync(() => T._v2.parseHeader(cat(hdr(1, { memKiB: 65536, passes: 1, lanes: 4 })))));
  await t('Argon2 con memoria excesiva (DoS): rechazado', () =>
    throwsSync(() => T._v2.parseHeader(cat(hdr(1, { memKiB: 2 ** 31, passes: 3, lanes: 4 })))));
  await t('PBKDF2 con pocas o demasiadas iteraciones: rechazado', () =>
    throwsSync(() => T._v2.parseHeader(cat(hdr(2, { iterations: 10 })))) &&
    throwsSync(() => T._v2.parseHeader(cat(hdr(2, { iterations: 2 ** 31 })))));
  await t('scrypt con N pequeno o memoria excesiva: rechazado', () =>
    throwsSync(() => T._v2.parseHeader(cat(hdr(3, { logN: 10, r: 8, p: 1 })))) &&
    throwsSync(() => T._v2.parseHeader(cat(hdr(3, { logN: 20, r: 16, p: 1 })))));
  await t('parametros por defecto dentro de limites', () =>
    !throwsSync(() => T._v2.parseHeader(cat(hdr(1, v2.DEFAULTS.argon2)))) &&
    !throwsSync(() => T._v2.parseHeader(cat(hdr(2, v2.DEFAULTS.pbkdf2)))) &&
    !throwsSync(() => T._v2.parseHeader(cat(hdr(3, v2.DEFAULTS.scrypt)))));
  await t('degradar KDF (scrypt -> PBKDF2/RAW) en el byte kdf invalida el paquete', async () => {
    const creds = { password: 'pw' };
    const p = await v2.seal(pt, creds, { kdf: 3, kdfParams: { logN: 15, r: 8, p: 1 } });
    const a = Uint8Array.from(p); a[2] = 0; const b = Uint8Array.from(p); b[2] = 2;
    return (await rejects(v2.open(a, { secret: secret64 }))) && (await rejects(v2.open(b, creds)));
  });
  await t('expectKdf: el receptor puede exigir un KDF concreto', async () => {
    const p = await v2.seal(pt, { secret: secret64 });
    return await rejects(v2.open(p, { secret: secret64 }, { expectKdf: v2.KDF.ARGON2ID }));
  });
  await t('contrasena + keyfile: keyfile distinta => no abre', async () => {
    const o = { kdf: 2, kdfParams: { iterations: 210000 } };
    const p = await v2.seal(pt, { password: 'pw', keyfile: bytes(64) }, o);
    return await rejects(v2.open(p, { password: 'pw', keyfile: bytes(64, (i) => i + 1) })) &&
           await rejects(v2.open(p, { password: 'pw' })) &&
           hex(await v2.open(p, { password: 'pw', keyfile: bytes(64) })) === hex(pt);
  });
  await t('sin KDF memory-hard disponible no se degrada en silencio a PBKDF2', async () => {
    // simula un entorno sin scrypt ni Argon2: debe exigir allowPbkdf2 explicito
    const nc = require('crypto'); const orig = nc.scrypt; nc.scrypt = undefined;
    try { return await rejects(v2.seal(pt, { password: 'pw' })); } finally { nc.scrypt = orig; }
  });

  console.log('--- niveles de seguridad declarados ---');
  await t('secreto 64 B => Grover 2^256 / 32 B => 2^128', () =>
    v2.securityLevel({ secret: secret64 }).groverBits === 256 && v2.securityLevel({ secret: secret32 }).groverBits === 128);
  await t('contrasena sola NO declara 2^256; con keyfile de 64 B si', () =>
    v2.securityLevel({ password: 'x' }).groverBits === null &&
    v2.securityLevel({ password: 'x', keyfile: bytes(64) }).groverBits === 256 &&
    v2.securityLevel({ password: 'x', keyfile: bytes(32) }).groverBits === null);
  await t('generateSecret(): 64 bytes y no repetido', () => {
    const a = v2.generateSecret(), b = v2.generateSecret();
    return a.length === 64 && hex(a) !== hex(b);
  });

  console.log('--- compatibilidad v1 ---');
  await t('v1 cifra/descifra como antes y no se mezcla con v2', async () => {
    const { encKey, macKey } = await mysx.deriveAeadKeys(bytes(32));
    const p1 = await mysx.aeadEncrypt(pt, encKey, macKey, { unsafeNoGuard: true });
    const ok = hex(await mysx.aeadDecrypt(p1, encKey, macKey)) === hex(pt);
    const p2 = await v2.seal(pt, { secret: secret64 });
    return ok && p1[0] === 1 && p2[0] === 2 &&
           await rejects(v2.open(p1, { secret: secret64 })) &&
           await rejects(mysx.aeadDecrypt(p2, encKey, macKey));
  });

  console.log('--- Argon2id (si @noble/hashes esta instalado) ---');
  let noble = null;
  try { noble = await import('@noble/hashes/argon2.js'); } catch (e) { /* no instalado */ }
  if (!noble) { skipped++; console.log('  [SKIP] @noble/hashes no instalado'); }
  else {
    await t('noble: vector RFC 9106 Argon2id (vector transcrito; contrasta con RFC 9106 s5.3 si falla)', async () => {
      const out = await noble.argon2idAsync(new Uint8Array(32).fill(1), new Uint8Array(16).fill(2),
        { t: 3, m: 32, p: 4, dkLen: 32, key: new Uint8Array(8).fill(3), personalization: new Uint8Array(12).fill(4) });
      return hex(out) === '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659';
    });
    v2.setArgon2Provider(v2.argon2FromNoble(noble.argon2idAsync));
    const ap = { memKiB: 19456, passes: 2, lanes: 1 };
    await t('Argon2id por proveedor: seleccion automatica, roundtrip y cabecera', async () => {
      const p = await v2.seal(pt, { password: 'pw', keyfile: bytes(64) }, { kdfParams: ap });
      return p[2] === v2.KDF.ARGON2ID &&
             hex(await v2.open(p, { password: 'pw', keyfile: bytes(64) })) === hex(pt);
    });
    await t('Argon2id: parametros alterados en la cabecera invalidan el paquete', async () => {
      const p = await v2.seal(pt, { password: 'pw' }, { kdfParams: ap });
      const q = Uint8Array.from(p); q[6] ^= 1;        // byte de "passes"
      return await rejects(v2.open(q, { password: 'pw' }));
    });
    await t('proveedor que devuelve longitud incorrecta: rechazado', async () => {
      v2.setArgon2Provider(() => new Uint8Array(32));
      const r = await rejects(v2.seal(pt, { password: 'pw' }, { kdf: 1, kdfParams: ap }));
      v2.setArgon2Provider(v2.argon2FromNoble(noble.argon2idAsync));
      return r;
    });
    v2.setArgon2Provider(null);
  }

  console.log(`\nV2 TESTS: ${pass} pass, ${fail} fail, ${skipped} skipped`);
  process.exit(fail ? 1 : 0);
})();
