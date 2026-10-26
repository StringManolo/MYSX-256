'use strict';
const mysx = require('./mysx.prod.js');
const { v2 } = mysx;

(async () => {
  const results = {};

  // 1. ¿V02 calendar inyectado?
  results.calendar_injected = mysx.TEST && mysx.TEST.CAL_TABLES[1] !== null;

  // 2. ¿v2 API completo?
  const required = ['seal', 'open', 'generateSecret', 'securityLevel',
                    'setArgon2Provider', 'argon2FromNoble',
                    'CAL', 'KDF', 'DEFAULTS', 'LIMITS'];
  results.v2_api_complete = required.every(k => k in v2);

  // 3. ¿Argon2id provider registrado?
  let argon2 = 'none';
  try {
    const { argon2idAsync } = await import('@noble/hashes/argon2.js');
    v2.setArgon2Provider(v2.argon2FromNoble(argon2idAsync));
    argon2 = 'noble';
  } catch (e) {
    if (typeof require('crypto').argon2 === 'function') argon2 = 'native';
    else if (typeof require('crypto').scrypt === 'function') argon2 = 'scrypt-fallback';
    else argon2 = 'none';
  }
  results.argon2 = argon2;

  // 4. Round-trip v2 con secret 64B
  try {
    const secret = v2.generateSecret();
    const pt = new TextEncoder().encode('round-trip test');
    const aad = new Uint8Array([1, 2, 3]);
    const ct = await v2.seal(pt, { secret }, { aad, context: 'verify' });
    const rt = await v2.open(ct, { secret }, { aad, context: 'verify' });
    results.roundtrip_raw = new TextDecoder().decode(rt) === 'round-trip test';
    results.packet_version = ct[0];  // debe ser 2
    results.packet_cal = ct[1];      // debe ser 1
  } catch (e) {
    results.roundtrip_raw = false;
    results.error = String(e);
  }

  // 5. Round-trip con password (si Argon2 o scrypt disponible)
  if (argon2 === 'noble' || argon2 === 'native' || argon2 === 'scrypt-fallback') {
    try {
      const pt = new TextEncoder().encode('password test');
      const ct = await v2.seal(pt, { password: 'test-password' }, {
        context: 'verify', allowPbkdf2: false
      });
      const rt = await v2.open(ct, { password: 'test-password' }, { context: 'verify' });
      results.roundtrip_password = new TextDecoder().decode(rt) === 'password test';
      results.packet_kdf = ct[2];  // debe ser 1 (Argon2), 2 (PBKDF2) o 3 (scrypt)
    } catch (e) {
      results.roundtrip_password = false;
      results.password_error = String(e);
    }
  } else {
    results.roundtrip_password = 'skipped (no KDF)';
  }

  // 6. securityLevel
  results.security_raw64 = v2.securityLevel({ secret: new Uint8Array(64) });
  results.security_raw32 = v2.securityLevel({ secret: new Uint8Array(32) });

  // 7. ¿v1 sigue funcionando? (para compat)
  try {
    const key = new Uint8Array(64);
    const macKey = new Uint8Array(32);
    const nonce = new Uint8Array(16);
    const pt = new Uint8Array(32);
    // Usar TEST API para forzar nonce
    if (mysx.TEST) {
      const pkt = await mysx.TEST._unsafeAeadEncryptWithNonce(pt, key, macKey, nonce);
      results.v1_compat = pkt[0] === 0x01 && pkt.length === 1 + 16 + 32 + 32;
    }
  } catch (e) {
    results.v1_compat = String(e);
  }

  console.log(JSON.stringify(results, null, 2));
})().catch(e => { console.error(e); process.exit(1); });
