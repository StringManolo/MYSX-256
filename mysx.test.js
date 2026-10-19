'use strict';

// =============================================================================
// MYSX-256/512 — Suite de tests (separada del artefacto de producción)
// =============================================================================
// Uso:
//   MYSX_ENABLE_TEST=1 node mysx.test.js
// o:
//   globalThis.__MYSX_ENABLE_TEST__ = true;
//   require('./mysx.test.js');
// =============================================================================

if (typeof process !== 'undefined') process.env.MYSX_ENABLE_TEST = '1';
if (typeof globalThis !== 'undefined') globalThis.__MYSX_ENABLE_TEST__ = true;

const MYSX = require('./mysx.prod.js');
const { TEST, aeadEncrypt, aeadDecrypt, deriveAeadKeys, deriveAeadKeysFromPassword,
        NonceGuard, CONFIG } = MYSX;

if (!TEST) {
  throw new Error('TEST no disponible. Asegúrate de cargar con MYSX_ENABLE_TEST=1');
}

const {
  _ctrXor, _encryptBlockCore, _keySchedule, _makeScratch,
  generateKAT, verifyKAT
} = TEST;
const { BLOCK_BYTES, KEY_BYTES, ROUNDS, NONCE_BYTES, MAC_KEY_BYTES, TAG_BYTES } = CONFIG;

// ---- PRNG reproducible (solo tests) ----
function makeRng(seed) {
  let t = seed >>> 0;
  return function() {
    t = (t + 0x6D2B79F5) >>> 0;
    let x = t;
    x = Math.imul(x ^ (x >>> 15), x | 1);
    x ^= x + Math.imul(x ^ (x >>> 7), x | 61);
    return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
  };
}
function fillRandom(rng, buf) {
  for (let i = 0; i < buf.length; i++) buf[i] = (rng() * 256) | 0;
}
function bitsDiff(a, b) {
  let d = 0;
  for (let i = 0; i < a.length; i++) {
    let x = a[i] ^ b[i];
    while (x) { d += x & 1; x >>>= 1; }
  }
  return d;
}

// ---- Estado del harness ----
const state = {
  okFunctional: true,
  okRegression: true,
  okNoncePolicy: true,
  okPasswordPath: true,
  errors: []
};
function fail(section, msg) {
  state[section] = false;
  state.errors.push(`[${section}] ${msg}`);
  console.log(`  FAIL [${section}] ${msg}`);
}
function pass(msg) { console.log(`  OK   ${msg}`); }

// =============================================================================
// 1) KAT funcional (digest fijado, falla si no coincide)
// =============================================================================
async function testKAT() {
  console.log('\n=== 1) KAT (regresión) ===');
  try {
    const ok = await verifyKAT({ strict: true });
    if (ok === true) pass('KAT coincide con el digest fijado');
    else fail('okRegression', 'KAT no coincide o no configurado');
  } catch (e) {
    fail('okRegression', e.message);
  }
}

// =============================================================================
// 2) Round-trip de bloque (necesita acceso a internos, vía TEST)
// =============================================================================
async function testBlockRoundTrip() {
  console.log('\n=== 2) Round-trip de bloque ===');
  // Round-trip vía CTR (única ruta pública); el bloque puro solo con TEST.
  const rng = makeRng(0xB10C);
  const key = new Uint8Array(KEY_BYTES);
  fillRandom(rng, key);
  const nonce = new Uint8Array(NONCE_BYTES);
  fillRandom(rng, nonce);

  let ok = true;
  for (const n of [0, 1, 15, 31, 32, 33, 100, 1000]) {
    const pt = new Uint8Array(n);
    fillRandom(rng, pt);
    const ct = _ctrXor(pt, key, nonce);
    const pt2 = _ctrXor(ct, key, nonce);
    if (!pt.every((v, i) => v === pt2[i])) { ok = false; break; }
  }
  if (ok) pass('CTR round-trip (8 longitudes)');
  else fail('okFunctional', 'CTR round-trip');
}

// =============================================================================
// 3) AEAD funcional + negativos estrictos
// =============================================================================
async function testAEAD() {
  console.log('\n=== 3) AEAD ===');
  const rng = makeRng(0xAEAD);
  const master = new Uint8Array(32);
  fillRandom(rng, master);
  const { encKey, macKey } = await deriveAeadKeys(master, { context: 'test' });

  const pt = new Uint8Array(80);
  fillRandom(rng, pt);
  const aad = new Uint8Array([0xAA, 0xBB]);
  const guard = new NonceGuard();
  const packet = await aeadEncrypt(pt, encKey, macKey, { aad, nonceGuard: guard });

  const pt2 = await aeadDecrypt(packet, encKey, macKey, { aad });
  if (pt.every((v, i) => v === pt2[i])) pass('round-trip 80 bytes + AAD');
  else fail('okFunctional', 'AEAD round-trip');

  // Negativos estrictos: deben fallar con 'MAC inválido'
  async function expectMACFail(label, mutator) {
    const p = new Uint8Array(packet);
    mutator(p);
    try { await aeadDecrypt(p, encKey, macKey, { aad }); }
    catch (e) {
      if (e.message.startsWith('MAC inválido')) { pass(`rechaza ${label}`); return; }
      fail('okFunctional', `${label}: excepción inesperada (${e.message})`);
      return;
    }
    fail('okFunctional', `${label}: no detectó manipulación`);
  }
  await expectMACFail('nonce alterado', p => { p[1] ^= 1; });
  await expectMACFail('ct alterado',    p => { p[1 + NONCE_BYTES] ^= 1; });
  await expectMACFail('tag alterado',   p => { p[p.length - 1] ^= 1; });

  try { await aeadDecrypt(packet, encKey, macKey, { aad: new Uint8Array([0xAA, 0xBC]) }); 
        fail('okFunctional', 'AAD distinto: no detectó manipulación'); }
  catch (e) {
    if (e.message.startsWith('MAC inválido')) pass('rechaza AAD distinto');
    else fail('okFunctional', `AAD distinto: excepción inesperada (${e.message})`);
  }

  // NonceGuard debe detectar reutilización si el mismo nonce se reinyecta
  // (esto requiere llamar al path unsafe con TEST._unsafe? no existe en PROD;
  //  verificamos que dos llamadas seguidas generan nonces distintos y ambos
  //  pasan el guard)
  const p2 = await aeadEncrypt(pt, encKey, macKey, { aad, nonceGuard: guard });
  if (p2[1] !== packet[1] || p2[2] !== packet[2]) pass('dos cifrados generan nonces distintos');
  else fail('okNoncePolicy', 'nonces repetidos');
}

// =============================================================================
// 4) Política de nonces y límites operativos
// =============================================================================
async function testNoncePolicy() {
  console.log('\n=== 4) NonceGuard ===');
  const rng = makeRng(0x90CE);
  const master = new Uint8Array(32);
  fillRandom(rng, master);
  const { encKey, macKey } = await deriveAeadKeys(master, { context: 'test' });

  // a) Sin guard ni unsafe -> debe lanzar
  try {
    await aeadEncrypt(new Uint8Array(8), encKey, macKey);
    fail('okNoncePolicy', 'aeadEncrypt sin guard no lanzó');
  } catch (e) {
    if (e.message.includes('nonceGuard')) pass('sin guard: rechazado');
    else fail('okNoncePolicy', `sin guard: excepción inesperada (${e.message})`);
  }

  // b) unsafeNoGuard: true -> debe funcionar
  try {
    await aeadEncrypt(new Uint8Array(8), encKey, macKey, { unsafeNoGuard: true });
    pass('unsafeNoGuard: aceptado');
  } catch (e) {
    fail('okNoncePolicy', `unsafeNoGuard: ${e.message}`);
  }

  // c) Guard con límite bajo: superarlo debe lanzar
  const guard = new NonceGuard({ maxMessagesPerKey: 3 });
  for (let i = 0; i < 3; i++) {
    await aeadEncrypt(new Uint8Array(8), encKey, macKey, { nonceGuard: guard });
  }
  try {
    await aeadEncrypt(new Uint8Array(8), encKey, macKey, { nonceGuard: guard });
    fail('okNoncePolicy', 'límite operativo no se aplicó');
  } catch (e) {
    if (e.message.includes('Límite operativo')) pass('límite operativo aplicado');
    else fail('okNoncePolicy', `límite: excepción inesperada (${e.message})`);
  }

  // d) Stats coherentes
  const s = guard.stats(encKey);
  if (s.count === 3) pass(`stats: count=${s.count}`);
  else fail('okNoncePolicy', `stats: count=${s.count}, esperado 3`);
}

// =============================================================================
// 5) Derivación de claves: contraseña vs secreto aleatorio
// =============================================================================
async function testKeyDerivation() {
  console.log('\n=== 5) Derivación de claves ===');
  const rng = makeRng(0xDEAD);
  const master = new Uint8Array(32);
  fillRandom(rng, master);
  const salt = new Uint8Array(16);
  fillRandom(rng, salt);

  // a) HKDF con secreto aleatorio
  try {
    const { encKey, macKey } = await deriveAeadKeys(master, { salt });
    if (encKey.length === KEY_BYTES && macKey.length === MAC_KEY_BYTES) pass('HKDF: longitudes correctas');
    else fail('okFunctional', 'HKDF: longitudes');
  } catch (e) { fail('okFunctional', `HKDF: ${e.message}`); }

  // b) HKDF con contextos distintos -> claves distintas
  try {
    const a = await deriveAeadKeys(master, { context: 'ctx-A', salt });
    const b = await deriveAeadKeys(master, { context: 'ctx-B', salt });
    const diff = !a.encKey.every((v, i) => v === b.encKey[i]);
    if (diff) pass('HKDF: contextos separan claves');
    else fail('okFunctional', 'HKDF: contextos no separan');
  } catch (e) { fail('okFunctional', `HKDF ctx: ${e.message}`); }

  // c) PBKDF2 sin salt -> debe lanzar
  try {
    await deriveAeadKeysFromPassword('correct horse battery staple', null);
    fail('okPasswordPath', 'PBKDF2 sin salt no lanzó');
  } catch (e) {
    if (e.message.includes('salt')) pass('PBKDF2 sin salt: rechazado');
    else fail('okPasswordPath', `PBKDF2 sin salt: ${e.message}`);
  }

  // d) PBKDF2 con salt -> funciona, y dos llamadas con la misma salt dan lo mismo
  try {
    const a = await deriveAeadKeysFromPassword('correct horse', salt, { iterations: 1000 });
    const b = await deriveAeadKeysFromPassword('correct horse', salt, { iterations: 1000 });
    if (a.encKey.every((v, i) => v === b.encKey[i])) pass('PBKDF2: determinista con misma salt');
    else fail('okPasswordPath', 'PBKDF2: no determinista');
  } catch (e) { fail('okPasswordPath', `PBKDF2: ${e.message}`); }

  // e) PBKDF2 con salts distintas -> claves distintas
  try {
    const salt2 = new Uint8Array(16);
    fillRandom(rng, salt2);
    const a = await deriveAeadKeysFromPassword('correct horse', salt,  { iterations: 1000 });
    const b = await deriveAeadKeysFromPassword('correct horse', salt2, { iterations: 1000 });
    const diff = !a.encKey.every((v, i) => v === b.encKey[i]);
    if (diff) pass('PBKDF2: salts distintas → claves distintas');
    else fail('okPasswordPath', 'PBKDF2: salts no separan');
  } catch (e) { fail('okPasswordPath', `PBKDF2 salt: ${e.message}`); }
}

// =============================================================================
// 6) Avalancha (indicador, no prueba)
// =============================================================================
async function testAvalanche() {
  console.log('\n=== 6) Avalancha (indicador, no prueba) ===');
  const rng = makeRng(0xA7A1);
  const key = new Uint8Array(KEY_BYTES);
  fillRandom(rng, key);
  const sch = _keySchedule(key);
  const sc = _makeScratch();

  const p = new Uint8Array(32);
  fillRandom(rng, p);
  const c0 = _encryptBlockCore(p, sch, ROUNDS, sc, true).slice();
  let total = 0;
  for (let bit = 0; bit < 256; bit++) {
    const p2 = new Uint8Array(p);
    p2[bit >> 3] ^= (1 << (bit & 7));
    total += bitsDiff(c0, _encryptBlockCore(p2, sch, ROUNDS, sc, true));
  }
  const avg = total / 256;
  console.log(`  texto plano: ${avg.toFixed(2)}/256 (ideal 128)`);
  if (Math.abs(avg - 128) < 8) pass('avalancha en rango');
  else fail('okFunctional', `avalancha fuera de rango: ${avg.toFixed(2)}`);
}

// =============================================================================
// Main
// =============================================================================
(async () => {
  console.log('\n=== MYSX-256/512 — Suite de tests ===');
  console.log('ADVERTENCIA: ningún test demuestra seguridad criptográfica.\n');

  await testKAT();
  await testBlockRoundTrip();
  await testAEAD();
  await testNoncePolicy();
  await testKeyDerivation();
  await testAvalanche();

  console.log('\n=== RESUMEN ===');
  const labels = {
    okFunctional:  'Funcional (round-trip, AEAD, KAT)',
    okRegression:  'Regresión (KAT)',
    okNoncePolicy:'Política de nonces',
    okPasswordPath:'Ruta de contraseña (PBKDF2)'
  };
  let allOk = true;
  for (const [k, label] of Object.entries(labels)) {
    console.log(`  ${label.padEnd(42)} ${state[k] ? 'PASS' : 'FAIL'}`);
    if (!state[k]) allOk = false;
  }
  if (state.errors.length) {
    console.log('\n  Errores:');
    for (const e of state.errors) console.log('    - ' + e);
  }
  console.log(`\n  RESULTADO GLOBAL: ${allOk ? 'PASS' : 'FAIL'}`);
  console.log('\n  CRYPTANALYSIS_STATUS: NOT_ESTABLISHED');
  console.log('  Un PASS aquí solo dice que los tests elegidos no detectaron fallos.');
  console.log('  La seguridad requiere criptoanálisis público independiente.');
  process.exit(allOk ? 0 : 1);
})().catch(e => { console.error(e); process.exit(1); });