'use strict';

// =============================================================================
// MYSX-256/512 — Test suite (v0.1-draft)
// =============================================================================
// Usage:
//   MYSX_ENABLE_TEST=1 node mysx.test.js
// =============================================================================

if (typeof process !== 'undefined') process.env.MYSX_ENABLE_TEST = '1';

const MYSX = require('./mysx.prod.js');
const { TEST, aeadEncrypt, aeadDecrypt, deriveAeadKeys, deriveAeadKeysFromPassword,
        NonceGuard, CONFIG } = MYSX;

if (!TEST) {
  throw new Error('TEST not available. Load with MYSX_ENABLE_TEST=1');
}

const {
  _ctrXor, _encryptBlockCore, _keySchedule, _makeScratch,
  generateKAT, verifyKAT
} = TEST;
const { BLOCK_BYTES, KEY_BYTES, ROUNDS, NONCE_BYTES, MAC_KEY_BYTES, TAG_BYTES } = CONFIG;

// ---- Reproducible PRNG (tests only) ----
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

// ---- Harness state ----
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
// 1) KAT (regression)
// =============================================================================
async function testKAT() {
  console.log('\n=== 1) KAT (regression) ===');
  try {
    const ok = await verifyKAT({ strict: true });
    if (ok === true) pass('KAT matches the fixed digest');
    else fail('okRegression', 'KAT does not match or not configured');
  } catch (e) {
    fail('okRegression', e.message);
  }
}

// =============================================================================
// 2) Block round-trip (via CTR)
// =============================================================================
async function testBlockRoundTrip() {
  console.log('\n=== 2) Block round-trip (via CTR) ===');
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
  if (ok) pass('CTR round-trip (8 lengths)');
  else fail('okFunctional', 'CTR round-trip');
}

// =============================================================================
// 3) AEAD functional + strict negatives
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

  // Negative tests: must fail with 'Invalid MAC'
  async function expectMACFail(label, mutator) {
    const p = new Uint8Array(packet);
    mutator(p);
    try { await aeadDecrypt(p, encKey, macKey, { aad }); }
    catch (e) {
      if (e.message === 'Invalid MAC') { pass(`rejects ${label}`); return; }
      fail('okFunctional', `${label}: unexpected error (${e.message})`);
      return;
    }
    fail('okFunctional', `${label}: did not detect tampering`);
  }
  await expectMACFail('altered nonce', p => { p[1] ^= 1; });
  await expectMACFail('altered ct',    p => { p[1 + NONCE_BYTES] ^= 1; });
  await expectMACFail('altered tag',   p => { p[p.length - 1] ^= 1; });

  try { await aeadDecrypt(packet, encKey, macKey, { aad: new Uint8Array([0xAA, 0xBC]) }); 
        fail('okFunctional', 'different AAD: did not detect tampering'); }
  catch (e) {
    if (e.message === 'Invalid MAC') pass('rejects different AAD');
    else fail('okFunctional', `different AAD: unexpected error (${e.message})`);
  }

  // Two encryptions must use different nonces
  const p2 = await aeadEncrypt(pt, encKey, macKey, { aad, nonceGuard: guard });
  if (p2[1] !== packet[1] || p2[2] !== packet[2]) pass('two encryptions use different nonces');
  else fail('okNoncePolicy', 'repeated nonces');
}

// =============================================================================
// 4) NonceGuard policy and operational limits
// =============================================================================
async function testNoncePolicy() {
  console.log('\n=== 4) NonceGuard ===');
  const rng = makeRng(0x90CE);
  const master = new Uint8Array(32);
  fillRandom(rng, master);
  const { encKey, macKey } = await deriveAeadKeys(master, { context: 'test' });

  // a) Without guard and without unsafe -> must throw
  try {
    await aeadEncrypt(new Uint8Array(8), encKey, macKey);
    fail('okNoncePolicy', 'aeadEncrypt without guard did not throw');
  } catch (e) {
    if (e.message.includes('nonceGuard')) pass('without guard: rejected');
    else fail('okNoncePolicy', `without guard: unexpected error (${e.message})`);
  }

  // b) unsafeNoGuard: true -> must work
  try {
    await aeadEncrypt(new Uint8Array(8), encKey, macKey, { unsafeNoGuard: true });
    pass('unsafeNoGuard: accepted');
  } catch (e) {
    fail('okNoncePolicy', `unsafeNoGuard: ${e.message}`);
  }

  // c) Guard with low limit: exceeding it must throw
  const guard = new NonceGuard({ maxMessagesPerKey: 3 });
  for (let i = 0; i < 3; i++) {
    await aeadEncrypt(new Uint8Array(8), encKey, macKey, { nonceGuard: guard });
  }
  try {
    await aeadEncrypt(new Uint8Array(8), encKey, macKey, { nonceGuard: guard });
    fail('okNoncePolicy', 'operational limit not enforced');
  } catch (e) {
    if (e.message.includes('Operational limit')) pass('operational limit enforced');
    else fail('okNoncePolicy', `limit: unexpected error (${e.message})`);
  }

  // d) Stats coherent
  const s = guard.stats(encKey);
  if (s.count === 3) pass(`stats: count=${s.count}`);
  else fail('okNoncePolicy', `stats: count=${s.count}, expected 3`);

  // e) P2: maxTrackedKeys (LRU eviction)
  const guard2 = new NonceGuard({ maxTrackedKeys: 2 });
  const k1 = new Uint8Array(KEY_BYTES); fillRandom(rng, k1);
  const k2 = new Uint8Array(KEY_BYTES); fillRandom(rng, k2);
  const k3 = new Uint8Array(KEY_BYTES); fillRandom(rng, k3);
  await aeadEncrypt(new Uint8Array(4), k1, macKey, { nonceGuard: guard2 });
  await aeadEncrypt(new Uint8Array(4), k2, macKey, { nonceGuard: guard2 });
  await aeadEncrypt(new Uint8Array(4), k3, macKey, { nonceGuard: guard2 });
  const s1 = guard2.stats(k1);
  const s3 = guard2.stats(k3);
  if (s1.count === 0 && s3.count === 1) pass('maxTrackedKeys: LRU eviction works');
  else fail('okNoncePolicy', `maxTrackedKeys: k1=${s1.count}, k3=${s3.count}`);
}

// =============================================================================
// 5) Key derivation: password vs random secret
// =============================================================================
async function testKeyDerivation() {
  console.log('\n=== 5) Key derivation ===');
  const rng = makeRng(0xDEAD);
  const master = new Uint8Array(32);
  fillRandom(rng, master);
  const salt = new Uint8Array(16);
  fillRandom(rng, salt);

  // a) HKDF with random secret
  try {
    const { encKey, macKey } = await deriveAeadKeys(master, { salt });
    if (encKey.length === KEY_BYTES && macKey.length === MAC_KEY_BYTES)
      pass('HKDF: correct lengths');
    else fail('okFunctional', 'HKDF: lengths');
  } catch (e) { fail('okFunctional', `HKDF: ${e.message}`); }

  // b) HKDF with different contexts -> different keys
  try {
    const a = await deriveAeadKeys(master, { context: 'ctx-A', salt });
    const b = await deriveAeadKeys(master, { context: 'ctx-B', salt });
    const diff = !a.encKey.every((v, i) => v === b.encKey[i]);
    if (diff) pass('HKDF: contexts separate keys');
    else fail('okFunctional', 'HKDF: contexts do not separate');
  } catch (e) { fail('okFunctional', `HKDF ctx: ${e.message}`); }

  // c) PBKDF2 without salt -> must throw
  try {
    await deriveAeadKeysFromPassword('correct horse battery staple', null);
    fail('okPasswordPath', 'PBKDF2 without salt did not throw');
  } catch (e) {
    if (e.message.includes('salt')) pass('PBKDF2 without salt: rejected');
    else fail('okPasswordPath', `PBKDF2 without salt: ${e.message}`);
  }

  // d) PBKDF2 with salt -> deterministic
  try {
    const a = await deriveAeadKeysFromPassword('correct horse', salt, { iterations: 1000 });
    const b = await deriveAeadKeysFromPassword('correct horse', salt, { iterations: 1000 });
    if (a.encKey.every((v, i) => v === b.encKey[i]))
      pass('PBKDF2: deterministic with same salt');
    else fail('okPasswordPath', 'PBKDF2: not deterministic');
  } catch (e) { fail('okPasswordPath', `PBKDF2: ${e.message}`); }

  // e) PBKDF2 with different salts -> different keys
  try {
    const salt2 = new Uint8Array(16);
    fillRandom(rng, salt2);
    const a = await deriveAeadKeysFromPassword('correct horse', salt,  { iterations: 1000 });
    const b = await deriveAeadKeysFromPassword('correct horse', salt2, { iterations: 1000 });
    const diff = !a.encKey.every((v, i) => v === b.encKey[i]);
    if (diff) pass('PBKDF2: different salts → different keys');
    else fail('okPasswordPath', 'PBKDF2: salts do not separate');
  } catch (e) { fail('okPasswordPath', `PBKDF2 salt: ${e.message}`); }
}

// =============================================================================
// 6) Avalanche (indicator, not proof)
// =============================================================================
async function testAvalanche() {
  console.log('\n=== 6) Avalanche (indicator, not proof) ===');
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
  console.log(`  plaintext: ${avg.toFixed(2)}/256 (ideal 128)`);
  if (Math.abs(avg - 128) < 8) pass('avalanche in range');
  else fail('okFunctional', `avalanche out of range: ${avg.toFixed(2)}`);
}

// =============================================================================
// Main
// =============================================================================
(async () => {
  console.log('\n=== MYSX-256/512 — Test suite (v0.1-draft) ===');
  console.log('WARNING: no test proves cryptographic security.\n');

  await testKAT();
  await testBlockRoundTrip();
  await testAEAD();
  await testNoncePolicy();
  await testKeyDerivation();
  await testAvalanche();

  console.log('\n=== SUMMARY ===');
  const labels = {
    okFunctional:  'Functional (round-trip, AEAD, KAT)',
    okRegression:  'Regression (KAT)',
    okNoncePolicy:'Nonce policy',
    okPasswordPath:'Password path (PBKDF2)'
  };
  let allOk = true;
  for (const [k, label] of Object.entries(labels)) {
    console.log(`  ${label.padEnd(42)} ${state[k] ? 'PASS' : 'FAIL'}`);
    if (!state[k]) allOk = false;
  }
  if (state.errors.length) {
    console.log('\n  Errors:');
    for (const e of state.errors) console.log('    - ' + e);
  }
  console.log(`\n  GLOBAL RESULT: ${allOk ? 'PASS' : 'FAIL'}`);
  console.log('\n  CRYPTANALYSIS_STATUS: NOT_ESTABLISHED');
  console.log('  A PASS here only says the chosen tests did not detect failures.');
  console.log('  Security requires independent public cryptanalysis.');
  process.exit(allOk ? 0 : 1);
})().catch(e => { console.error(e); process.exit(1); });
