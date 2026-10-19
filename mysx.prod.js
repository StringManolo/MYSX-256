'use strict';

// =============================================================================
// MYSX-256/512 — API de PRODUCCIÓN  (v0.1-experimental)
// -----------------------------------------------------------------------------
// Cifrador propio, NO auditado externamente. NO usar para datos sensibles.
// Para producción real: AES-256-GCM o XChaCha20-Poly1305.
//
// Este artefacto NO expone:
//   - CTR crudo
//   - cifrado con nonce impuesto
//   - funciones de rondas reducidas
//   - utilidades de test
// Solo se exponen AEAD, derivación de claves y NonceGuard.
//
// El cifrador está CONGELADO. Cualquier cambio de ronda o key schedule
// requiere una versión nueva (v0.2-...) y volver a evaluar por separado.
// =============================================================================

const cryptoNode =
  (typeof globalThis !== 'undefined' && globalThis.crypto)
    ? globalThis.crypto
    : (typeof require !== 'undefined' ? require('crypto').webcrypto : null);
if (!cryptoNode) throw new Error('WebCrypto no disponible');

// ===== Parámetros (congelados) =====
const CONFIG = Object.freeze({
  BLOCK_BYTES: 32,
  KEY_BYTES: 64,
  ROUNDS: 128,
  NONCE_BYTES: 16,
  MAC_KEY_BYTES: 32,
  TAG_BYTES: 32,
  VERSION: 0x01,
  MAX_AAD_BYTES: 0x7fffffff,
  MAX_CT_BYTES: 0x7fffffff,
  DEFAULT_MAX_MESSAGES_PER_KEY: 2 ** 32,
  DEFAULT_MAX_TRACKED_NONCES: 1024,
  PBKDF2_ITERATIONS: 600000
});

const {
  BLOCK_BYTES, KEY_BYTES, ROUNDS, NONCE_BYTES, MAC_KEY_BYTES, TAG_BYTES, VERSION
} = CONFIG;

// =============================================================================
// Internos del cifrador (NO exportados en PROD)
// =============================================================================
const MYZ_PERM = new Uint8Array([
   4,12,20,28,  0, 8,16,24,  5,13,21,29,
   2, 7,10,15,18,23,26,31,  6,14,22,30,
   1, 9,17,25,  3,11,19,27
]);
const CONST = new Uint32Array([
  0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
  0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89
]);
function rotl32(x, n) { n &= 31; return (((x << n) | (x >>> (32 - n))) >>> 0); }
function simonF(x)   { return ((rotl32(x, 1) & rotl32(x, 8)) ^ rotl32(x, 2)) >>> 0; }

function _keySchedule(keyBytes) {
  if (keyBytes.length !== KEY_BYTES) throw new Error(`Clave debe ser ${KEY_BYTES} bytes`);
  const s = new Uint32Array(16);
  for (let i = 0; i < 16; i++) {
    s[i] = ((keyBytes[i*4] << 24) | (keyBytes[i*4+1] << 16) |
            (keyBytes[i*4+2] << 8) | keyBytes[i*4+3]) >>> 0;
  }
  const addKeys = new Array(ROUNDS);
  for (let r = 0; r < ROUNDS; r++) {
    const rk = new Uint32Array(8);
    const spread = Math.imul(r + 1, 0x9E3779B9) >>> 0;
    for (let i = 0; i < 8; i++) {
      rk[i] = (s[i] ^ s[(i + 5) & 15] ^ s[(i + 11) & 15]
               ^ CONST[(r + i) & 7] ^ spread) >>> 0;
      if (i < 4) {
        const fk = (s[(i + 8) & 15] ^ CONST[(r + i + 3) & 7]) >>> 0;
        rk[i] = (rk[i] ^ fk) >>> 0;
      }
    }
    addKeys[r] = rk;
    const L = s.slice(0, 8);
    const R = s.slice(8, 16);
    for (let i = 0; i < 8; i++) {
      const a = R[i], b = R[(i + 1) & 7], c = R[(i + 3) & 7];
      const F = (rotl32((a + b) >>> 0, 7) ^ rotl32(c, 13)
                 ^ CONST[i] ^ spread) >>> 0;
      s[i]     = R[i];
      s[i + 8] = (L[i] ^ F) >>> 0;
    }
  }
  const rkFinal = new Uint32Array(8);
  for (let i = 0; i < 8; i++) {
    rkFinal[i] = (s[i] ^ s[(i + 8) & 15] ^ CONST[(ROUNDS + i) & 7]) >>> 0;
  }
  return { addKeys, rkFinal };
}

function _makeScratch() {
  return { tmp: new Uint8Array(32), tmp2: new Uint8Array(32),
           st: new Uint32Array(8), out: new Uint8Array(32) };
}

function _roundEncrypt(st, rk, r, sc) {
  const { tmp, tmp2 } = sc;
  for (let i = 0; i < 8; i++) st[i] = (st[i] ^ rk[i]) >>> 0;
  for (let i = 0; i < 4; i++) {
    const L = st[i], R = st[i + 4];
    st[i]     = R;
    st[i + 4] = (L ^ simonF(R)) >>> 0;
  }
  for (let i = 0; i < 8; i++) {
    tmp[i*4]   = (st[i] >>> 24) & 0xff;
    tmp[i*4+1] = (st[i] >>> 16) & 0xff;
    tmp[i*4+2] = (st[i] >>> 8)  & 0xff;
    tmp[i*4+3] =  st[i]         & 0xff;
  }
  for (let i = 0; i < 32; i++) tmp2[i] = tmp[MYZ_PERM[i]];
  for (let i = 0; i < 8; i++) {
    st[i] = ((tmp2[i*4] << 24) | (tmp2[i*4+1] << 16) |
             (tmp2[i*4+2] << 8) | tmp2[i*4+3]) >>> 0;
  }
  const sh = ((r % 31) + 1) | 0;
  for (let i = 0; i < 8; i++) st[i] = rotl32(st[i], sh);
}

function _encryptBlockCore(block, schedule, nr, sc, withFinalWhiten) {
  const st = sc.st;
  for (let i = 0; i < 8; i++) {
    st[i] = ((block[i*4] << 24) | (block[i*4+1] << 16) |
             (block[i*4+2] << 8) | block[i*4+3]) >>> 0;
  }
  for (let r = 0; r < nr; r++) _roundEncrypt(st, schedule.addKeys[r], r, sc);
  if (withFinalWhiten) {
    for (let i = 0; i < 8; i++) st[i] = (st[i] ^ schedule.rkFinal[i]) >>> 0;
  }
  const out = sc.out;
  for (let i = 0; i < 8; i++) {
    out[i*4]   = (st[i] >>> 24) & 0xff;
    out[i*4+1] = (st[i] >>> 16) & 0xff;
    out[i*4+2] = (st[i] >>> 8)  & 0xff;
    out[i*4+3] =  st[i]         & 0xff;
  }
  return out;
}

function _ctrXor(data, key, nonce16) {
  const schedule = _keySchedule(key);
  const sc = _makeScratch();
  const out = new Uint8Array(data.length);
  const ctr = new Uint8Array(32);
  ctr.set(nonce16, 0);
  for (let off = 0; off < data.length; off += BLOCK_BYTES) {
    const ks = _encryptBlockCore(ctr, schedule, ROUNDS, sc, true);
    const n = Math.min(BLOCK_BYTES, data.length - off);
    for (let j = 0; j < n; j++) out[off + j] = data[off + j] ^ ks[j];
    for (let k = 31; k >= 16; k--) {
      ctr[k] = (ctr[k] + 1) & 0xff;
      if (ctr[k] !== 0) break;
    }
  }
  return out;
}

// =============================================================================
// MAC input
// =============================================================================
function _writeU32BE(buf, off, v) {
  buf[off]   = (v >>> 24) & 0xff;
  buf[off+1] = (v >>> 16) & 0xff;
  buf[off+2] = (v >>> 8)  & 0xff;
  buf[off+3] =  v         & 0xff;
}
function _buildMacInput(version, nonce, aad, ct) {
  if (aad.length > CONFIG.MAX_AAD_BYTES) throw new Error('AAD demasiado largo');
  if (ct.length > CONFIG.MAX_CT_BYTES)  throw new Error('CT demasiado largo');
  const total = 1 + NONCE_BYTES + 4 + aad.length + 4 + ct.length;
  const buf = new Uint8Array(total);
  let off = 0;
  buf[off++] = version;
  buf.set(nonce, off); off += NONCE_BYTES;
  _writeU32BE(buf, off, aad.length); off += 4;
  buf.set(aad, off); off += aad.length;
  _writeU32BE(buf, off, ct.length); off += 4;
  buf.set(ct, off);
  return buf;
}

// =============================================================================
// NonceGuard — política operativa de nonces por clave
// =============================================================================
function _hex(buf) {
  let s = '';
  for (let i = 0; i < buf.length; i++) s += buf[i].toString(16).padStart(2, '0');
  return s;
}

class NonceGuard {
  constructor(opts = {}) {
    this.maxMessagesPerKey = opts.maxMessagesPerKey ?? CONFIG.DEFAULT_MAX_MESSAGES_PER_KEY;
    this.maxTrackedNonces  = opts.maxTrackedNonces  ?? CONFIG.DEFAULT_MAX_TRACKED_NONCES;
    this._state = new Map();
  }
  check(key, nonce) {
    const keyHex = _hex(key);
    const nonceHex = _hex(nonce);
    let s = this._state.get(keyHex);
    if (!s) { s = { count: 0, recent: [] }; this._state.set(keyHex, s); }
    if (s.count >= this.maxMessagesPerKey) {
      throw new Error(`Límite operativo alcanzado: ${this.maxMessagesPerKey} mensajes por clave`);
    }
    if (s.recent.includes(nonceHex)) {
      throw new Error('Nonce reutilizado con la misma clave (dentro de la ventana rastreada)');
    }
    s.count++;
    s.recent.push(nonceHex);
    if (s.recent.length > this.maxTrackedNonces) s.recent.shift();
  }
  stats(key) {
    const s = this._state.get(_hex(key));
    return s ? { count: s.count, tracked: s.recent.length } : { count: 0, tracked: 0 };
  }
}

// =============================================================================
// AEAD — encrypt-then-MAC con HMAC-SHA256
// =============================================================================
async function aeadEncrypt(plaintext, key, macKey, opts = {}) {
  const { aad = new Uint8Array(0), nonceGuard, unsafeNoGuard = false } = opts;
  if (key.length !== KEY_BYTES)        throw new Error(`key debe ser ${KEY_BYTES} bytes`);
  if (macKey.length !== MAC_KEY_BYTES) throw new Error(`macKey debe ser ${MAC_KEY_BYTES} bytes`);
  if (!nonceGuard && !unsafeNoGuard) {
    throw new Error('aeadEncrypt requiere nonceGuard o unsafeNoGuard: true');
  }

  const nonce = new Uint8Array(NONCE_BYTES);
  cryptoNode.getRandomValues(nonce);
  if (nonceGuard) nonceGuard.check(key, nonce);

  const ct = _ctrXor(plaintext, key, nonce);
  const macInput = _buildMacInput(VERSION, nonce, aad, ct);
  const ck = await cryptoNode.subtle.importKey(
    'raw', macKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const tag = new Uint8Array(await cryptoNode.subtle.sign('HMAC', ck, macInput));

  const out = new Uint8Array(1 + NONCE_BYTES + ct.length + TAG_BYTES);
  out[0] = VERSION;
  out.set(nonce, 1);
  out.set(ct, 1 + NONCE_BYTES);
  out.set(tag, 1 + NONCE_BYTES + ct.length);
  return out;
}

async function aeadDecrypt(packet, key, macKey, opts = {}) {
  const { aad = new Uint8Array(0) } = opts;
  const minLen = 1 + NONCE_BYTES + TAG_BYTES;
  if (packet.length < minLen) throw new Error('Paquete demasiado corto');
  if (packet[0] !== VERSION)   throw new Error(`Versión desconocida: ${packet[0]}`);

  const nonce = packet.slice(1, 1 + NONCE_BYTES);
  const ct    = packet.slice(1 + NONCE_BYTES, packet.length - TAG_BYTES);
  const tag   = packet.slice(packet.length - TAG_BYTES);

  const macInput = _buildMacInput(VERSION, nonce, aad, ct);
  const ck = await cryptoNode.subtle.importKey(
    'raw', macKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
  );
  if (!await cryptoNode.subtle.verify('HMAC', ck, tag, macInput)) {
    throw new Error('MAC inválido');
  }
  return _ctrXor(ct, key, nonce);
}

// =============================================================================
// Derivación de claves
// =============================================================================
async function deriveAeadKeys(secret, opts = {}) {
  const context = opts.context ?? 'MYSX-256/512';
  const salt    = opts.salt    ?? new Uint8Array(32);

  const ck = await cryptoNode.subtle.importKey(
    'raw', secret, 'HKDF', false, ['deriveBits']
  );
  const enc = new TextEncoder();
  const encKey = new Uint8Array(await cryptoNode.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(context + ':enc') },
    ck, KEY_BYTES * 8
  ));
  const macKey = new Uint8Array(await cryptoNode.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(context + ':mac') },
    ck, MAC_KEY_BYTES * 8
  ));
  return { encKey, macKey };
}

async function deriveAeadKeysFromPassword(password, salt, opts = {}) {
  if (!salt || salt.length < 16) {
    throw new Error('salt obligatoria (≥16 bytes, única por contexto/archivo)');
  }

  let pwBytes;
  if (typeof password === 'string') {
    pwBytes = new TextEncoder().encode(password);
  } else if (password instanceof Uint8Array) {
    pwBytes = password;
  } else if (password instanceof ArrayBuffer) {
    pwBytes = new Uint8Array(password);
  } else {
    throw new Error('password debe ser string, Uint8Array o ArrayBuffer');
  }

  const iterations = opts.iterations ?? CONFIG.PBKDF2_ITERATIONS;
  const context    = opts.context    ?? 'MYSX-256/512';

  const pwKey = await cryptoNode.subtle.importKey(
    'raw', pwBytes, 'PBKDF2', false, ['deriveBits']
  );
  const prk = new Uint8Array(await cryptoNode.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    pwKey, 256
  ));
  return deriveAeadKeys(prk, { context, salt });
}

// =============================================================================
// API pública de producción
// =============================================================================
const PROD = {
  aeadEncrypt,
  aeadDecrypt,
  deriveAeadKeys,
  deriveAeadKeysFromPassword,
  NonceGuard,
  CONFIG
};

// =============================================================================
// TEST API — solo si se pide explícitamente al cargar el módulo
// =============================================================================
const ENABLE_TEST =
  (typeof process !== 'undefined' && process.env && process.env.MYSX_ENABLE_TEST === '1') ||
  (typeof globalThis !== 'undefined' && globalThis.__MYSX_ENABLE_TEST__ === true);

if (ENABLE_TEST) {
  const KNOWN_KAT_DIGEST = '3a8084d0b7df7eb691cfb54494410a5222652c219a336ee58bde48a64524a8b3';

  // UNSAFE: nonce impuesto por el caller. Solo para tests/KAT.
  // En producción, usar aeadEncrypt (nonce interno + NonceGuard).
  async function _unsafeAeadEncryptWithNonce(plaintext, key, macKey, nonce, aad = new Uint8Array(0)) {
    if (key.length !== KEY_BYTES)        throw new Error(`key debe ser ${KEY_BYTES} bytes`);
    if (macKey.length !== MAC_KEY_BYTES) throw new Error(`macKey debe ser ${MAC_KEY_BYTES} bytes`);
    if (nonce.length !== NONCE_BYTES)    throw new Error(`nonce debe ser ${NONCE_BYTES} bytes`);

    const ct = _ctrXor(plaintext, key, nonce);
    const macInput = _buildMacInput(VERSION, nonce, aad, ct);
    const ck = await cryptoNode.subtle.importKey(
      'raw', macKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const tag = new Uint8Array(await cryptoNode.subtle.sign('HMAC', ck, macInput));

    const out = new Uint8Array(1 + NONCE_BYTES + ct.length + TAG_BYTES);
    out[0] = VERSION;
    out.set(nonce, 1);
    out.set(ct, 1 + NONCE_BYTES);
    out.set(tag, 1 + NONCE_BYTES + ct.length);
    return out;
  }

  async function generateKAT() {
    const key = new Uint8Array(KEY_BYTES);
    for (let i = 0; i < KEY_BYTES; i++) key[i] = i;
    const sch = _keySchedule(key);
    const buf = new Uint8Array(16 * 64);
    let off = 0;
    for (let t = 0; t < 16; t++) {
      const pt = new Uint8Array(32);
      for (let i = 0; i < 32; i++) pt[i] = (t * 32 + i) & 0xff;
      const ct = _encryptBlockCore(pt, sch, ROUNDS, _makeScratch(), true).slice();
      buf.set(pt, off); off += 32;
      buf.set(ct, off); off += 32;
    }
    const h = new Uint8Array(await cryptoNode.subtle.digest('SHA-256', buf));
    return Array.from(h).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async function verifyKAT({ strict = true } = {}) {
    const digest = await generateKAT();
    if (KNOWN_KAT_DIGEST === null) {
      if (strict) throw new Error(`KAT no configurado. Digest calculado: ${digest}`);
      console.log(`KAT: NOT_CONFIGURED. Digest calculado: ${digest}`);
      return null;
    }
    const ok = digest === KNOWN_KAT_DIGEST;
    if (!ok && strict) throw new Error(`KAT FAIL. esperado=${KNOWN_KAT_DIGEST} obtenido=${digest}`);
    return ok;
  }

  PROD.TEST = {
    _ctrXor,
    _keySchedule,
    _encryptBlockCore,
    _makeScratch,
    _roundEncrypt,
    _unsafeAeadEncryptWithNonce,
    generateKAT,
    verifyKAT,
    KNOWN_KAT_DIGEST,
    CONFIG
  };
}

module.exports = PROD;
