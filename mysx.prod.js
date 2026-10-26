'use strict';
// =============================================================================
// MYSX-256/512 — Public API (v0.2-experimental)
// -----------------------------------------------------------------------------
// Experimental cipher. NOT externally audited. DO NOT use for sensitive data.
// For production: AES-256-GCM or XChaCha20-Poly1305.
//
// v0.2 adds a NEW packet format (VERSION 0x02, namespace `v2`):
//   * rotation calendar selected by a header byte (hardcoded tables; no env var)
//   * 512-bit secrets, HKDF-SHA512, 512-bit MAC key, HMAC-SHA512 64-byte tag
//   * one key per message (32-byte random salt), authenticated header
//   * password path: Argon2id (injected, vetted provider) > scrypt > PBKDF2-SHA512
// The v0.1 functions (aeadEncrypt, ...) are kept UNCHANGED for backward
// compatibility (consecutive calendar, HKDF-SHA256, 32-byte tag). They give at
// most 2^128 quantum (Grover) security and are DEPRECATED for new data.
//
// This artifact does NOT expose: raw CTR, caller-imposed nonces, reduced-round
// functions or test utilities (except with MYSX_ENABLE_TEST=1).
// =============================================================================

const cryptoNode =
  (typeof globalThis !== 'undefined' && globalThis.crypto)
    ? globalThis.crypto
    : (typeof require !== 'undefined' ? require('crypto').webcrypto : null);
if (!cryptoNode) throw new Error('WebCrypto not available');

const nodeCrypto =
  (typeof require !== 'undefined') ? require('crypto') : null;

// ===== Parameters =====
const CONFIG = Object.freeze({
  BLOCK_BYTES: 32,
  KEY_BYTES: 64,
  ROUNDS: 128,
  NONCE_BYTES: 16,
  MAC_KEY_BYTES: 32,          // v1 only
  TAG_BYTES: 32,              // v1 only
  VERSION: 0x01,              // v1 packets
  VERSION_V2: 0x02,
  MAX_AAD_BYTES: 0x7fffffff,
  MAX_CT_BYTES: 0x7fffffff,
  MAX_PLAINTEXT_BYTES: 0x7fffffff,
  DEFAULT_MAX_MESSAGES_PER_KEY: 2 ** 32,
  DEFAULT_MAX_TRACKED_NONCES: 1024,
  DEFAULT_MAX_TRACKED_KEYS: 1024,
  DEFAULT_SAVE_EVERY: 100,
  PBKDF2_ITERATIONS: 600000   // v1 password path
});

const {
  BLOCK_BYTES, KEY_BYTES, ROUNDS, NONCE_BYTES, MAC_KEY_BYTES, TAG_BYTES, VERSION
} = CONFIG;

// =============================================================================
// Rotation calendars (HARDCODED, selected per packet by the CAL header byte)
// -----------------------------------------------------------------------------
// id 0: consecutive (r mod 31)+1  == v0.1 behaviour (byte-identical).
// id 1: v0.2 calendar. Paste it with:  node set_calendar.js CALENDAR_v02.txt
//       (rewrites the three lines between the markers; validates the permutation).
// A calendar is a permutation of 1..31; round r uses table[r % 31].
// =============================================================================
const CAL_CONSECUTIVE = Object.freeze(Array.from({ length: 31 }, (_, i) => i + 1));
// >>> V02_CALENDAR
const V02_CALENDAR = Object.freeze([22,5,8,7,17,10,30,1,11,26,6,3,12,23,25,13,28,20,21,19,24,2,18,9,4,15,29,27,16,14,31]);
// <<< V02_CALENDAR
function _validCalendar(t) {
  if (!Array.isArray(t) || t.length !== 31) return false;
  const s = [...t].sort((a, b) => a - b);
  for (let i = 0; i < 31; i++) if (s[i] !== i + 1) return false;
  return true;
}
if (V02_CALENDAR !== null && !_validCalendar(V02_CALENDAR)) {
  throw new Error('V02_CALENDAR is not a permutation of 1..31');
}
const CAL = Object.freeze({ CONSECUTIVE_V1: 0, V02: 1 });
const CAL_TABLES = Object.freeze({ 0: CAL_CONSECUTIVE, 1: V02_CALENDAR });
function _calTable(id) {
  const t = CAL_TABLES[id];
  if (!t) {
    throw new Error(id === CAL.V02
      ? 'MYSX v2: v0.2 calendar not configured (run: node set_calendar.js CALENDAR_v02.txt)'
      : 'MYSX v2: unknown calendar id');
  }
  return t;
}

// =============================================================================
// Cipher internals (not exported in PROD)
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
  if (keyBytes.length !== KEY_BYTES) throw new Error(`Key must be ${KEY_BYTES} bytes`);
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

function _roundEncrypt(st, rk, r, sc, table) {
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
  const sh = table[r % 31] | 0;
  for (let i = 0; i < 8; i++) st[i] = rotl32(st[i], sh);
}

function _encryptBlockCore(block, schedule, nr, sc, withFinalWhiten, table = CAL_CONSECUTIVE) {
  const st = sc.st;
  for (let i = 0; i < 8; i++) {
    st[i] = ((block[i*4] << 24) | (block[i*4+1] << 16) |
             (block[i*4+2] << 8) | block[i*4+3]) >>> 0;
  }
  for (let r = 0; r < nr; r++) _roundEncrypt(st, schedule.addKeys[r], r, sc, table);
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

function _ctrXor(data, key, nonce16, table = CAL_CONSECUTIVE) {
  const schedule = _keySchedule(key);
  const sc = _makeScratch();
  const out = new Uint8Array(data.length);
  const ctr = new Uint8Array(32);
  ctr.set(nonce16, 0);
  for (let off = 0; off < data.length; off += BLOCK_BYTES) {
    const ks = _encryptBlockCore(ctr, schedule, ROUNDS, sc, true, table);
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
// Type validation helpers
// =============================================================================
function _requireBytes(name, value, expectedLen) {
  if (!(value instanceof Uint8Array)) {
    throw new Error(`${name} must be a Uint8Array`);
  }
  if (expectedLen !== undefined && value.length !== expectedLen) {
    throw new Error(`${name} must be ${expectedLen} bytes`);
  }
}

// =============================================================================
// v1 MAC input
// =============================================================================
function _writeU32BE(buf, off, v) {
  buf[off]   = (v >>> 24) & 0xff;
  buf[off+1] = (v >>> 16) & 0xff;
  buf[off+2] = (v >>> 8)  & 0xff;
  buf[off+3] =  v         & 0xff;
}
function _buildMacInput(version, nonce, aad, ct) {
  if (aad.length > CONFIG.MAX_AAD_BYTES) throw new Error('AAD too long');
  if (ct.length > CONFIG.MAX_CT_BYTES)  throw new Error('CT too long');
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
// NonceGuard — best-effort nonce policy (v1 only; v2 uses one key per message)
// =============================================================================
function _keyId(key) {
  let h1 = 0x811c9dc5 >>> 0;
  let h2 = 0x84222325 >>> 0;
  for (let i = 0; i < key.length; i++) {
    const b = key[i];
    h1 ^= b;
    h1 = Math.imul(h1, 0x01000193) >>> 0;
    h2 ^= (b + i) & 0xff;
    h2 = Math.imul(h2, 0x85ebca6b) >>> 0;
  }
  return h1.toString(16).padStart(8, '0') + h2.toString(16).padStart(8, '0');
}

function _hex(buf) {
  let s = '';
  for (let i = 0; i < buf.length; i++) s += buf[i].toString(16).padStart(2, '0');
  return s;
}

class NonceGuard {
  constructor(opts = {}) {
    this.maxMessagesPerKey = opts.maxMessagesPerKey ?? CONFIG.DEFAULT_MAX_MESSAGES_PER_KEY;
    this.maxTrackedNonces  = opts.maxTrackedNonces  ?? CONFIG.DEFAULT_MAX_TRACKED_NONCES;
    this.maxTrackedKeys    = opts.maxTrackedKeys    ?? CONFIG.DEFAULT_MAX_TRACKED_KEYS;
    this.saveEvery         = opts.saveEvery         ?? CONFIG.DEFAULT_SAVE_EVERY;
    this.onSave            = opts.onSave            ?? null;
    this._state = new Map();
    this._sinceSave = 0;
    if (opts.initialState) this._loadState(opts.initialState);
  }
  check(key, nonce) {
    const keyId = _keyId(key);
    const nonceHex = _hex(nonce);
    let s = this._state.get(keyId);
    if (s) {
      this._state.delete(keyId);
      this._state.set(keyId, s);
    } else {
      if (this._state.size >= this.maxTrackedKeys) {
        const oldest = this._state.keys().next().value;
        this._state.delete(oldest);
      }
      s = { count: 0, recent: [] };
      this._state.set(keyId, s);
    }
    if (s.count >= this.maxMessagesPerKey) {
      throw new Error(`Operational limit reached: ${this.maxMessagesPerKey} messages per key`);
    }
    if (s.recent.includes(nonceHex)) {
      throw new Error('Nonce reused with the same key (within tracked window)');
    }
    s.count++;
    s.recent.push(nonceHex);
    if (s.recent.length > this.maxTrackedNonces) s.recent.shift();
    this._sinceSave++;
    if (this.onSave && this._sinceSave >= this.saveEvery) {
      this._sinceSave = 0;
      this.onSave(this._exportState());
    }
  }
  stats(key) {
    const s = this._state.get(_keyId(key));
    return s ? { count: s.count, tracked: s.recent.length } : { count: 0, tracked: 0 };
  }
  _exportState() {
    const out = {};
    for (const [k, v] of this._state) out[k] = { count: v.count, recent: v.recent.slice() };
    return out;
  }
  _loadState(state) {
    this._state.clear();
    for (const [k, v] of Object.entries(state)) {
      this._state.set(k, { count: v.count, recent: v.recent.slice() });
    }
  }
  save() { return this._exportState(); }
  load(state) { this._loadState(state); }
}

// =============================================================================
// v1 AEAD (DEPRECATED for new data: <= 2^128 quantum security)
// =============================================================================
async function aeadEncrypt(plaintext, key, macKey, opts = {}) {
  const { aad = new Uint8Array(0), nonceGuard, unsafeNoGuard = false } = opts;
  _requireBytes('plaintext', plaintext);
  _requireBytes('key', key, KEY_BYTES);
  _requireBytes('macKey', macKey, MAC_KEY_BYTES);
  _requireBytes('aad', aad);
  if (plaintext.length > CONFIG.MAX_PLAINTEXT_BYTES) {
    throw new Error(`plaintext too long (max ${CONFIG.MAX_PLAINTEXT_BYTES} bytes)`);
  }
  if (!nonceGuard && !unsafeNoGuard) {
    throw new Error('aeadEncrypt requires nonceGuard or unsafeNoGuard: true');
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
  _requireBytes('packet', packet);
  _requireBytes('key', key, KEY_BYTES);
  _requireBytes('macKey', macKey, MAC_KEY_BYTES);
  _requireBytes('aad', aad);
  const minLen = 1 + NONCE_BYTES + TAG_BYTES;
  if (packet.length < minLen) throw new Error('Packet too short');
  if (packet[0] !== VERSION)   throw new Error(`Unknown version: ${packet[0]}`);

  const nonce = packet.slice(1, 1 + NONCE_BYTES);
  const ct    = packet.slice(1 + NONCE_BYTES, packet.length - TAG_BYTES);
  const tag   = packet.slice(packet.length - TAG_BYTES);

  const macInput = _buildMacInput(VERSION, nonce, aad, ct);
  const ck = await cryptoNode.subtle.importKey(
    'raw', macKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
  );
  if (!await cryptoNode.subtle.verify('HMAC', ck, tag, macInput)) {
    throw new Error('Invalid MAC');
  }
  return _ctrXor(ct, key, nonce);
}

async function deriveAeadKeys(secret, opts = {}) {
  _requireBytes('secret', secret);
  const context = opts.context ?? 'MYSX-256/512';
  const salt    = opts.salt    ?? new Uint8Array(32);
  _requireBytes('salt', salt);

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
    throw new Error('salt required (>= 16 bytes, unique per context/file)');
  }
  _requireBytes('salt', salt);
  let pwBytes;
  if (typeof password === 'string') {
    pwBytes = new TextEncoder().encode(password);
  } else if (password instanceof Uint8Array) {
    pwBytes = password;
  } else if (password instanceof ArrayBuffer) {
    pwBytes = new Uint8Array(password);
  } else {
    throw new Error('password must be string, Uint8Array or ArrayBuffer');
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
// v2 — 512-bit keys, one key per message, authenticated header
// -----------------------------------------------------------------------------
// Packet:  VERSION(1)=2 | CAL(1) | KDF(1) | KDF_PARAMS(var) | SALT(32) | NONCE(16)
//          | CT(n) | TAG(64)
// ikm      = secret                                   (KDF 0: 64 B for 2^256 Grover)
//          = lp(PasswordKDF(NFKC(pw), SALT)) | lp(keyfile)   (KDF 1,2,3)
// PRK      = HKDF-Extract-SHA512(salt = SALT, ikm)
// info     = lp("MYSX-256/512 v2") | CAL | KDF | lp(context) | lp(label)
// encKey   = HKDF-Expand(PRK, info(label="enc"), 64);  macKey likewise ("mac", 64)
// TAG      = HMAC-SHA512(macKey, HEADER | u64(|AAD|) | AAD | u64(|CT|) | CT)
// =============================================================================
const KDF2 = Object.freeze({ RAW: 0, ARGON2ID: 1, PBKDF2_SHA512: 2, SCRYPT: 3 });
const V2 = Object.freeze({ SALT: 32, NONCE: 16, TAG: 64, KEY: 64 });
const V2_LIMITS = Object.freeze({
  argon2: { memKiB: [19456, 1048576], passes: [2, 16], lanes: [1, 16] },
  pbkdf2: { iterations: [210000, 10000000] },
  scrypt: { logN: [15, 20], r: [8, 16], p: [1, 16], maxBytes: 2 ** 30 }
});
const V2_DEFAULTS = Object.freeze({
  argon2: { memKiB: 65536, passes: 3, lanes: 4 },     // RFC 9106, second recommended option
  pbkdf2: { iterations: 600000 },
  scrypt: { logN: 17, r: 8, p: 1 }                    // 128 MiB
});

const _fail = (m) => { throw new Error('MYSX v2: ' + m); };
function _concat(...arrs) {
  let n = 0; for (const a of arrs) n += a.length;
  const o = new Uint8Array(n); let p = 0;
  for (const a of arrs) { o.set(a, p); p += a.length; }
  return o;
}
function _u16(n) { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n); return b; }
function _u64(n) { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return b; }
function _lp(x) {
  if (x.length > 0xffff) _fail('field too long');
  return _concat(_u16(x.length), x);
}
const _utf8 = (s) => new TextEncoder().encode(s);
function _inRange(v, [lo, hi]) { return Number.isInteger(v) && v >= lo && v <= hi; }

let _argon2Provider = null;
/**
 * Register a vetted Argon2id implementation. Signature:
 *   fn({ password: Uint8Array, salt: Uint8Array, memKiB, passes, lanes, dkLen }) -> Uint8Array | Promise<Uint8Array>
 * Recommended: @noble/hashes (pure JS, zero dependencies, runs in Node and browsers):
 *   const { argon2idAsync } = await import('@noble/hashes/argon2.js');
 *   mysx.v2.setArgon2Provider(mysx.v2.argon2FromNoble(argon2idAsync));
 * Check that the library's audit scope covers argon2 and that it passes the
 * RFC 9106 vectors in your CI before trusting it.
 */
function setArgon2Provider(fn) {
  if (fn !== null && typeof fn !== 'function') throw new Error('provider must be a function or null');
  _argon2Provider = fn;
}
function argon2FromNoble(argon2idAsync) {
  return ({ password, salt, memKiB, passes, lanes, dkLen }) =>
    argon2idAsync(password, salt, { t: passes, m: memKiB, p: lanes, dkLen, maxmem: 2 ** 32 - 1 });
}

function _v2BuildHeader({ cal, kdf, kdfParams, salt, nonce }) {
  if (!(cal in CAL_TABLES)) _fail('unknown calendar');
  if (!Object.values(KDF2).includes(kdf)) _fail('unknown kdf');
  if (salt.length !== V2.SALT || nonce.length !== V2.NONCE) _fail('salt/nonce length');
  const parts = [new Uint8Array([CONFIG.VERSION_V2, cal, kdf])];
  if (kdf === KDF2.ARGON2ID) {
    const b = new Uint8Array(6); const dv = new DataView(b.buffer);
    dv.setUint32(0, kdfParams.memKiB); b[4] = kdfParams.passes; b[5] = kdfParams.lanes; parts.push(b);
  } else if (kdf === KDF2.PBKDF2_SHA512) {
    const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, kdfParams.iterations); parts.push(b);
  } else if (kdf === KDF2.SCRYPT) {
    parts.push(new Uint8Array([kdfParams.logN, kdfParams.r, kdfParams.p]));
  }
  parts.push(salt, nonce);
  return _concat(...parts);
}

function _v2ParseHeader(buf) {
  if (buf.length < 3 + V2.SALT + V2.NONCE + V2.TAG) _fail('packet truncated');
  let o = 0;
  const version = buf[o++], cal = buf[o++], kdf = buf[o++];
  if (version !== CONFIG.VERSION_V2) _fail('unsupported version');
  if (!(cal in CAL_TABLES)) _fail('unknown calendar');
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let kdfParams = null;
  if (kdf === KDF2.RAW) {
    // no params
  } else if (kdf === KDF2.ARGON2ID) {
    if (buf.length < o + 6) _fail('packet truncated');
    kdfParams = { memKiB: dv.getUint32(o), passes: buf[o + 4], lanes: buf[o + 5] }; o += 6;
    const L = V2_LIMITS.argon2;
    if (!_inRange(kdfParams.memKiB, L.memKiB) || !_inRange(kdfParams.passes, L.passes) ||
        !_inRange(kdfParams.lanes, L.lanes)) _fail('Argon2 parameters out of bounds');
  } else if (kdf === KDF2.PBKDF2_SHA512) {
    if (buf.length < o + 4) _fail('packet truncated');
    kdfParams = { iterations: dv.getUint32(o) }; o += 4;
    if (!_inRange(kdfParams.iterations, V2_LIMITS.pbkdf2.iterations)) _fail('PBKDF2 iterations out of bounds');
  } else if (kdf === KDF2.SCRYPT) {
    if (buf.length < o + 3) _fail('packet truncated');
    kdfParams = { logN: buf[o], r: buf[o + 1], p: buf[o + 2] }; o += 3;
    const L = V2_LIMITS.scrypt;
    if (!_inRange(kdfParams.logN, L.logN) || !_inRange(kdfParams.r, L.r) || !_inRange(kdfParams.p, L.p) ||
        128 * (2 ** kdfParams.logN) * kdfParams.r > L.maxBytes) _fail('scrypt parameters out of bounds');
  } else _fail('unknown kdf');
  if (buf.length < o + V2.SALT + V2.NONCE + V2.TAG) _fail('packet truncated');
  const salt = buf.slice(o, o + V2.SALT); o += V2.SALT;
  const nonce = buf.slice(o, o + V2.NONCE); o += V2.NONCE;
  return { version, cal, kdf, kdfParams, salt, nonce, headerLen: o };
}

function _v2Info(cal, kdf, context, label) {
  return _concat(_lp(_utf8('MYSX-256/512 v2')), new Uint8Array([cal, kdf]), _lp(_utf8(context)), _lp(_utf8(label)));
}

async function _v2DeriveKeys(ikm, salt, cal, kdf, context) {
  const ck = await cryptoNode.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const mk = async (label) => new Uint8Array(await cryptoNode.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-512', salt, info: _v2Info(cal, kdf, context, label) }, ck, V2.KEY * 8));
  return { encKey: await mk('enc'), macKey: await mk('mac') };
}

function _pwBytes(password) {
  if (typeof password === 'string') return _utf8(password.normalize('NFKC'));
  if (password instanceof Uint8Array) return password;
  _fail('password must be string or Uint8Array');
}

async function _passwordKdf(kdf, kdfParams, pw, salt, opts) {
  if (kdf === KDF2.ARGON2ID) {
    const args = { password: pw, salt, memKiB: kdfParams.memKiB, passes: kdfParams.passes,
                   lanes: kdfParams.lanes, dkLen: 64 };
    const prov = opts.argon2Provider ?? _argon2Provider;
    let out;
    if (prov) out = await prov(args);
    else if (opts.allowNativeArgon2 && nodeCrypto && typeof nodeCrypto.argon2Sync === 'function') {
      // Node >= 24.7, documented as experimental: explicit opt-in only.
      out = nodeCrypto.argon2Sync('argon2id', { message: pw, nonce: salt, parallelism: args.lanes,
        tagLength: 64, memory: args.memKiB, passes: args.passes });
    } else _fail('Argon2id needs a registered provider (setArgon2Provider) or allowNativeArgon2');
    if (!(out instanceof Uint8Array) && !(out instanceof ArrayBuffer)) _fail('Argon2 provider returned a non-byte value');
    out = new Uint8Array(out);
    if (out.length !== 64) _fail('Argon2 provider returned the wrong length');
    return out;
  }
  if (kdf === KDF2.PBKDF2_SHA512) {
    const k = await cryptoNode.subtle.importKey('raw', pw, 'PBKDF2', false, ['deriveBits']);
    return new Uint8Array(await cryptoNode.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: kdfParams.iterations, hash: 'SHA-512' }, k, 512));
  }
  if (kdf === KDF2.SCRYPT) {
    if (!nodeCrypto || typeof nodeCrypto.scrypt !== 'function') _fail('scrypt is only available in Node');
    const N = 2 ** kdfParams.logN;
    return new Uint8Array(await new Promise((res, rej) => nodeCrypto.scrypt(pw, salt, 64,
      { N, r: kdfParams.r, p: kdfParams.p, maxmem: 160 * N * kdfParams.r + (1 << 20) },
      (e, k) => e ? rej(e) : res(k))));
  }
  _fail('invalid password kdf');
}

async function _v2Ikm(kdf, kdfParams, salt, creds, opts) {
  if (kdf === KDF2.RAW) {
    const s = creds.secret;
    if (!(s instanceof Uint8Array)) _fail('creds.secret must be a Uint8Array');
    if (s.length !== 64 && s.length !== 32) _fail('secret must be 64 bytes (2^256 Grover) or 32 bytes (2^128 Grover)');
    return s;
  }
  if (creds.password == null) _fail('creds.password required');
  const out = await _passwordKdf(kdf, kdfParams, _pwBytes(creds.password), salt, opts);
  const kf = creds.keyfile == null ? new Uint8Array(0) : creds.keyfile;
  if (!(kf instanceof Uint8Array)) _fail('creds.keyfile must be a Uint8Array');
  return _concat(_lp(out), _lp(kf));
}

async function _v2Mac(macKey, header, aad, ct, usage) {
  const k = await cryptoNode.subtle.importKey('raw', macKey, { name: 'HMAC', hash: 'SHA-512' }, false, [usage]);
  return _concat(header, _u64(aad.length), aad, _u64(ct.length), ct);
}

function _chooseKdf(creds, opts) {
  if (creds.secret != null) return KDF2.RAW;
  if (opts.kdf != null) return opts.kdf;
  if (opts.argon2Provider || _argon2Provider ||
      (opts.allowNativeArgon2 && nodeCrypto && typeof nodeCrypto.argon2Sync === 'function')) return KDF2.ARGON2ID;
  if (nodeCrypto && typeof nodeCrypto.scrypt === 'function') return KDF2.SCRYPT;
  if (opts.allowPbkdf2) return KDF2.PBKDF2_SHA512;
  _fail('no memory-hard KDF available (register an Argon2 provider, use Node for scrypt, or pass allowPbkdf2: true)');
}

/**
 * Seal. creds: { secret } (64 B recommended) | { password, keyfile? }.
 * opts: { aad, context, cal, kdf, kdfParams, argon2Provider, allowNativeArgon2, allowPbkdf2 }
 */
async function v2Seal(plaintext, creds, opts = {}) {
  _requireBytes('plaintext', plaintext);
  if (plaintext.length > CONFIG.MAX_PLAINTEXT_BYTES) _fail('plaintext too long');
  const aad = opts.aad ?? new Uint8Array(0); _requireBytes('aad', aad);
  const cal = opts.cal ?? CAL.V02;
  const table = _calTable(cal);
  const kdf = _chooseKdf(creds, opts);
  const kdfParams = opts.kdfParams ??
    (kdf === KDF2.ARGON2ID ? V2_DEFAULTS.argon2 : kdf === KDF2.PBKDF2_SHA512 ? V2_DEFAULTS.pbkdf2
      : kdf === KDF2.SCRYPT ? V2_DEFAULTS.scrypt : null);
  const salt = opts._salt ?? cryptoNode.getRandomValues(new Uint8Array(V2.SALT));
  const nonce = opts._nonce ?? cryptoNode.getRandomValues(new Uint8Array(V2.NONCE));
  const header = _v2BuildHeader({ cal, kdf, kdfParams, salt, nonce });
  _v2ParseHeader(_concat(header, new Uint8Array(V2.TAG)));      // same limits as the receiver
  const ikm = await _v2Ikm(kdf, kdfParams, salt, creds, opts);
  const { encKey, macKey } = await _v2DeriveKeys(ikm, salt, cal, kdf, opts.context ?? '');
  const ct = _ctrXor(plaintext, encKey, nonce, table);
  const macInput = await _v2Mac(macKey, header, aad, ct, 'sign');
  const k = await cryptoNode.subtle.importKey('raw', macKey, { name: 'HMAC', hash: 'SHA-512' }, false, ['sign']);
  const tag = new Uint8Array(await cryptoNode.subtle.sign('HMAC', k, macInput));
  return _concat(header, ct, tag);
}

async function v2Open(packet, creds, opts = {}) {
  _requireBytes('packet', packet);
  const aad = opts.aad ?? new Uint8Array(0); _requireBytes('aad', aad);
  const h = _v2ParseHeader(packet);
  if (opts.expectKdf != null && h.kdf !== opts.expectKdf) _fail('authentication failed');
  const table = _calTable(h.cal);
  const header = packet.subarray(0, h.headerLen);
  const ct = packet.subarray(h.headerLen, packet.length - V2.TAG);
  const tag = packet.subarray(packet.length - V2.TAG);
  const ikm = await _v2Ikm(h.kdf, h.kdfParams, h.salt, creds, opts);
  const { encKey, macKey } = await _v2DeriveKeys(ikm, h.salt, h.cal, h.kdf, opts.context ?? '');
  const macInput = await _v2Mac(macKey, header, aad, ct, 'verify');
  const k = await cryptoNode.subtle.importKey('raw', macKey, { name: 'HMAC', hash: 'SHA-512' }, false, ['verify']);
  if (!await cryptoNode.subtle.verify('HMAC', k, tag, macInput)) _fail('authentication failed');
  return _ctrXor(ct, encKey, h.nonce, table);
}

function generateSecret() { return cryptoNode.getRandomValues(new Uint8Array(64)); }

/** Declared (nominal) key-recovery security of the key layer, classical and Grover. */
function securityLevel(creds) {
  if (creds.secret != null) {
    const bits = Math.min(8 * creds.secret.length, 512);
    return { classicalBits: bits, groverBits: bits / 2,
      note: bits === 512 ? 'nominal 2^256 (Grover) for ONE target; 2^256/sqrt(N) if an attacker needs only ONE of N messages'
                         : '256-bit secret: 2^128 (Grover)' };
  }
  const kf = creds.keyfile == null ? 0 : creds.keyfile.length;
  if (kf >= 64) return { classicalBits: 512, groverBits: 256, note: 'nominal 2^256 thanks to the >=64-byte keyfile' };
  return { classicalBits: null, groverBits: null, note: 'limited by password entropy; no 2^256 without a >=64-byte random keyfile' };
}

// =============================================================================
// Public API
// =============================================================================
const PROD = {
  // v1 (deprecated for new data)
  aeadEncrypt,
  aeadDecrypt,
  deriveAeadKeys,
  deriveAeadKeysFromPassword,
  NonceGuard,
  CONFIG,
  // v2
  v2: { seal: v2Seal, open: v2Open, generateSecret, securityLevel, setArgon2Provider, argon2FromNoble,
        CAL, KDF: KDF2, DEFAULTS: V2_DEFAULTS, LIMITS: V2_LIMITS }
};

// =============================================================================
// TEST API — disabled by default (env var only)
// =============================================================================
const ENABLE_TEST =
  (typeof process !== 'undefined' && process.env && process.env.MYSX_ENABLE_TEST === '1');

if (ENABLE_TEST) {
  const KNOWN_KAT_DIGEST = '3a8084d0b7df7eb691cfb54494410a5222652c219a336ee58bde48a64524a8b3';

  async function _unsafeAeadEncryptWithNonce(plaintext, key, macKey, nonce, aad = new Uint8Array(0)) {
    _requireBytes('plaintext', plaintext);
    _requireBytes('key', key, KEY_BYTES);
    _requireBytes('macKey', macKey, MAC_KEY_BYTES);
    _requireBytes('nonce', nonce, NONCE_BYTES);
    _requireBytes('aad', aad);
    if (plaintext.length > CONFIG.MAX_PLAINTEXT_BYTES) {
      throw new Error(`plaintext too long (max ${CONFIG.MAX_PLAINTEXT_BYTES} bytes)`);
    }
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

  // cal: calendar id (0 = consecutive, original KAT) or an explicit 31-entry table for analysis
  async function generateKAT(cal = 0) {
    const table = Array.isArray(cal) ? cal : _calTable(cal);
    const key = new Uint8Array(KEY_BYTES);
    for (let i = 0; i < KEY_BYTES; i++) key[i] = i;
    const sch = _keySchedule(key);
    const buf = new Uint8Array(16 * 64);
    let off = 0;
    for (let t = 0; t < 16; t++) {
      const pt = new Uint8Array(32);
      for (let i = 0; i < 32; i++) pt[i] = (t * 32 + i) & 0xff;
      const ct = _encryptBlockCore(pt, sch, ROUNDS, _makeScratch(), true, table).slice();
      buf.set(pt, off); off += 32;
      buf.set(ct, off); off += 32;
    }
    const h = new Uint8Array(await cryptoNode.subtle.digest('SHA-256', buf));
    return Array.from(h).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async function verifyKAT({ strict = true } = {}) {
    const digest = await generateKAT(0);
    const ok = digest === KNOWN_KAT_DIGEST;
    if (!ok && strict) throw new Error(`KAT FAIL. expected=${KNOWN_KAT_DIGEST} got=${digest}`);
    return ok;
  }

  PROD.TEST = {
    _ctrXor,
    _keySchedule,
    _encryptBlockCore,
    _makeScratch,
    _roundEncrypt,
    _unsafeAeadEncryptWithNonce,
    _v2: { buildHeader: _v2BuildHeader, parseHeader: _v2ParseHeader, deriveKeys: _v2DeriveKeys,
           ikm: _v2Ikm, passwordKdf: _passwordKdf, info: _v2Info },
    CAL_TABLES,
    generateKAT,
    verifyKAT,
    KNOWN_KAT_DIGEST,
    CONFIG
  };
}

module.exports = PROD;