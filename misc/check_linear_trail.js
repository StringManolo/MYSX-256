'use strict';
process.env.MYSX_ENABLE_TEST = '1';
const MYSX = require('./mysx.prod.js');
const { TEST } = MYSX;
const { _keySchedule, _encryptBlockCore, _makeScratch, CONFIG } = TEST;
const { KEY_BYTES } = CONFIG;

const ROUNDS = 4;  // ajustar

// REEMPLAZAR con las máscaras del trail del MILP (salida de --trail)
// Formato: lista de [palabra, bit]
const alpha_bits = [[0, 0]];  // máscara de entrada (ejemplo)
const beta_bits  = [[0, 0]];  // máscara de salida (leer del trail)

function bitsToMask(bits) {
  const m = new Uint8Array(32);
  for (const [w, b] of bits) {
    m[w * 4 + (3 - (b >> 3))] |= (1 << (b & 7)) & 0xff;
  }
  return m;
}

function parity(x) {
  let p = 0;
  for (let i = 0; i < x.length; i++) {
    let v = x[i];
    while (v) { p ^= (v & 1); v >>>= 1; }
  }
  return p;
}

const alpha = bitsToMask(alpha_bits);
const beta  = bitsToMask(beta_bits);

const key = new Uint8Array(KEY_BYTES);
for (let i = 0; i < KEY_BYTES; i++) key[i] = i;
const sch = _keySchedule(key);
const sc = _makeScratch();

let matches = 0;
const N = 100000;
for (let t = 0; t < N; t++) {
  const p = new Uint8Array(32);
  for (let i = 0; i < 32; i++) p[i] = (Math.random() * 256) | 0;
  const c = _encryptBlockCore(p, sch, ROUNDS, sc, false).slice();
  const lhs = parity(alpha.map((v, i) => v & p[i]))
            ^ parity(beta.map((v, i) => v & c[i]));
  if (lhs === 0) matches++;
}

const corr = 2 * (matches / N) - 1;
console.log(`N=${N}, matches=${matches} (${(matches/N*100).toFixed(3)}%)`);
console.log(`Correlación: ${corr.toExponential(3)}`);
if (Math.abs(corr) > 0.01) {
  console.log('→ CORRELACIÓN ALTA. Trail REAL. Cifrador potencialmente roto.');
  console.log(`   Peso empírico ≈ ${Math.round(-Math.log2(Math.abs(corr)))}`);
} else {
  console.log('→ Correlación baja. Probablemente artefacto del modelo.');
}
