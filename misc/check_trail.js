'use strict';
process.env.MYSX_ENABLE_TEST = '1';
const MYSX = require('./mysx.prod.js');
const { TEST } = MYSX;
const { _keySchedule, _encryptBlockCore, _makeScratch, CONFIG } = TEST;
const { KEY_BYTES } = CONFIG;

const ROUNDS_REDUCED = 4;

// ΔP: w0 b0  (mismo mapeo que usa el MILP)
const dP = new Uint8Array(32);
dP[0 * 4 + (3 - (0 >> 3))] = (1 << (0 & 7)) & 0xff;

// ΔC esperado (trail MILP): w0b4, w1b10, w1b16, w1b30, w6b4
const dC_expected = new Uint8Array(32);
for (const [w, b] of [[0,4],[1,10],[1,16],[1,30],[6,4]]) {
  dC_expected[w * 4 + (3 - (b >> 3))] |= (1 << (b & 7)) & 0xff;
}

const key = new Uint8Array(KEY_BYTES);
for (let i = 0; i < KEY_BYTES; i++) key[i] = i;
const sch = _keySchedule(key);
const sc = _makeScratch();

let matches = 0, diffWeightSum = 0;
const N = 2000;
for (let t = 0; t < N; t++) {
  const p = new Uint8Array(32);
  for (let i = 0; i < 32; i++) p[i] = (Math.random() * 256) | 0;
  const p2 = new Uint8Array(32);
  for (let i = 0; i < 32; i++) p2[i] = p[i] ^ dP[i];

  const c1 = _encryptBlockCore(p,  sch, ROUNDS_REDUCED, sc, false).slice();
  const c2 = _encryptBlockCore(p2, sch, ROUNDS_REDUCED, sc, false).slice();

  let ok = true, hw = 0;
  for (let i = 0; i < 32; i++) {
    const b = c1[i] ^ c2[i];
    if (b !== dC_expected[i]) ok = false;
    let v = b;
    while (v) { hw += v & 1; v >>>= 1; }
  }
  if (ok) matches++;
  diffWeightSum += hw;
}

console.log(`Trail match rate: ${matches}/${N} (${(matches/N*100).toFixed(2)}%)`);
console.log(`Peso medio ΔC:    ${(diffWeightSum/N).toFixed(2)} bits`);
console.log(matches === N
  ? '→ Prob-1 REAL. El cifrador tiene un distinguidor determinista.'
  : `→ NO es prob-1. Artefacto del modelo. Prob real ≈ 2^-${Math.round(Math.log2(N/Math.max(matches,1)))}`);
