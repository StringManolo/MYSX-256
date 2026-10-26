'use strict';
process.env.MYSX_ENABLE_TEST = '1';
const crypto = require('crypto');
const T = require('./mysx.prod.js').TEST;
const sc = T._makeScratch();

function rnd(n) { return new Uint8Array(crypto.randomBytes(n)); }
function enc(pt, sch, r) { return T._encryptBlockCore(pt, sch, r, sc, false).slice(); }

// Convert a sparse diff (list of [word, bit] pairs) to a 32-byte mask
function makeDiff(pairs) {
  const d = new Uint8Array(32);
  for (const [w, b] of pairs) {
    d[w * 4 + (3 - (b >> 3))] |= (1 << (b & 7)) & 0xff;
  }
  return d;
}

function sampleDiff(dIn, r, N) {
  const hist = new Map();
  for (let n = 0; n < N; n++) {
    const key = rnd(64);
    const sch = T._keySchedule(key);
    const p = rnd(32);
    const p2 = new Uint8Array(32);
    for (let i = 0; i < 32; i++) p2[i] = p[i] ^ dIn[i];
    const c = enc(p, sch, r);
    const c2 = enc(p2, sch, r);
    const dC = new Uint8Array(32);
    let hw = 0;
    for (let i = 0; i < 32; i++) {
      dC[i] = c[i] ^ c2[i];
      let v = dC[i]; while (v) { hw += v & 1; v >>>= 1; }
    }
    // Use only the weight as the key (probabilities are per-weight, not per-value)
    hist.set(hw, (hist.get(hw) || 0) + 1);
  }
  return hist;
}

console.log('=== Differential validation at w=32 (multi-bit inputs) ===\n');
console.log('Sampling with N=20000 pairs per (input, rounds). Weights are Hamming weights of ΔC.\n');

// Predictions from paper §3.2 for w0b0 (weight 0 at r=1... up to 18 at r=6)
const predicted = {
  1: 0, 2: 2, 3: 6, 4: 8, 5: 10, 6: 18
};

const inputs = [
  { name: 'w0b0 (single bit)', pairs: [[0, 0]] },
  { name: 'w0b1 (single bit)', pairs: [[0, 1]] },
  { name: 'w0b0+1 (two bits, same word)', pairs: [[0, 0], [0, 1]] },
  { name: 'w0b0 + w4b0 (two bits, L+R)', pairs: [[0, 0], [4, 0]] },
];

const N = 20000;

for (const input of inputs) {
  console.log(`--- ΔIn = ${input.name} ---`);
  const dIn = makeDiff(input.pairs);
  for (const r of [1, 2, 3, 4, 5, 6]) {
    const hist = sampleDiff(dIn, r, N);
    const sorted = [...hist.entries()].sort((a, b) => b[1] - a[1]);
    const [topW, topC] = sorted[0];
    const topProb = topC / N;
    const pred = predicted[r];
    const predProb = Math.pow(2, -pred);
    const ratio = predProb > 0 ? (topProb / predProb) : 'N/A';
    console.log(
      `  r=${r}: top weight = ${topW} (count ${topC}, prob ${topProb.toExponential(2)}), ` +
      `predicted weight = ${pred} (prob ${predProb.toExponential(2)}), ratio = ${ratio}`
    );
  }
  console.log();
}

console.log('=== How to interpret ===\n');
console.log('If ratio ≈ 1: MILP is correct.');
console.log('If ratio > 2: clustering increases the probability (good for attacker).');
console.log('If ratio < 0.5: MILP overestimates (the trail is less likely than predicted).');
console.log('If topProb <= 3/N: no signal, N is too small.');
