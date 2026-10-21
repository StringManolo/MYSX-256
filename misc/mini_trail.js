'use strict';
// =============================================================================
// mini_trail.js — Differential and linear trail verification in mini-MYSX
// -----------------------------------------------------------------------------
// At w=8, the state is 64 bits and we can sample N=2^20 pairs per round.
// This verifies whether the trails predicted by the MILP (at w=32) also
// appear at w=8 with the same weight (probability 2^-weight).
//
// Differential: fix ΔP = single bit at word 0, bit 0. Sample N pairs with
// random round keys. Report top ΔC frequency, compare to 2^-predictedWeight.
//
// Linear: fix α = single bit at word 0, bit 0. Test all 64 single-bit β masks.
// Report max |corr|, compare to 2^-predictedWeight.
// =============================================================================
const { makeMini } = require('./mini');

function singleBitMask(bit) {
  const mask = new Array(8).fill(0);
  mask[bit >> 3] = 1 << (bit & 7);
  return mask;
}

function sampleDiff(m, nr, dP, N) {
  const hist = new Map();
  for (let n = 0; n < N; n++) {
    const rks = Array.from({ length: nr }, () => m.randState());
    const P = m.randState();
    const P2 = P.map((x, i) => x ^ dP[i]);
    const C  = m.encrypt(P,  rks, nr);
    const C2 = m.encrypt(P2, rks, nr);
    const dC = C.map((x, i) => (x ^ C2[i]) & m.M);
    const key = dC.join(',');
    hist.set(key, (hist.get(key) || 0) + 1);
  }
  return hist;
}

function parity(x) {
  let p = 0;
  while (x) { p ^= (x & 1); x >>>= 1; }
  return p;
}

function sampleLinear(m, nr, alpha, beta, N) {
  let sum = 0;
  for (let n = 0; n < N; n++) {
    const rks = Array.from({ length: nr }, () => m.randState());
    const P = m.randState();
    const C = m.encrypt(P, rks, nr);
    let pa = 0, pb = 0;
    for (let i = 0; i < 8; i++) {
      pa ^= parity(alpha[i] & P[i]);
      pb ^= parity(beta[i]  & C[i]);
    }
    sum += (pa ^ pb) ? -1 : 1;
  }
  return Math.abs(sum) / N;
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------
const w = 8, a = 1, b = 4, c = 2;
const m = makeMini(w, a, b, c, 'MYSZKOWS', 0xC0FFEE);

const N_diff = 1 << 20;
const N_lin  = 1 << 20;

console.log(`Mini-MYSX w=${w}, (a,b,c)=(${a},${b},${c}), N=${N_diff}\n`);

// Predicted weights from PAPER.md §3.2 (differential, w0b0)
const predictedDiff = { 1: 0, 2: 2, 3: 6, 4: 8, 5: 10, 6: 18 };
// Predicted weights from PAPER.md §4.1.1 (linear, hybrid model, w0b0)
const predictedLin  = { 1: 0, 2: 2, 3: 6, 4: 8,  5: 10 };

// -----------------------------------------------------------------------------
// Differential sampling
// -----------------------------------------------------------------------------
console.log('=== Differential ===');
const dP = singleBitMask(0);
console.log(`ΔP = [${dP.map(x => '0x' + x.toString(16)).join(',')}]`);

for (const nr of [1, 2, 3, 4, 5, 6]) {
  const t0 = Date.now();
  const hist = sampleDiff(m, nr, dP, N_diff);
  const sorted = [...hist.entries()].sort((a, b) => b[1] - a[1]);
  const [topKey, topCount] = sorted[0];
  const topProb = topCount / N_diff;
  const pred = predictedDiff[nr];
  const predProb = Math.pow(2, -pred);

  const observedW = topProb > 0 ? -Math.log2(topProb) : Infinity;
  console.log(`r=${nr}: ${sorted.length} unique ΔC, top prob = ${topProb.toExponential(2)} = 2^-${observedW.toFixed(2)}`);
  console.log(`  MILP predicted weight: ${pred} (prob 2^-${pred} = ${predProb.toExponential(2)})`);
  console.log(`  observed/predicted: ${(topProb / predProb).toFixed(2)}x`);
  if (topCount <= 3) {
    console.log(`  --> no signal (top count ≤ 3, consistent with noise)`);
  } else if (topProb > predProb * 2) {
    console.log(`  --> observed > 2x predicted: clustering or better trail`);
  } else if (topProb < predProb / 2) {
    console.log(`  --> observed < 1/2 predicted: model overestimates or trail absent`);
  } else {
    console.log(`  --> consistent with model`);
  }
  console.log(`  time: ${((Date.now() - t0) / 1000).toFixed(1)}s\n`);
}

// -----------------------------------------------------------------------------
// Linear sampling: fix α = word 0 bit 0, test all 64 single-bit β
// -----------------------------------------------------------------------------
console.log('=== Linear ===');
const alpha = singleBitMask(0);
console.log(`α = [${alpha.map(x => '0x' + x.toString(16)).join(',')}]`);
console.log(`Sweeping 64 single-bit β masks.\n`);

for (const nr of [1, 2, 3, 4, 5]) {
  const t0 = Date.now();
  let bestBeta = -1, bestCorr = 0;
  const all = [];
  for (let bit = 0; bit < 64; bit++) {
    const beta = singleBitMask(bit);
    const corr = sampleLinear(m, nr, alpha, beta, N_lin);
    all.push({ bit, corr });
    if (corr > bestCorr) { bestCorr = corr; bestBeta = bit; }
  }
  const pred = predictedLin[nr];
  const predCorr = Math.pow(2, -pred);
  const observedW = bestCorr > 0 ? -Math.log2(bestCorr) : Infinity;
  const sigma = 1 / Math.sqrt(N_lin);

  console.log(`r=${nr}: best corr = ${bestCorr.toExponential(2)} = 2^-${observedW.toFixed(2)} (β = bit ${bestBeta})`);
  console.log(`  MILP predicted weight: ${pred} (corr 2^-${pred} = ${predCorr.toExponential(2)})`);
  console.log(`  observed/predicted: ${(bestCorr / predCorr).toFixed(2)}x`);
  console.log(`  σ (noise) = ${sigma.toExponential(2)}, threshold for 3σ = ${(3 * sigma).toExponential(2)}`);
  console.log(`  top 3 β: ${all.sort((a, b) => b.corr - a.corr).slice(0, 3).map(x => `bit ${x.bit}: ${x.corr.toExponential(2)}`).join(', ')}`);
  if (bestCorr < 3 * sigma) {
    console.log(`  --> no signal detected (best < 3σ)`);
  } else if (bestCorr > predCorr * 2) {
    console.log(`  --> observed > 2x predicted: clustering or better trail`);
  } else if (bestCorr < predCorr / 2) {
    console.log(`  --> observed < 1/2 predicted: model overestimates or trail absent`);
  } else {
    console.log(`  --> consistent with model`);
  }
  console.log(`  time: ${((Date.now() - t0) / 1000).toFixed(1)}s\n`);
}
