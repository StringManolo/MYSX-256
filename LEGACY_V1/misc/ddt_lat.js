'use strict';
// =============================================================================
// ddt_lat.js — Exact DDT and LAT of F at w=8
// -----------------------------------------------------------------------------
// F(x) = (rotl(x,a) & rotl(x,b)) ^ rotl(x,c)
// At w=8 with (a,b,c)=(1,4,2), the full DDT and LAT are 256×256 and can be
// computed exactly by brute force. This gives the true per-F differential
// uniformity and nonlinearity, which are the inputs the MILP approximates.
// =============================================================================
const { makeMini } = require('./mini');

function popcount(x) {
  x = x - ((x >>> 1) & 0x55555555);
  x = (x & 0x33333333) + ((x >>> 2) & 0x33333333);
  x = (x + (x >>> 4)) & 0x0F0F0F0F;
  return (x * 0x01010101) >>> 24;
}

function computeDDT(m) {
  const N = m.M + 1;
  const ddt = new Uint32Array(N * N);
  const F = new Uint8Array(N);
  for (let x = 0; x < N; x++) F[x] = m.F(x);
  for (let dx = 1; dx < N; dx++) {
    const row = dx * N;
    for (let x = 0; x < N; x++) {
      ddt[row + (F[x] ^ F[x ^ dx])]++;
    }
  }
  return ddt;
}

function computeLAT(m) {
  const N = m.M + 1;
  const lat = new Int32Array(N * N);
  const F = new Uint8Array(N);
  const par = new Uint8Array(N);
  for (let x = 0; x < N; x++) { F[x] = m.F(x); par[x] = popcount(x) & 1; }
  // For each x, for each (alpha, beta): sign = (-1)^(par(alpha&x) ^ par(beta&F(x)))
  for (let x = 0; x < N; x++) {
    const fx = F[x];
    for (let alpha = 0; alpha < N; alpha++) {
      const pa = par[alpha & x] ? -1 : 1;
      const row = alpha * N;
      for (let beta = 0; beta < N; beta++) {
        const pb = par[beta & fx] ? -1 : 1;
        lat[row + beta] += pa * pb;
      }
    }
  }
  return lat;
}

function analyzeDDT(ddt, N) {
  let maxVal = 0, examples = [];
  const hist = {};
  for (let dx = 1; dx < N; dx++) {
    for (let dy = 0; dy < N; dy++) {
      const v = ddt[dx * N + dy];
      if (v === 0) continue;
      hist[v] = (hist[v] || 0) + 1;
      if (v > maxVal) { maxVal = v; examples = [[dx, dy]]; }
      else if (v === maxVal && examples.length < 5) examples.push([dx, dy]);
    }
  }
  return { maxVal, hist, examples };
}

function analyzeLAT(lat, N) {
  let maxVal = 0, examples = [];
  for (let alpha = 1; alpha < N; alpha++) {
    for (let beta = 1; beta < N; beta++) {
      const v = Math.abs(lat[alpha * N + beta]);
      if (v > maxVal) { maxVal = v; examples = [[alpha, beta]]; }
      else if (v === maxVal && examples.length < 5) examples.push([alpha, beta]);
    }
  }
  return { maxVal, examples };
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------
const w = 8, a = 1, b = 4, c = 2;
const m = makeMini(w, a, b, c, 'MYSZKOWS', 0);
const N = m.M + 1;

console.log(`F(x) = (rotl(x,${a}) & rotl(x,${b})) ^ rotl(x,${c}), w=${w}, N=${N}\n`);

let t0 = Date.now();
const ddt = computeDDT(m);
const ddtMs = Date.now() - t0;

const ddtRes = analyzeDDT(ddt, N);
console.log('=== DDT ===');
console.log(`  time: ${ddtMs} ms`);
console.log(`  max entry: ${ddtRes.maxVal} (prob ${ddtRes.maxVal}/${N} = 2^-${Math.log2(N / ddtRes.maxVal).toFixed(2)})`);
console.log(`  differential uniformity: ${ddtRes.maxVal}`);
console.log(`  distinct DDT values: ${Object.keys(ddtRes.hist).length}`);
const topHist = Object.entries(ddtRes.hist).sort((a, b) => Number(b[0]) - Number(a[0])).slice(0, 8);
for (const [v, count] of topHist) {
  console.log(`    DDT=${String(v).padStart(4)}: ${count} entries`);
}
console.log(`  examples of max:`);
for (const [dx, dy] of ddtRes.examples.slice(0, 3)) {
  console.log(`    (Δx=0x${dx.toString(16).padStart(2, '0')}, Δy=0x${dy.toString(16).padStart(2, '0')})`);
}

console.log();
t0 = Date.now();
const lat = computeLAT(m);
const latMs = Date.now() - t0;

const latRes = analyzeLAT(lat, N);
console.log('=== LAT ===');
console.log(`  time: ${latMs} ms`);
console.log(`  max |LAT|: ${latRes.maxVal} (corr ${latRes.maxVal}/${N} = 2^-${Math.log2(N / latRes.maxVal).toFixed(2)})`);
console.log(`  nonlinearity: ${(N - latRes.maxVal) / 2}`);
console.log(`  examples of max:`);
for (const [alpha, beta] of latRes.examples.slice(0, 3)) {
  console.log(`    (α=0x${alpha.toString(16).padStart(2, '0')}, β=0x${beta.toString(16).padStart(2, '0')}): LAT=${lat[alpha * N + beta]}`);
}

// -----------------------------------------------------------------------------
// MILP consistency check
// -----------------------------------------------------------------------------
console.log('\n=== MILP assumption ===');
console.log('The MILP models each active AND as cost 1, i.e., prob 2^-1 per active AND.');
console.log('For a single AND z=x&y, max DDT is 2 (prob 2^-1 per active bit).');
console.log(`For F at w=${w}, observed max DDT = ${ddtRes.maxVal} / ${N}.`);
const ratio = ddtRes.maxVal / 2;
console.log(`Ratio to single-AND model: ${ratio.toFixed(2)}x.`);
console.log(`If F were a single AND, max DDT would be 2 (prob 2^-7 for one active bit over 8-bit word).`);
console.log(`Observed ${ddtRes.maxVal}: this is the clustering of the AND + 2 XORs in F.`);
console.log(`The MILP's per-round weight is the number of active ANDs, NOT the DDT of F.`);
console.log(`DDT/LAT of F alone does not validate round-level trails.`);
console.log(`For round-level verification, run mini_trail.js.`);
