'use strict';
const crypto = require('crypto');
const { makeMini } = require('./mini');

function popcount(x) { let p = 0; while (x) { p ^= x & 1; x >>>= 1; } return p; }
function parity(x, mask) { let p = 0; for (let i = 0; i < 8; i++) p ^= popcount(x[i] & mask[i]) & 1; return p; }
function bitMask(bits) {
  const m = [0,0,0,0,0,0,0,0];
  for (const b of bits) m[b >> 3] |= 1 << (b & 7);
  return m;
}

// Independently uniform round keys (crypto random, not an LCG)
function randomRoundKeys(nr) {
  const rks = [];
  for (let r = 0; r < nr; r++) {
    const buf = crypto.randomBytes(8);
    rks.push(Array.from(buf));
  }
  return rks;
}

async function main() {
  const w = 8, a = 1, b = 4, c = 2;
  const m = makeMini(w, a, b, c, 'MYSZ', 0xC0FFEE);

  const N = 1 << 19;      // lower for speed; raise to 2^20 for precision
  const nKeys = 4;

  const alphas = [
    { label: 'a0', mask: bitMask([0]) },
    { label: 'a5', mask: bitMask([5]) },
  ];

  // 1-bit beta masks (exhaustive)
  const betas = [];
  for (let bit = 0; bit < 64; bit++) {
    betas.push({ label: `b${bit}`, mask: bitMask([bit]) });
  }
  // Dense beta masks — built correctly (2 and 3 bits)
  for (const pair of [[0,1],[0,2],[0,3],[1,2],[2,3],[0,8],[1,5],[0,32],[8,32]]) {
    betas.push({ label: pair.join('^'), mask: bitMask(pair) });
  }
  betas.push({ label: '0^1^2', mask: bitMask([0,1,2]) });

  const sigma = 1 / Math.sqrt(N);
  const expectedMax = sigma * Math.sqrt(2 * Math.log(nKeys * betas.length));
  console.log(`N=${N}, keys=${nKeys}, w=${w}, kw='MYSZ'`);
  console.log(`Per-key sigma = ${sigma.toExponential(2)}`);
  console.log(`Expected max |corr| under H0 (${nKeys*betas.length} estimates): ${expectedMax.toExponential(2)}\n`);
  console.log('r | alpha | mean|corr| | max|corr| | max/sigma');
  console.log('--+-------+-----------+-----------+----------');

  for (const nr of [1, 2, 3, 4, 5]) {
    for (const { label: aLabel, mask: alpha } of alphas) {
      // |corr| per (key, beta): do NOT accumulate the sign across keys
      const corrsPerKey = [];
      for (let ki = 0; ki < nKeys; ki++) {
        const rks = randomRoundKeys(nr);
        const sums = new Array(betas.length).fill(0);
        for (let n = 0; n < N; n++) {
          const P = m.randState();
          const C = m.encrypt(P, rks, nr);
          const pAlpha = parity(P, alpha);
          for (let i = 0; i < betas.length; i++) {
            const pBeta = parity(C, betas[i].mask);
            sums[i] += (pAlpha ^ pBeta) ? -1 : 1;
          }
        }
        for (let i = 0; i < betas.length; i++) {
          corrsPerKey.push(Math.abs(sums[i] / N));
        }
      }
      const mean = corrsPerKey.reduce((a,b)=>a+b,0) / corrsPerKey.length;
      const max = Math.max(...corrsPerKey);
      console.log(`r=${nr} | ${aLabel}    | ${mean.toExponential(2)} | ${max.toExponential(2)} | ${(max/sigma).toFixed(2)}`);
    }
  }
}
main();
