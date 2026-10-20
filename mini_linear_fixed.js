'use strict';
// mini_linear_fixed.js
const { makeMini } = require('./mini');

function popcount(x) { let p = 0; while (x) { p ^= x & 1; x >>>= 1; } return p; }
function parity(x, mask) { let p = 0; for (let i = 0; i < 8; i++) p ^= popcount(x[i] & mask[i]) & 1; return p; }
function bitMask(bits) {
  const m = [0,0,0,0,0,0,0,0];
  for (const b of bits) m[b >> 3] |= 1 << (b & 7);
  return m;
}

async function main() {
  const w = 8, a = 1, b = 4, c = 2;
  const m = makeMini(w, a, b, c, 'MYSZ', 0xC0FFEE);  // non-degenerate

  const alpha = bitMask([0]);           // word 0 bit 0
  const N = 1 << 20;
  const keys = [0x01, 0x42, 0xA5, 0x3C].map(k => {
    const rks = [];
    let t = k;
    for (let r = 0; r < 6; r++) { t = (t * 1103515245 + 12345) & 0x7fffffff; rks.push(Array.from({length:8}, (_, i) => (t >>> (i*4)) & 0xff)); }
    return rks;
  });

  console.log(`N=${N}, keys=${keys.length}, w=${w}, kw='MYSZ'\n`);
  console.log('r | β bits | mean |corr| | max |corr|');
  console.log('--+--------+------------+-----------');

  for (const nr of [1, 2, 3, 4, 5]) {
    const betas = [];
    for (let bit = 0; bit < 64; bit++) betas.push({ label: `b${bit}`, mask: bitMask([bit]) });
    // dense β masks (XOR of multiple bits)
    for (const [b1, b2] of [[0,1],[0,2],[0,3],[1,2],[2,3],[0,1,2]]) {
      betas.push({ label: `${b1}^${b2}`, mask: bitMask([b1, b2].filter((x,i,a)=>a.indexOf(x)===i)) });
    }

    const corrs = [];
    for (const { mask: beta } of betas) {
      let sum = 0;
      for (const rks of keys) {
        for (let n = 0; n < N; n++) {
          const P = m.randState();
          const C = m.encrypt(P, rks.slice(0, nr), nr);
          sum += (parity(P, alpha) ^ parity(C, beta)) ? -1 : 1;
        }
      }
      const corr = Math.abs(sum / (N * keys.length));
      corrs.push(corr);
    }
    const meanCorr = corrs.reduce((a,b)=>a+b,0) / corrs.length;
    const maxCorr = Math.max(...corrs);
    console.log(`r=${nr} | ${betas.length.toString().padStart(6)} | ${meanCorr.toExponential(2)} | ${maxCorr.toExponential(2)}`);
  }
}
main();
