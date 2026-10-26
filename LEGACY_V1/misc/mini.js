'use strict';

// =============================================================================
// mini.js — Mini-MYSX: scaled-down version of MYSX for tractable analysis
// -----------------------------------------------------------------------------
// With w=32 and (a,b,c)=(1,8,2), F and the permutation reproduce exactly the
// real MYSX. With w=16 or w=8, the structure is preserved (4 Feistel cells,
// Myszkowski transposition, round-dependent rotation).
//
// IMPORTANT (non-degeneracy):
//   For w=8, nB=8. If you use the 8-letter keyword 'MYSZKOWS', cols=8, rows=1,
//   and the permutation becomes [4,0,5,2,7,6,1,3]. With perm[0]=4, a difference
//   in word 0 goes to word 4 after Feistel, and perm[0]=4 brings it back to
//   word 0. F never sees a difference. Result: probability-1 differential
//   for all rounds. This is a DEGENERATE case and NOT representative of MYSX.
//
//   Use a 4-letter keyword (e.g., 'MYSZ') for w=8: cols=4, rows=2,
//   perm=[0,4,1,5,2,6,3,7]. This breaks the L→R→L cycle and lets the
//   difference pass through F on round 2.
//
//   For w=16: nB=16. Use a 4-letter keyword (cols=4, rows=4) or 8-letter
//   (cols=8, rows=2). Both are non-degenerate.
// =============================================================================

function makeRng(seed) {
  let t = seed >>> 0;
  return function () {
    t = (t + 0x6D2B79F5) >>> 0;
    let x = t;
    x = Math.imul(x ^ (x >>> 15), x | 1);
    x ^= x + Math.imul(x ^ (x >>> 7), x | 61);
    return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
  };
}

function makeMini(w, a, b, c, keyword = 'MYSZKOWS', seed = 0xC0FFEE) {
  if (w % 8 !== 0 || w < 8 || w > 32) {
    throw new Error(`w must be a multiple of 8 in [8, 32]; got ${w}`);
  }
  if (keyword.length < 2) throw new Error('keyword must have at least 2 letters');

  const M = w === 32 ? 0xFFFFFFFF : ((1 << w) - 1) >>> 0;
  const bpw = w / 8;
  const nB = 8 * bpw;
  const rng = makeRng(seed);

  const rotl = (x, n) => {
    n = ((n % w) + w) % w;
    if (n === 0) return x >>> 0;
    return (((x << n) | (x >>> (w - n))) & M) >>> 0;
  };

  const F = x => (((rotl(x, a) & rotl(x, b)) ^ rotl(x, c)) & M) >>> 0;

  const cols = keyword.length;
  if (nB % cols !== 0) {
    throw new Error(`nB (${nB}) must be divisible by keyword length (${cols})`);
  }
  const rows = nB / cols;
  const perm = [];
  for (const L of [...new Set(keyword)].sort()) {
    const cs = [...keyword].map((ch, i) => (ch === L ? i : -1)).filter(i => i >= 0);
    for (let r = 0; r < rows; r++) {
      for (const col of cs) perm.push(r * cols + col);
    }
  }

  function round(s, rk, r) {
    for (let i = 0; i < 8; i++) s[i] = (s[i] ^ rk[i]) & M;
    for (let p = 0; p < 4; p++) {
      const L = s[p], R = s[p + 4];
      s[p]     = R;
      s[p + 4] = (L ^ F(R)) & M;
    }
    const bytes = [];
    for (let i = 0; i < 8; i++) {
      for (let k = 0; k < bpw; k++) {
        bytes.push((s[i] >>> (8 * (bpw - 1 - k))) & 0xff);
      }
    }
    const pb = perm.map(j => bytes[j]);
    const sh = (r % (w - 1)) + 1;
    for (let i = 0; i < 8; i++) {
      let v = 0;
      for (let k = 0; k < bpw; k++) v = (v << 8) | pb[i * bpw + k];
      s[i] = rotl(v, sh);
    }
  }

  function encrypt(pt, rks, nr) {
    if (pt.length !== 8) throw new Error('pt must have 8 words');
    if (rks.length < nr) throw new Error('rks must have at least nr entries');
    const s = pt.slice();
    for (let r = 0; r < nr; r++) round(s, rks[r], r);
    return s;
  }

  function randState() {
    return Array.from({ length: 8 }, () => Math.floor(rng() * (M + 1)));
  }

  return { w, M, F, rotl, perm, round, encrypt, randState, rng, bpw, nB, keyword };
}

module.exports = { makeMini, makeRng };
