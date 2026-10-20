'use strict';

const { makeMini } = require('./mini');

// simonF reconstructed from mysx.prod.js (not exported publicly)
const rotl32 = (x, n) => { n &= 31; return (((x << n) | (x >>> (32 - n))) >>> 0); };
const simonF = x => ((rotl32(x, 1) & rotl32(x, 8)) ^ rotl32(x, 2)) >>> 0;

// Expected MYZ_PERM from mysx.prod.js
const EXPECTED_PERM = [
   4,12,20,28,  0, 8,16,24,  5,13,21,29,
   2, 7,10,15,18,23,26,31,  6,14,22,30,
   1, 9,17,25,  3,11,19,27
];

// -----------------------------------------------------------------------------
// 1) Permutation check at w=32
// -----------------------------------------------------------------------------
const m32 = makeMini(32, 1, 8, 2, 'MYSZKOWS', 0);
const permOk =
  m32.perm.length === 32 && m32.perm.every((v, i) => v === EXPECTED_PERM[i]);

console.log('w=32: MYZ_PERM reproduces:', permOk ? 'OK' : 'FAIL');
if (!permOk) {
  console.log('  expected:', EXPECTED_PERM);
  console.log('  got:     ', m32.perm);
}

// -----------------------------------------------------------------------------
// 2) F check at w=32 vs simonF from mysx.prod.js
// -----------------------------------------------------------------------------
console.log('\nw=32: F vs simonF');
const testInputs = [
  0x00000000, 0x00000001, 0x00000002, 0x00000055, 0x000000AA, 0x000000FF,
  0x12345678, 0x55555555, 0xAAAAAAAA, 0xFFFFFFFF, 0x80000000, 0x00000003,
  0xDEADBEEF, 0xCAFEBABE, 0x0F0F0F0F, 0xF0F0F0F0
];
let fOk = true;
for (const x of testInputs) {
  const mf = m32.F(x);
  const sf = simonF(x);
  const match = mf === sf;
  if (!match) fOk = false;
  console.log(
    `  x=0x${(x >>> 0).toString(16).padStart(8, '0')}: ` +
    `mini.F=0x${(mf >>> 0).toString(16).padStart(8, '0')}, ` +
    `simonF=0x${(sf >>> 0).toString(16).padStart(8, '0')} ` +
    `${match ? 'OK' : 'FAIL'}`
  );
}
console.log('w=32: F matches simonF:', fOk ? 'OK' : 'FAIL');

// -----------------------------------------------------------------------------
// 3) Other scales (sanity)
// -----------------------------------------------------------------------------
console.log('\nOther scales:');
const scales = [
  [16, 1, 8, 2],   // half-size word, same rotations (Simon-like scaling)
  [8,  1, 4, 2],   // quarter-size word, rotation = w/2 (recommended for w=8)
];
for (const [w, a, b, c] of scales) {
  try {
    const m = makeMini(w, a, b, c, 'MYSZKOWS', 0);
    console.log(
      `  w=${w}, (a,b,c)=(${a},${b},${c}): ` +
      `perm.length=${m.perm.length}, ` +
      `F(0x01)=0x${m.F(1).toString(16)}, ` +
      `F(0x55)=0x${m.F(0x55).toString(16)}`
    );
  } catch (e) {
    console.log(`  w=${w}, (a,b,c)=(${a},${b},${c}): ERROR ${e.message}`);
  }
}

// -----------------------------------------------------------------------------
// 4) Encrypt smoke test at w=8 and w=16 (structure check)
// -----------------------------------------------------------------------------
console.log('\nEncrypt smoke test:');
for (const [w, a, b, c, nr] of [
  [8,  1, 4, 2, 4],
  [16, 1, 8, 2, 4]
]) {
  const m = makeMini(w, a, b, c, 'MYSZKOWS', 0);
  const pt  = m.randState();
  const rks = Array.from({ length: nr }, () => m.randState());
  const ct  = m.encrypt(pt, rks, nr);
  console.log(
    `  w=${w}, nr=${nr}: ` +
    `pt=[${pt.map(x => x.toString(16)).join(',')}] -> ` +
    `ct=[${ct.map(x => x.toString(16)).join(',')}]`
  );
}

// -----------------------------------------------------------------------------
// 5) Round-trip check: encrypt, then invert by hand for a single round (w=8)
//    This is not decryption, just a structural sanity check.
// -----------------------------------------------------------------------------
console.log('\nRound-trip by hand at w=8 (feistel cell invertibility):');
{
  const m = makeMini(8, 1, 4, 2, 'MYSZKOWS', 0);
  const pt  = m.randState();
  const rk  = m.randState();
  const s0 = pt.slice();
  const s1 = s0.slice();
  m.round(s1, rk, 0);

  // Manually invert one round at w=8:
  //   after AddRoundKey:  x[i] = s0[i] ^ rk[i]
  //   after feistel:      y[p] = x[p+4],  y[p+4] = x[p] ^ F(x[p+4])
  //   after transposition: same permutation (byte-level)
  //   after rotation:     s1[i] = rotl(y[i], sh)
  // Inverse:
  //   1) undo rotation: y'[i] = rotr(s1[i], sh)
  //   2) undo transposition: permute back
  //   3) undo feistel: x'[p] = y'[p+4] ^ F(y'[p]), x'[p+4] = y'[p]
  //   4) undo AddRoundKey: s0'[i] = x'[i] ^ rk[i]
  const w = 8, bpw = 1, sh = (0 % (w - 1)) + 1;
  const rotr = (x, n) => { n = ((n % w) + w) % w; return ((x >>> n) | (x << (w - n))) & m.M; };

  // 1) undo rotation
  const y1 = s1.map(v => rotr(v, sh));

  // 2) undo transposition: bytes -> reorder by inverse perm
  const bytes1 = [];
  for (let i = 0; i < 8; i++) bytes1.push(y1[i] & 0xff);
  const inv = new Array(m.perm.length);
  for (let i = 0; i < m.perm.length; i++) inv[m.perm[i]] = i;
  const bytes0 = new Array(m.perm.length);
  for (let i = 0; i < m.perm.length; i++) bytes0[i] = bytes1[inv[i]];
  const y0 = [];
  for (let i = 0; i < 8; i++) y0.push(bytes0[i]);

  // 3) undo feistel
  const x = new Array(8);
  for (let p = 0; p < 4; p++) {
    const newL = y0[p];        // was R
    const newR = y0[p + 4];    // was L ^ F(R)
    const R = newL;
    const L = newR ^ m.F(R);
    x[p]     = L & m.M;
    x[p + 4] = R & m.M;
  }

  // 4) undo AddRoundKey
  const s0p = x.map((v, i) => (v ^ rk[i]) & m.M);

  const ok = s0p.every((v, i) => v === s0[i]);
  console.log(
    `  s0=[${s0.map(x => x.toString(16)).join(',')}] ` +
    `-> invert -> [${s0p.map(x => x.toString(16)).join(',')}] ` +
    `${ok ? 'OK' : 'FAIL'}`
  );
}
