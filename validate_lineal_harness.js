'use strict';
// =============================================================================
// validate_linear_harness.js — Sanity check for the linear sampling harness
// -----------------------------------------------------------------------------
// At w=8, r=1, with:
//   alpha = {word0 bit2, word4 bit0} = [0x04,0,0,0, 0x01,0,0,0]
//   beta  = word0 bit3              = [0x08,0,0,0, 0,0,0,0]
//   fixed round key rk[0]
// the correlation should be EXACTLY ±0.5.
//
// Derivation (see paper §2.5 for the round structure):
//   P0[2] ^ P4[0] ^ C0[3] = (y0[1] & y0[6]) ^ (rk0[2] ^ rk4[0])
// where y0 = x4 = P4 ^ rk4. Since y0[1], y0[6] are uniform, the AND has
// P(AND=1) = 1/4, so the linear approximation holds with prob 3/4 and
// correlation 2·(3/4) − 1 = ±1/2, sign given by (rk0[2] ^ rk4[0]).
//
// If the harness returns ~0 with random keys per sample, that is the bug
// (key-averaging washes out the sign). If it returns ~0 with a fixed key,
// the harness has a deeper bug.
// =============================================================================
const { makeMini } = require('./mini');

function popcount(x) {
  let p = 0;
  while (x) { p ^= (x & 1); x >>>= 1; }
  return p;
}

function parityMasked(x, mask) {
  let p = 0;
  for (let i = 0; i < x.length; i++) p ^= popcount(x[i] & mask[i]) & 1;
  return p;
}

async function run(mode, N) {
  const w = 8, a = 1, b = 4, c = 2;
  const m = makeMini(w, a, b, c, 'MYSZKOWS', 0x1234);

  const alpha = [0x04, 0, 0, 0, 0x01, 0, 0, 0];
  const beta  = [0x08, 0, 0, 0, 0,    0, 0, 0];

  // Fixed round key (only one round needed)
  const fixedRk = m.randState();
  const fixedRks = [fixedRk];

  let sum = 0;
  for (let n = 0; n < N; n++) {
    const P = m.randState();
    // In 'fixed' mode, we reuse the same round key. In 'random', we
    // regenerate it per sample (which is what the current mini_trail.js does).
    const rks = mode === 'fixed' ? fixedRks : [m.randState()];
    const C = m.encrypt(P, rks, 1);
    const pa = parityMasked(P, alpha);
    const pb = parityMasked(C, beta);
    sum += (pa ^ pb) ? -1 : 1;
  }
  return sum / N;
}

(async () => {
  const N = 1 << 20;
  console.log(`N = ${N} = 2^${Math.log2(N)}\n`);

  const corrFixed = await run('fixed', N);
  console.log(`mode = fixed:    corr = ${corrFixed.toFixed(6)}  |corr| = ${Math.abs(corrFixed).toFixed(6)}`);
  console.log(`  expected |corr| ≈ 0.5 (fixed key preserves the sign)\n`);

  const corrRandom = await run('random', N);
  console.log(`mode = random:   corr = ${corrRandom.toFixed(6)}  |corr| = ${Math.abs(corrRandom).toFixed(6)}`);
  console.log(`  expected |corr| ≈ 0 (random key averages out the sign)\n`);

  console.log('=== Verdict ===');
  const fixedOk  = Math.abs(Math.abs(corrFixed)  - 0.5) < 0.01;
  const randomOk = Math.abs(corrRandom) < 0.01;
  if (fixedOk && randomOk) {
    console.log('PASS: harness is correct.');
    console.log('  - Fixed key gives |corr| = 0.5 exactly (trail exists).');
    console.log('  - Random key per sample washes it to ~0 (sign averaging).');
    console.log('  - The current mini_trail.js uses random keys, hence its result is meaningless.');
  } else if (!fixedOk && randomOk) {
    console.log('FAIL: fixed key does not give 0.5. Harness has a bug.');
    console.log(`  observed ${corrFixed.toFixed(4)}, expected ±0.5.`);
  } else if (fixedOk && !randomOk) {
    console.log('FAIL: random key did NOT wash out the correlation.');
    console.log(`  observed ${corrRandom.toFixed(4)}, expected ~0.`);
    console.log('  This suggests the round key is not being applied at all.');
  } else {
    console.log('FAIL: both modes are wrong. Harness is broken.');
  }
})();
