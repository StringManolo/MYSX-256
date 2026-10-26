'use strict';
process.env.MYSX_ENABLE_TEST = '1';
const crypto = require('crypto');
const T = require('./mysx.prod.js').TEST;
const sc = T._makeScratch();
function rnd(n) { return new Uint8Array(crypto.randomBytes(n)); }
function enc(pt, sch, r) { return T._encryptBlockCore(pt, sch, r, sc, false).slice(); }

// --- Exact MILP trail at r=4 from w0b0 (from PAPER.md §3.2) ---
const ROUNDS = 4;
const MILP_WEIGHT = 8;          // number of active ANDs (NOT hw(Δout))
const dInWords = [[0, 0]];
const dOutWords = [[0, 4], [1, 10], [1, 16], [1, 30], [6, 4]];
// hw(Δout) = 5, but MILP weight = 8. The two are different quantities.
// The expected probability is 2^-8, not 2^-5.
// -----------------------------------------------------------

function makeMask(bits) {
  const m = new Uint8Array(32);
  for (const [w, b] of bits) m[w*4 + (3 - (b >> 3))] |= (1 << (b & 7)) & 0xff;
  return m;
}
function hw(x) { let h = 0; for (const v of x) { let u = v; while (u) { h += u & 1; u >>>= 1; } } return h; }

async function main() {
  const dIn = makeMask(dInWords);
  const dOutExpected = makeMask(dOutWords);
  const hwOut = hw(dOutExpected);
  const expectedProb = Math.pow(2, -MILP_WEIGHT);

  console.log(`ΔIn : ${dInWords.map(p=>p.join('b')).join(', ')}`);
  console.log(`ΔOut: ${dOutWords.map(p=>p.join('b')).join(', ')} (Hamming weight ${hwOut})`);
  console.log(`MILP weight: ${MILP_WEIGHT} (expected prob 2^-${MILP_WEIGHT} = ${expectedProb.toExponential(3)})`);
  console.log(`Note: hw(ΔOut) = ${hwOut} and MILP weight = ${MILP_WEIGHT} are different quantities.\n`);

  const N = 1 << 17;
  const nKeys = 8;
  const keys = Array.from({ length: nKeys }, () => rnd(64));
  const schs = keys.map(k => T._keySchedule(k));

  let totalHits = 0, totalTrials = 0;
  const start = Date.now();
  for (let ki = 0; ki < nKeys; ki++) {
    const sch = schs[ki];
    let hits = 0;
    for (let n = 0; n < N; n++) {
      const p = rnd(32);
      const p2 = new Uint8Array(32);
      for (let i = 0; i < 32; i++) p2[i] = p[i] ^ dIn[i];
      const c = enc(p, sch, ROUNDS);
      const c2 = enc(p2, sch, ROUNDS);
      let match = true;
      for (let i = 0; i < 32; i++) {
        if ((c[i] ^ c2[i]) !== dOutExpected[i]) { match = false; break; }
      }
      if (match) hits++;
    }
    totalHits += hits;
    totalTrials += N;
    console.log(`key ${ki}: ${hits}/${N} = ${(hits/N).toExponential(3)}`);
  }
  const observed = totalHits / totalTrials;
  const ratio = observed / expectedProb;
  console.log(`\nTOTAL: ${totalHits}/${totalTrials} = ${observed.toExponential(3)}`);
  console.log(`Expected (2^-${MILP_WEIGHT}): ${expectedProb.toExponential(3)}`);
  console.log(`Ratio observed/expected: ${ratio.toFixed(2)}x`);
  console.log(`Time: ${((Date.now()-start)/1000).toFixed(1)}s\n`);
  console.log('Interpretation:');
  console.log('  ratio ≈ 1    : trail verified, MILP correct');
  console.log('  ratio > 2    : clustering increases probability (favors attacker)');
  console.log('  ratio < 0.5  : model overestimates or clustering is destructive');
}
main();
