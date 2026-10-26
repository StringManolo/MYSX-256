'use strict';
const { makeMini } = require('./mini');

console.log('=== Keyword / w compatibility ===\n');

for (const [w, kw, label] of [
  [32, 'MYSZKOWS', 'real MYSX (8-letter keyword, cols=8, rows=4)'],
  [16, 'MYSZKOWS', 'w=16, 8-letter keyword (cols=8, rows=2)'],
  [16, 'MYSZ',     'w=16, 4-letter keyword (cols=4, rows=4)'],
  [8,  'MYSZKOWS', 'w=8, 8-letter keyword (cols=8, rows=1) DEGENERATE'],
  [8,  'MYSZ',     'w=8, 4-letter keyword (cols=4, rows=2) non-degenerate'],
]) {
  try {
    const m = makeMini(w, w === 8 ? 1 : 1, w === 8 ? 4 : 8, 2, kw, 0);
    const permStr = m.perm.join(',');
    const degenerate = w === 8 && kw === 'MYSZKOWS';
    console.log(`w=${w}, kw='${kw}' — ${label}`);
    console.log(`  perm = [${permStr}]`);
    console.log(`  perm[0] = ${m.perm[0]}, L→R→L cycle at word 0: ${m.perm[0] === 4 ? 'YES (degenerate)' : 'NO (ok)'}`);
    console.log(`  status: ${degenerate ? 'DEGENERATE — do not use for analysis' : 'OK'}\n`);
  } catch (e) {
    console.log(`w=${w}, kw='${kw}': ERROR ${e.message}\n`);
  }
}

console.log('=== F differential at w=8 with non-degenerate keyword ===\n');

// Sanity: the differential at r=2 should NOT be prob 1 anymore
function quickDiff(w, kw, nr, dIn, N) {
  const m = makeMini(w, 1, w === 8 ? 4 : 8, 2, kw, 0xC0FFEE);
  const hist = new Map();
  for (let n = 0; n < N; n++) {
    const rks = Array.from({ length: nr }, () => m.randState());
    const P = m.randState();
    const P2 = P.map((x, i) => x ^ dIn[i]);
    const C = m.encrypt(P, rks, nr);
    const C2 = m.encrypt(P2, rks, nr);
    const dC = C.map((x, i) => (x ^ C2[i]) & m.M);
    const key = dC.join(',');
    hist.set(key, (hist.get(key) || 0) + 1);
  }
  const sorted = [...hist.entries()].sort((a, b) => b[1] - a[1]);
  return sorted.slice(0, 3).map(([k, v]) => ({ dC: k, prob: v / N, count: v }));
}

const dIn = [1, 0, 0, 0, 0, 0, 0, 0];
const N = 10000;

for (const [kw, label] of [['MYSZKOWS', 'DEGENERATE'], ['MYSZ', 'non-degenerate']]) {
  console.log(`kw='${kw}' (${label}):`);
  for (const nr of [1, 2, 3, 4]) {
    const top = quickDiff(8, kw, nr, dIn, N);
    const t = top[0];
    console.log(`  r=${nr}: top ΔC prob = ${t.prob.toFixed(4)} (${t.count}/${N}), '${t.dC}'`);
  }
  console.log();
}

console.log('=== Expected ===\n');
console.log('kw=MYSZKOWS: r=1..4 all prob 1.00 (degenerate L→R→L cycle).');
console.log('kw=MYSZ:     r=1 prob 1.00 (no F yet), r≥2 prob < 1 (F activates).');
