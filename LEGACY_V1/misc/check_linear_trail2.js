'use strict';
process.env.MYSX_ENABLE_TEST = '1';
const MYSX = require('./mysx.prod.js');
const { TEST } = MYSX;
const { _keySchedule, _encryptBlockCore, _makeScratch, CONFIG } = TEST;
const { KEY_BYTES } = CONFIG;

// Trail a r=3 del modelo lineal corregido (peso=8, corr esperada ≈ 2^-8)
const ROUNDS = 3;
const alpha_bits = [[0, 0]];                          // entrada
const beta_bits  = [[0, 14],
                    [2, 15], [2, 16], [2, 30],
                    [3, 23], [3, 24],
                    [4, 24], [4, 26],
                    [5, 15], [5, 16],
                    [7, 6]];                          // salida
const EXPECTED_CORR = Math.pow(2, -8);  // ≈ 0.00390625

function bitsToMask(bits) {
  const m = new Uint8Array(32);
  for (const [w, b] of bits) {
    m[w * 4 + (3 - (b >> 3))] |= (1 << (b & 7)) & 0xff;
  }
  return m;
}

function parity(x) {
  let p = 0;
  for (let i = 0; i < x.length; i++) {
    let v = x[i];
    while (v) { p ^= (v & 1); v >>>= 1; }
  }
  return p;
}

const alpha = bitsToMask(alpha_bits);
const beta  = bitsToMask(beta_bits);

// Clave determinista (igual que en el modelo, para reproducibilidad)
const key = new Uint8Array(KEY_BYTES);
for (let i = 0; i < KEY_BYTES; i++) key[i] = i;
const sch = _keySchedule(key);
const sc = _makeScratch();

// --- Test 1: trail del MILP a r=3 ---
const N = 5000000;
let matches = 0;
for (let t = 0; t < N; t++) {
  const p = new Uint8Array(32);
  for (let i = 0; i < 32; i++) p[i] = (Math.random() * 256) | 0;
  const c = _encryptBlockCore(p, sch, ROUNDS, sc, false).slice();
  const lhs = parity(alpha.map((v, i) => v & p[i]))
            ^ parity(beta.map((v, i) => v & c[i]));
  if (lhs === 0) matches++;
}
const corr = 2 * (matches / N) - 1;
const sigma = 1 / Math.sqrt(N);

console.log('=== Test 1: trail del MILP (α = w0b0, β = 11 bits, peso=8, r=3) ===');
console.log(`N=${N}, matches=${matches} (${(matches/N*100).toFixed(4)}%)`);
console.log(`Correlación observada: ${corr.toExponential(3)}`);
console.log(`Correlación esperada:  ${EXPECTED_CORR.toExponential(3)} (2^-8)`);
console.log(`σ (ruido):             ${sigma.toExponential(3)}`);
console.log(`Desviación:            ${(Math.abs(corr) / sigma).toFixed(2)}σ`);
console.log('');

if (Math.abs(corr) > 5 * sigma && Math.abs(corr) > EXPECTED_CORR / 4) {
  console.log('→ Trail EXISTE. Correlación significativa detectada.');
  console.log(`  Peso empírico ≈ ${Math.round(-Math.log2(Math.abs(corr)))}`);
  console.log('  Consistente con el modelo lineal. Capítulo cerrado.');
} else if (Math.abs(corr) <= 5 * sigma) {
  console.log('→ Correlación NO significativa con esta muestra.');
  console.log('  Puede ser: (a) trail más débil de lo esperado,');
  console.log('  (b) clustering que la diluye, (c) N insuficiente.');
} else {
  console.log('→ Correlación anómala. Investigar.');
}

// --- Test 2: control con máscara aleatoria (debe dar ~0) ---
function randomMask() {
  const m = new Uint8Array(32);
  for (let i = 0; i < 32; i++) m[i] = (Math.random() * 256) | 0;
  return m;
}
const alphaCtrl = randomMask();
const betaCtrl  = randomMask();
let matchesCtrl = 0;
const N_CTRL = 100000;
for (let t = 0; t < N_CTRL; t++) {
  const p = new Uint8Array(32);
  for (let i = 0; i < 32; i++) p[i] = (Math.random() * 256) | 0;
  const c = _encryptBlockCore(p, sch, ROUNDS, sc, false).slice();
  const lhs = parity(alphaCtrl.map((v, i) => v & p[i]))
            ^ parity(betaCtrl.map((v, i) => v & c[i]));
  if (lhs === 0) matchesCtrl++;
}
const corrCtrl = 2 * (matchesCtrl / N_CTRL) - 1;
const sigmaCtrl = 1 / Math.sqrt(N_CTRL);

console.log('');
console.log('=== Test 2: control con máscara aleatoria (debe dar ~0) ===');
console.log(`N=${N_CTRL}, correlación=${corrCtrl.toExponential(3)}, ` +
            `${(Math.abs(corrCtrl)/sigmaCtrl).toFixed(2)}σ`);
if (Math.abs(corrCtrl) < 5 * sigmaCtrl) {
  console.log('→ Control OK: sin correlación espuria.');
} else {
  console.log('→ Control anómalo. Investigar el harness.');
}
