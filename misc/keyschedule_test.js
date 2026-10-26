'use strict';

// =============================================================================
// keyschedule_test.js — Auditoría del key schedule de MYSX-256/512
// -----------------------------------------------------------------------------
// Reimplementa keySchedule con acceso a los estados intermedios (necesario para
// analizar la propagación de diferencias) y verifica que coincide con la
// implementación de producción en mysx.prod.js.
//
// Tests:
//   1. Verificación de reimplementación (vs. mysx.prod.js)
//   2. Biyectividad del state update (Feistel 8+8)
//   3. Espacio nulo de Δrk[0]=0 (analítico, GF(2))
//   4. Propagación de diferencias del espacio nulo a través de rondas
//   5. Avalancha (1 bit de K → bits de rk[r])
//   6. Búsqueda aleatoria de diferenciales de bajo peso
//   7. Scan de claves débiles
//
// Uso: node keyschedule_test.js
// =============================================================================

process.env.MYSX_ENABLE_TEST = '1';
const MYSX = require('./mysx.prod.js');
const { TEST } = MYSX;
if (!TEST) { console.error('TEST no disponible. Carga con MYSX_ENABLE_TEST=1'); process.exit(1); }
const { _keySchedule, CONFIG } = TEST;
const { KEY_BYTES, ROUNDS } = CONFIG;

// =============================================================================
// Reimplementación con estados intermedios
// (debe coincidir con mysx.prod.js _keySchedule)
// =============================================================================
const CONST = new Uint32Array([
  0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
  0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89
]);

function rotl32(x, n) { n &= 31; return (((x << n) | (x >>> (32 - n))) >>> 0); }

function keyScheduleWithStates(keyBytes) {
  if (keyBytes.length !== KEY_BYTES) throw new Error(`Clave debe ser ${KEY_BYTES} bytes`);
  const s = new Uint32Array(16);
  for (let i = 0; i < 16; i++) {
    s[i] = ((keyBytes[i*4] << 24) | (keyBytes[i*4+1] << 16) |
            (keyBytes[i*4+2] << 8) | keyBytes[i*4+3]) >>> 0;
  }
  const states = [s.slice()];
  const addKeys = new Array(ROUNDS);

  for (let r = 0; r < ROUNDS; r++) {
    const rk = new Uint32Array(8);
    const spread = Math.imul(r + 1, 0x9E3779B9) >>> 0;
    for (let i = 0; i < 8; i++) {
      rk[i] = (s[i] ^ s[(i + 5) & 15] ^ s[(i + 11) & 15]
               ^ CONST[(r + i) & 7] ^ spread) >>> 0;
      if (i < 4) {
        const fk = (s[(i + 8) & 15] ^ CONST[(r + i + 3) & 7]) >>> 0;
        rk[i] = (rk[i] ^ fk) >>> 0;
      }
    }
    addKeys[r] = rk;

    const L = s.slice(0, 8);
    const R = s.slice(8, 16);
    for (let i = 0; i < 8; i++) {
      const a = R[i], b = R[(i + 1) & 7], c = R[(i + 3) & 7];
      const F = (rotl32((a + b) >>> 0, 7) ^ rotl32(c, 13)
                 ^ CONST[i] ^ spread) >>> 0;
      s[i]     = R[i];
      s[i + 8] = (L[i] ^ F) >>> 0;
    }
    states.push(s.slice());
  }

  const rkFinal = new Uint32Array(8);
  for (let i = 0; i < 8; i++) {
    rkFinal[i] = (s[i] ^ s[(i + 8) & 15] ^ CONST[(ROUNDS + i) & 7]) >>> 0;
  }
  return { addKeys, rkFinal, states };
}

// =============================================================================
// Utilidades
// =============================================================================
function weightU32(arr) {
  let w = 0;
  for (const x of arr) {
    let v = x;
    while (v) { w += v & 1; v >>>= 1; }
  }
  return w;
}

function xorU32(a, b) {
  const out = new Uint32Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = (a[i] ^ b[i]) >>> 0;
  return out;
}

function keyToBits(keyBytes) {
  const bits = new Uint8Array(KEY_BYTES * 8);
  for (let i = 0; i < KEY_BYTES; i++) {
    for (let b = 0; b < 8; b++) {
      bits[i*8 + b] = (keyBytes[i] >>> (7 - b)) & 1;
    }
  }
  return bits;
}

// Construye una clave con los words indicados en 0xFFFFFFFF y el resto 0
function keyFromWordPattern(wordIndices) {
  const key = new Uint8Array(KEY_BYTES);
  for (const w of wordIndices) {
    for (let b = 0; b < 4; b++) key[w*4 + b] = 0xFF;
  }
  return key;
}

// =============================================================================
// Test 1: Verificación de reimplementación
// =============================================================================
function testVerify() {
  console.log('\n=== Test 1: Verificación de reimplementación ===');
  const key = new Uint8Array(KEY_BYTES);
  for (let i = 0; i < KEY_BYTES; i++) key[i] = (i * 7 + 13) & 0xff;
  const prod = _keySchedule(key);
  const ours = keyScheduleWithStates(key);

  let ok = true;
  for (let r = 0; r < ROUNDS; r++) {
    for (let i = 0; i < 8; i++) {
      if (prod.addKeys[r][i] !== ours.addKeys[r][i]) { ok = false; break; }
    }
    if (!ok) break;
  }
  if (ok) {
    for (let i = 0; i < 8; i++) {
      if (prod.rkFinal[i] !== ours.rkFinal[i]) { ok = false; break; }
    }
  }
  console.log(`  Reimplementación coincide con prod: ${ok ? 'OK' : 'FAIL'}`);
  return ok;
}

// =============================================================================
// Test 2: Biyectividad del state update
// =============================================================================
// La actualización es Feistel 8+8: s[i]'=R[i], s[i+8]'=L[i]^F(R). Es biyectiva
// por construcción. Reconstruimos s[r] desde s[r+1] y comparamos.
function testBijectivity() {
  console.log('\n=== Test 2: Biyectividad del state update ===');
  const key = new Uint8Array(KEY_BYTES);
  for (let i = 0; i < KEY_BYTES; i++) key[i] = (i * 13 + 7) & 0xff;
  const { states } = keyScheduleWithStates(key);

  let ok = true;
  for (let r = 0; r < ROUNDS; r++) {
    const sNext = states[r+1];
    const sCur = states[r];
    const spread = Math.imul(r + 1, 0x9E3779B9) >>> 0;
    const rec = new Uint32Array(16);
    for (let i = 0; i < 8; i++) rec[i + 8] = sNext[i];
    for (let i = 0; i < 8; i++) {
      const a = sNext[i], b = sNext[(i+1)&7], c = sNext[(i+3)&7];
      const F = (rotl32((a + b) >>> 0, 7) ^ rotl32(c, 13)
                 ^ CONST[i] ^ spread) >>> 0;
      rec[i] = (sNext[i + 8] ^ F) >>> 0;
    }
    for (let i = 0; i < 16; i++) {
      if (rec[i] !== sCur[i]) { ok = false; break; }
    }
    if (!ok) break;
  }
  console.log(`  State update biyectivo: ${ok ? 'OK' : 'FAIL'}`);
  return ok;
}

// =============================================================================
// Test 3: Espacio nulo de Δrk[0] = 0
// =============================================================================
// rk[0][i] = s[i] ^ s[(i+5)&15] ^ s[(i+11)&15] ^ (fk fold si i<4)
// donde fk = s[(i+8)&15] ^ CONST.
// Δrk[0][i] = 0 da un sistema lineal en ΔK (que es s[0..15] inicialmente).
//
// Resolvemos el sistema sobre GF(2) a nivel de palabra (cada palabra como
// variable binaria "difiere o no"). El espacio nulo real es el producto
// tensorial con GF(2)^32 (bits dentro de cada palabra), pero para el análisis
// basta con la dimensión a nivel de palabra.
function testNullSpaceRk0() {
  console.log('\n=== Test 3: Espacio nulo de Δrk[0]=0 ===');

  // Construir 8 ecuaciones. Cada ecuación: lista de índices de palabras
  // (los que tienen coeficiente 1 tras XOR).
  const rows = [];
  for (let i = 0; i < 8; i++) {
    const terms = [i, (i+5)&15, (i+11)&15];
    if (i < 4) terms.push((i+8)&15);
    // XOR: deduplicar
    const count = {};
    for (const v of terms) count[v] = (count[v] || 0) + 1;
    const row = Object.keys(count)
      .filter(k => count[k] % 2 === 1)
      .map(k => +k)
      .sort((a,b) => a-b);
    rows.push({ vars: row, pivot: -1 });
  }

  // Eliminación gaussiana sobre GF(2)
  let rank = 0;
  const pivots = [];
  for (let col = 0; col < 16; col++) {
    let pivotRow = -1;
    for (let r = rank; r < rows.length; r++) {
      if (rows[r].vars.includes(col)) { pivotRow = r; break; }
    }
    if (pivotRow === -1) continue;
    [rows[rank], rows[pivotRow]] = [rows[pivotRow], rows[rank]];
    for (let r = 0; r < rows.length; r++) {
      if (r !== rank && rows[r].vars.includes(col)) {
        const combined = new Set(rows[r].vars);
        for (const v of rows[rank].vars) {
          if (combined.has(v)) combined.delete(v);
          else combined.add(v);
        }
        rows[r].vars = [...combined].sort((a,b) => a-b);
      }
    }
    rows[rank].pivot = col;
    pivots.push(col);
    rank++;
  }

  const freeCols = [];
  for (let c = 0; c < 16; c++) if (!pivots.includes(c)) freeCols.push(c);

  // Base del espacio nulo (cada vector es un patrón de palabras que difieren)
  const basis = [];
  for (const freeCol of freeCols) {
    const sol = new Uint8Array(16);
    sol[freeCol] = 1;
    for (let r = 0; r < rank; r++) {
      const pivot = rows[r].pivot;
      let s = 0;
      for (const v of rows[r].vars) if (v !== pivot) s ^= sol[v];
      sol[pivot] = s;
    }
    basis.push(sol);
  }

  console.log(`  Ecuaciones: 8, incógnitas: 16 (palabras)`);
  console.log(`  Rango: ${rank}`);
  console.log(`  Dimensión del espacio nulo (palabras): ${16 - rank}`);
  console.log(`  Patrones no nulos con Δrk[0]=0: ${(1 << (16 - rank)) - 1}`);
  console.log(`  (Cada patrón se puede aplicar a los 32 bits de cada palabra →`);
  console.log(`   ${(1 << (16 - rank)) - 1} · (2^32 - 1)^k patrones reales, k = peso del patrón)`);

  // Verificar empíricamente que cada vector base da Δrk[0] = 0
  const zeroKey = new Uint8Array(KEY_BYTES);
  const baseSched = keyScheduleWithStates(zeroKey);
  let allVerified = true;
  for (const bv of basis) {
    const idxs = [];
    for (let w = 0; w < 16; w++) if (bv[w]) idxs.push(w);
    const modKey = keyFromWordPattern(idxs);
    const modSched = keyScheduleWithStates(modKey);
    let diff = 0;
    for (let i = 0; i < 8; i++) {
      diff |= (modSched.addKeys[0][i] ^ baseSched.addKeys[0][i]) >>> 0;
    }
    if (diff !== 0) { allVerified = false; break; }
  }
  console.log(`  Todos los vectores base dan Δrk[0]=0: ${allVerified ? 'OK' : 'FAIL'}`);

  return { basis, rank, nullity: 16 - rank, allVerified };
}

// =============================================================================
// Test 4: Propagación de diferencias del espacio nulo
// =============================================================================
// Para cada vector base (patrón de palabras), propagamos Δrk[r] para r=0..128
// y reportamos el peso mínimo por ronda. Si algún Δrk[r]=0 para r>0, es un
// distinguidor de claves relacionadas.
function testNullSpacePropagation(nsResult) {
  console.log('\n=== Test 4: Propagación de diferencias del espacio nulo ===');
  const { basis } = nsResult;
  if (basis.length === 0) {
    console.log('  Sin espacio nulo — nada que propagar');
    return null;
  }

  const zeroKey = new Uint8Array(KEY_BYTES);
  const baseSched = keyScheduleWithStates(zeroKey);

  // Para cada vector base, calcular Δrk[r] y su peso
  const results = [];
  for (let bi = 0; bi < basis.length; bi++) {
    const bv = basis[bi];
    const idxs = [];
    for (let w = 0; w < 16; w++) if (bv[w]) idxs.push(w);
    const modKey = keyFromWordPattern(idxs);
    const modSched = keyScheduleWithStates(modKey);

    const weights = [];
    for (let r = 0; r < ROUNDS; r++) {
      const drk = xorU32(modSched.addKeys[r], baseSched.addKeys[r]);
      weights.push(weightU32(drk));
    }
    const dfinal = xorU32(modSched.rkFinal, baseSched.rkFinal);
    results.push({ basisIdx: bi, wordPattern: idxs, weights, finalWeight: weightU32(dfinal) });
  }

  // Reportar tabla compacta: para cada vector, peso de Δrk[r] en r=0,1,2,3,4,8,16,32,64,128
  const checkRounds = [0, 1, 2, 3, 4, 8, 16, 32, 64, 128];
  console.log(`  ${'vec'.padEnd(4)} | ${'#words'.padEnd(7)} | ${checkRounds.map(r => `r=${r}`.padEnd(5)).join(' ')}`);
  for (const res of results) {
    const row = checkRounds.map(r => {
      if (r === 128) return String(res.finalWeight).padEnd(5);
      return String(res.weights[r]).padEnd(5);
    });
    console.log(`  ${String(res.basisIdx).padEnd(4)} | ${String(res.wordPattern.length).padEnd(7)} | ${row.join(' ')}`);
  }

  // Buscar distinguidores: algún Δrk[r] = 0 para r > 0
  let distinguishers = [];
  for (const res of results) {
    for (let r = 1; r < ROUNDS; r++) {
      if (res.weights[r] === 0) {
        distinguishers.push({ basisIdx: res.basisIdx, round: r });
      }
    }
    if (res.finalWeight === 0) {
      distinguishers.push({ basisIdx: res.basisIdx, round: 'final' });
    }
  }

  console.log('');
  if (distinguishers.length === 0) {
    console.log('  Sin distinguidores: ningún Δrk[r]=0 para r>0 ni whitening final.');
    console.log('  → El espacio nulo de rk[0] no sobrevive a la ronda 1.');
  } else {
    console.log(`  ALERTA: ${distinguishers.length} distinguidores encontrados:`);
    for (const d of distinguishers.slice(0, 20)) {
      console.log(`    vec ${d.basisIdx}, ronda ${d.round}: Δrk=0`);
    }
  }

  // Distribución mínima: para cada ronda, el menor peso entre todos los vectores
  console.log('\n  Peso mínimo de Δrk[r] por ronda (más bajo = peor para la seguridad):');
  const minPerRound = [];
  for (let r = 0; r < ROUNDS; r++) {
    let m = Infinity;
    for (const res of results) if (res.weights[r] < m) m = res.weights[r];
    minPerRound.push(m);
  }
  const sampleRounds = [0, 1, 2, 3, 4, 5, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128];
  for (const r of sampleRounds) {
    if (r === 128) {
      let m = Infinity;
      for (const res of results) if (res.finalWeight < m) m = res.finalWeight;
      console.log(`    r=${String(r).padStart(3)}: min peso = ${m}`);
    } else {
      console.log(`    r=${String(r).padStart(3)}: min peso = ${minPerRound[r]}`);
    }
  }

  return { results, distinguishers, minPerRound };
}

// =============================================================================
// Test 5: Avalancha (1 bit de K → bits de rk[r])
// =============================================================================
function testAvalanche() {
  console.log('\n=== Test 5: Avalancha (1 bit de K → bits de rk[r]) ===');
  const baseKey = new Uint8Array(KEY_BYTES);
  for (let i = 0; i < KEY_BYTES; i++) baseKey[i] = (i * 17 + 3) & 0xff;
  const baseSched = keyScheduleWithStates(baseKey);
  const baseBits = keyToBits(baseKey);

  // Para cada uno de los 512 bits de la clave, medir cuántos bits de rk[r] cambian
  const sampleRounds = [0, 1, 2, 4, 8, 16, 32, 64, 128];
  const perRound = sampleRounds.map(() => ({ sum: 0, min: Infinity, max: 0, count: 0 }));

  for (let bit = 0; bit < KEY_BYTES * 8; bit++) {
    const modBits = new Uint8Array(baseBits);
    modBits[bit] ^= 1;
    const modKey = new Uint8Array(KEY_BYTES);
    for (let i = 0; i < KEY_BYTES; i++) {
      let b = 0;
      for (let j = 0; j < 8; j++) b = (b << 1) | modBits[i*8 + j];
      modKey[i] = b;
    }
    const modSched = keyScheduleWithStates(modKey);

    for (let ri = 0; ri < sampleRounds.length; ri++) {
      const r = sampleRounds[ri];
      let diff;
      if (r === 128) diff = xorU32(modSched.rkFinal, baseSched.rkFinal);
      else diff = xorU32(modSched.addKeys[r], baseSched.addKeys[r]);
      const w = weightU32(diff);
      perRound[ri].sum += w;
      perRound[ri].count++;
      if (w < perRound[ri].min) perRound[ri].min = w;
      if (w > perRound[ri].max) perRound[ri].max = w;
    }
  }

  console.log(`  ${'ronda'.padEnd(6)} | ${'media'.padEnd(7)} | ${'min'.padEnd(4)} | ${'max'.padEnd(4)} | ideal`);
  for (let ri = 0; ri < sampleRounds.length; ri++) {
    const r = sampleRounds[ri];
    const avg = perRound[ri].sum / perRound[ri].count;
    const ideal = r === 128 ? 128 : (r === 0 ? null : 128);
    const idealStr = ideal === null ? '(lineal)' : '128';
    console.log(`  ${String(r).padEnd(6)} | ${avg.toFixed(2).padEnd(7)} | ${String(perRound[ri].min).padEnd(4)} | ${String(perRound[ri].max).padEnd(4)} | ${idealStr}`);
  }
  console.log('\n  Nota: r=0 es lineal (avalancha baja esperada). De r=1 en adelante,');
  console.log('  el ideal es ~128/256 bits (50%). Si algún r tiene avalancha baja,');
  console.log('  hay falta de difusión en el key schedule.');
}

// =============================================================================
// Test 6: Búsqueda aleatoria de diferenciales de bajo peso
// =============================================================================
function testRandomDifferentials(numSamples) {
  console.log(`\n=== Test 6: Búsqueda aleatoria de diferenciales (${numSamples} muestras) ===`);
  console.log('  ΔK aleatorio con peso 1-4 → Δrk[r] mínimo por ronda');

  const baseKey = new Uint8Array(KEY_BYTES);
  for (let i = 0; i < KEY_BYTES; i++) baseKey[i] = (i * 19 + 5) & 0xff;
  const baseSched = keyScheduleWithStates(baseKey);

  const minPerRound = new Array(ROUNDS).fill(Infinity);
  let minFinal = Infinity;
  const bestSamples = [];  // (round, weight, keyPattern)

  for (let s = 0; s < numSamples; s++) {
    // Generar ΔK con peso 1-4 bits
    const dk = new Uint8Array(KEY_BYTES);
    const nBits = 1 + Math.floor(Math.random() * 4);
    for (let b = 0; b < nBits; b++) {
      const bytePos = Math.floor(Math.random() * KEY_BYTES);
      const bitPos = Math.floor(Math.random() * 8);
      dk[bytePos] |= (1 << bitPos) & 0xff;
    }
    // Aplicar ΔK a la clave base
    const modKey = new Uint8Array(KEY_BYTES);
    for (let i = 0; i < KEY_BYTES; i++) modKey[i] = baseKey[i] ^ dk[i];
    const modSched = keyScheduleWithStates(modKey);

    for (let r = 0; r < ROUNDS; r++) {
      const w = weightU32(xorU32(modSched.addKeys[r], baseSched.addKeys[r]));
      if (w < minPerRound[r]) minPerRound[r] = w;
    }
    const wf = weightU32(xorU32(modSched.rkFinal, baseSched.rkFinal));
    if (wf < minFinal) minFinal = wf;
  }

  console.log(`  ${'ronda'.padEnd(6)} | ${'min peso'.padEnd(9)}`);
  const sampleRounds = [0, 1, 2, 3, 4, 5, 6, 8, 12, 16, 24, 32, 64, 128];
  for (const r of sampleRounds) {
    if (r === 128) console.log(`  ${String(r).padEnd(6)} | ${minFinal}`);
    else console.log(`  ${String(r).padEnd(6)} | ${minPerRound[r]}`);
  }
  console.log('\n  Si min peso es 0 en alguna ronda, hay un diferencial que anula rk[r].');
  console.log('  Si es bajo (<10) en muchas rondas, el key schedule no difunde bien.');
}

// =============================================================================
// Test 7: Scan de claves débiles
// =============================================================================
function testWeakKeys() {
  console.log('\n=== Test 7: Scan de claves débiles ===');
  const patterns = [
    { name: 'all-zero',        key: (i) => 0x00 },
    { name: 'all-one',         key: (i) => 0xFF },
    { name: 'alternating-0xAA',key: (i) => 0xAA },
    { name: 'alternating-0x55',key: (i) => 0x55 },
    { name: 'increasing',      key: (i) => i & 0xFF },
    { name: 'pi-constants',    key: (i) => CONST[i % 8] & 0xFF },
  ];

  for (const p of patterns) {
    const key = new Uint8Array(KEY_BYTES);
    for (let i = 0; i < KEY_BYTES; i++) key[i] = p.key(i);
    const { addKeys, rkFinal } = keyScheduleWithStates(key);

    // Métricas:
    // - ¿rk[0] es cero o tiene peso bajo?
    const w0 = weightU32(addKeys[0]);
    // - ¿Cuántos round keys distintos hay entre sí? (si hay muy pocos, es malo)
    const unique = new Set();
    for (let r = 0; r < ROUNDS; r++) unique.add(Array.from(addKeys[r]).join(','));
    // - ¿Algún rk[r] es cero?
    let anyZero = false;
    for (let r = 0; r < ROUNDS; r++) if (weightU32(addKeys[r]) === 0) anyZero = true;
    if (weightU32(rkFinal) === 0) anyZero = true;

    console.log(`  ${p.name.padEnd(15)} | peso rk[0]=${String(w0).padStart(3)} | roundkeys únicas=${unique.size}/${ROUNDS} | ¿alguna cero?=${anyZero ? 'SÍ' : 'no'}`);
  }
}

// =============================================================================
// Main
// =============================================================================
function main() {
  console.log('=============================================================');
  console.log('  Auditoría del key schedule de MYSX-256/512');
  console.log('=============================================================');
  console.log('ADVERTENCIA: estos tests no demuestran seguridad. Solo descartan');
  console.log('debilidades obvias. El análisis completo requiere MILP/SAT.');

  const startTime = Date.now();

  const okVerify = testVerify();
  if (!okVerify) {
    console.log('\nFATAL: reimplementación no coincide con prod. Abortando.');
    process.exit(1);
  }

  testBijectivity();
  const nsResult = testNullSpaceRk0();
  testNullSpacePropagation(nsResult);
  testAvalanche();
  testRandomDifferentials(2000);
  testWeakKeys();

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  console.log(`\n=============================================================`);
  console.log(`  Tests completados en ${elapsed}s`);
  console.log(`=============================================================`);
  console.log('  Interpretación:');
  console.log('  - Si el espacio nulo de Δrk[0]=0 tiene dimensión d>0, hay 2^d-1');
  console.log('    patrones de palabra que anulan la primera subclave.');
  console.log('  - Si alguno de esos patrones da Δrk[r]=0 en r>0, es un');
  console.log('    distinguidor de claves relacionadas (debilidad seria).');
  console.log('  - Si la avalancha a r>=1 es ~50% pero la de r=0 es baja,');
  console.log('    el key schedule difunde a partir de la ronda 1.');
  console.log('  - Si min peso aleatorio es 0 o muy bajo, hay claves relacionadas');
  console.log('    que producen subclaves predecibles.');
}

main();