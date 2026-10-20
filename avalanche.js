'use strict';
const fs = require('fs');
const { T, rnd, enc } = require('./lab');

function avalanche(r, N, whiten = false) {
  const cnt = new Uint32Array(256 * 256);
  for (let n = 0; n < N; n++) {
    const sch = T._keySchedule(rnd(64));
    const pt = rnd(32);
    const c0 = enc(pt, sch, r, whiten);
    for (let i = 0; i < 256; i++) {
      const p2 = pt.slice();
      p2[i >> 3] ^= 1 << (i & 7);
      const c1 = enc(p2, sch, r, whiten);
      for (let j = 0; j < 256; j++) {
        if (((c0[j >> 3] ^ c1[j >> 3]) >> (j & 7)) & 1) cnt[i * 256 + j]++;
      }
    }
  }
  let minReach = 256, minReachBit = -1;
  for (let i = 0; i < 256; i++) {
    let reach = 0;
    for (let j = 0; j < 256; j++) if (cnt[i * 256 + j] > 0) reach++;
    if (reach < minReach) { minReach = reach; minReachBit = i; }
  }
  let chi2 = 0, maxAbsZ = 0, maxCell = null;
  for (let i = 0; i < 256; i++) {
    for (let j = 0; j < 256; j++) {
      const c = cnt[i * 256 + j];
      const d = c - N / 2;
      chi2 += d * d / (N / 4);
      const z = Math.abs(d) / Math.sqrt(N / 4);
      if (z > maxAbsZ) { maxAbsZ = z; maxCell = [i, j]; }
    }
  }
  const df = 65536;
  const zChi = (chi2 - df) / Math.sqrt(2 * df);
  return {
    r, whiten,
    minReach, minReachBit,
    maxAbsZ: +maxAbsZ.toFixed(2), maxCell,
    zChi: +zChi.toFixed(2)
  };
}

const N = 2000;
const maxR = 24;
const rows = [];
const t0 = Date.now();
console.log('r | minReach | minBit | maxAbsZ | maxCell   | zChi');
console.log('--+----------+--------+---------+-----------+------');
for (let r = 1; r <= maxR; r++) {
  const a = avalanche(r, N);
  rows.push(a);
  const line = `${String(a.r).padStart(2)} | ${String(a.minReach).padStart(8)} | ` +
               `${String(a.minReachBit).padStart(6)} | ${String(a.maxAbsZ).padStart(7)} | ` +
               `${JSON.stringify(a.maxCell).padEnd(9)} | ${String(a.zChi).padStart(5)}`;
  console.log(line);
}
const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
console.log(`\nTiempo: ${elapsed}s`);

// CSV para el paper
const csv = 'r,N,whiten,minReach,minReachBit,maxAbsZ,maxCellI,maxCellJ,zChi\n' +
  rows.map(a => `${a.r},${N},${a.whiten},${a.minReach},${a.minReachBit},${a.maxAbsZ},${a.maxCell[0]},${a.maxCell[1]},${a.zChi}`).join('\n');
fs.writeFileSync('avalanche.csv', csv + '\n');
console.log('Escrito avalanche.csv');
