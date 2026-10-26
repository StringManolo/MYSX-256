#!/usr/bin/env node
'use strict';
// set_calendar.js — Inyecta un calendario de rotación en mysx.prod.js
// Uso: node set_calendar.js CALENDAR_v02.txt
// Acepta: "MYSX_ROT_CAL=1,2,...,31" o "1,2,...,31" (una línea).

const fs = require('fs');

const path = process.argv[2];
if (!path) {
  console.error('Uso: node set_calendar.js <archivo>');
  process.exit(1);
}

const raw = fs.readFileSync(path, 'utf8').trim();
const line = raw.replace(/^MYSX_ROT_CAL\s*=\s*/, '').split(/\s+/)[0];
const table = line.split(',').map(s => parseInt(s.trim(), 10));

if (table.length !== 31 || table.some(Number.isNaN)) {
  console.error(`ERROR: esperado 31 enteros, encontrado ${table.length}`);
  process.exit(1);
}
const sorted = [...table].sort((a, b) => a - b);
for (let i = 0; i < 31; i++) {
  if (sorted[i] !== i + 1) {
    console.error('ERROR: el calendario no es permutación de 1..31');
    process.exit(1);
  }
}

const JS = 'mysx.prod.js';
let src = fs.readFileSync(JS, 'utf8');

const START = '// >>> V02_CALENDAR';
const END   = '// <<< V02_CALENDAR';
const startIdx = src.indexOf(START);
const endIdx   = src.indexOf(END);
if (startIdx < 0 || endIdx < 0 || endIdx < startIdx) {
  console.error(`ERROR: markers ${START} / ${END} no encontrados en ${JS}`);
  process.exit(1);
}

const replacement =
  `${START}\n` +
  `const V02_CALENDAR = Object.freeze(${JSON.stringify(table)});\n` +
  `${END}`;

const before = src.slice(0, startIdx);
const after  = src.slice(endIdx + END.length);
fs.writeFileSync(JS, before + replacement + after);

console.log(`OK: ${JS} actualizado con calendario de ${path}`);
console.log(`  valores: [${table.join(',')}]`);
