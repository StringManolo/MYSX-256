process.env.MYSX_ENABLE_TEST = '1'; // debe ir ANTES del require
const fs = require('fs');
const crypto = require('crypto');
const MYSX = require('../mysx.prod.js');

const N_FILES = 100;
const BITS_PER_FILE = 1_000_000;
const BYTES_PER_FILE = BITS_PER_FILE / 8; // 125000

if (!MYSX.TEST) throw new Error('TEST API no disponible');
fs.mkdirSync('nist_input', { recursive: true });

for (let f = 0; f < N_FILES; f++) {
  const key   = crypto.randomBytes(64);   // 512 bits
  const nonce = crypto.randomBytes(16);   // 128 bits
  const zeros = new Uint8Array(BYTES_PER_FILE);
  const ks    = MYSX.TEST._ctrXor(zeros, key, nonce); // keystream puro
  const name  = `nist_input/data${String(f).padStart(3, '0')}`;
  fs.writeFileSync(name, Buffer.from(ks));
  process.stdout.write(`\r${f + 1}/${N_FILES}`);
}
console.log('\nListo: nist_input/ con 100 ficheros de 1.000.000 bits.');
