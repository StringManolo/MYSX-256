'use strict';
process.env.MYSX_ENABLE_TEST = '1';
const crypto = require('crypto');
const T = require('./mysx.prod.js').TEST;
if (!T) throw new Error('TEST no disponible');

const sc = T._makeScratch();
const rnd = n => new Uint8Array(crypto.randomBytes(n));

// _encryptBlockCore devuelve un buffer compartido -> .slice()
const enc = (pt, sch, r, whiten = false) =>
  T._encryptBlockCore(pt, sch, r, sc, whiten).slice();

module.exports = { T, rnd, enc };
