'use strict';

const crypto = require('crypto');
const md4 = require('./md4');

function utf16le(str) {
  return Buffer.from(str, 'utf16le');
}

// NTOWF / NT hash: MD4(UTF-16LE(password))
function ntHash(password) {
  return md4(utf16le(password));
}

function hmacMd5(key, data) {
  return crypto.createHmac('md5', key).update(data).digest();
}

function md5(data) {
  return crypto.createHash('md5').update(data).digest();
}

module.exports = { utf16le, ntHash, hmacMd5, md5 };
