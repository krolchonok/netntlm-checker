'use strict';

// Pure-JS MD4 (RFC 1320) — Node's OpenSSL build no longer exposes MD4,
// but NTOWF (the NT hash) is defined as MD4(UTF-16LE(password)).
function leftRotate(x, c) {
  return ((x << c) | (x >>> (32 - c))) >>> 0;
}

function md4(msgBuffer) {
  const msgLen = msgBuffer.length;
  const bitLen = BigInt(msgLen) * 8n;
  const padLen = (56 - ((msgLen + 1) % 64) + 64) % 64;
  const totalLen = msgLen + 1 + padLen + 8;

  const buf = Buffer.alloc(totalLen);
  msgBuffer.copy(buf, 0);
  buf[msgLen] = 0x80;
  buf.writeBigUInt64LE(bitLen, totalLen - 8);

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const s1 = [3, 7, 11, 19];
  const s2 = [3, 5, 9, 13];
  const s3 = [3, 9, 11, 15];
  const order2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
  const order3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
  const M = new Uint32Array(16);

  for (let offset = 0; offset < totalLen; offset += 64) {
    for (let i = 0; i < 16; i++) M[i] = buf.readUInt32LE(offset + i * 4);

    let A = a0, B = b0, C = c0, D = d0;

    for (let i = 0; i < 16; i++) {
      const f = (B & C) | (~B & D);
      const tmp = D;
      D = C; C = B;
      B = leftRotate((A + f + M[i]) >>> 0, s1[i % 4]);
      A = tmp;
    }

    for (let i = 0; i < 16; i++) {
      const k = order2[i];
      const g = (B & C) | (B & D) | (C & D);
      const tmp = D;
      D = C; C = B;
      B = leftRotate((A + g + M[k] + 0x5A827999) >>> 0, s2[i % 4]);
      A = tmp;
    }

    for (let i = 0; i < 16; i++) {
      const k = order3[i];
      const h = B ^ C ^ D;
      const tmp = D;
      D = C; C = B;
      B = leftRotate((A + h + M[k] + 0x6ED9EBA1) >>> 0, s3[i % 4]);
      A = tmp;
    }

    a0 = (a0 + A) >>> 0;
    b0 = (b0 + B) >>> 0;
    c0 = (c0 + C) >>> 0;
    d0 = (d0 + D) >>> 0;
  }

  const out = Buffer.alloc(16);
  out.writeUInt32LE(a0, 0);
  out.writeUInt32LE(b0, 4);
  out.writeUInt32LE(c0, 8);
  out.writeUInt32LE(d0, 12);
  return out;
}

module.exports = md4;
