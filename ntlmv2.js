'use strict';

const { utf16le, ntHash, hmacMd5 } = require('./crypto-utils');

// Parses a hashcat -m 5600 / NetNTLMv2 line:
// username::domain:serverChallenge:NTProofStr:blob
function parseNetNTLMv2(line) {
  const parts = line.trim().split(':');
  if (parts.length < 6) {
    throw new Error('Unrecognized format: expected username::domain:serverChallenge:NTProofStr:blob');
  }
  const [username, , domain, serverChallengeHex, ntProofStrHex, ...rest] = parts;
  const blobHex = rest.join(':');

  if (!/^[0-9a-fA-F]{16}$/.test(serverChallengeHex)) throw new Error('Bad server challenge field');
  if (!/^[0-9a-fA-F]{32}$/.test(ntProofStrHex)) throw new Error('Bad NTProofStr field');
  if (!/^[0-9a-fA-F]+$/.test(blobHex)) throw new Error('Bad blob field');

  return {
    username,
    domain,
    serverChallenge: Buffer.from(serverChallengeHex, 'hex'),
    ntProofStr: ntProofStrHex.toLowerCase(),
    blob: Buffer.from(blobHex, 'hex'),
  };
}

function checkPassword(line, password) {
  const { username, domain, serverChallenge, ntProofStr, blob } = parseNetNTLMv2(line);

  const nt = ntHash(password);
  const identity = utf16le(username.toUpperCase() + domain);
  const ntlmv2Hash = hmacMd5(nt, identity);
  const proof = hmacMd5(ntlmv2Hash, Buffer.concat([serverChallenge, blob]));

  return {
    username,
    domain,
    variant: 'NTLMv2',
    match: proof.toString('hex') === ntProofStr,
  };
}

module.exports = { checkPassword, parseNetNTLMv2 };
