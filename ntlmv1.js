'use strict';

const { ntHash, md5 } = require('./crypto-utils');
const { desEncryptBlock, expandDesKey } = require('./des');

// Parses a hashcat -m 5500 / NetNTLMv1 line:
// username::domain:LMresponse:NTresponse:serverChallenge
function parseNetNTLMv1(line) {
  const parts = line.trim().split(':');
  if (parts.length !== 6) {
    throw new Error('Unrecognized format: expected username::domain:LMresponse:NTresponse:serverChallenge');
  }
  const [username, , domain, lmHex, ntHex, challengeHex] = parts;

  if (!/^[0-9a-fA-F]{48}$/.test(lmHex)) throw new Error('Bad LM response field (expected 48 hex chars)');
  if (!/^[0-9a-fA-F]{48}$/.test(ntHex)) throw new Error('Bad NT response field (expected 48 hex chars)');
  if (!/^[0-9a-fA-F]{16}$/.test(challengeHex)) throw new Error('Bad server challenge field (expected 16 hex chars)');

  return {
    username,
    domain,
    lmResponse: Buffer.from(lmHex, 'hex'),
    ntResponse: ntHex.toLowerCase(),
    serverChallenge: Buffer.from(challengeHex, 'hex'),
  };
}

// The 3 DES keys used for a NetNTLMv1 response are derived from the 16-byte
// NT hash split into 7-byte thirds (the last third zero-padded).
function desKeysFromNtHash(nt) {
  const k1 = nt.subarray(0, 7);
  const k2 = nt.subarray(7, 14);
  const k3 = Buffer.concat([nt.subarray(14, 16), Buffer.alloc(5)]);
  return [expandDesKey(k1), expandDesKey(k2), expandDesKey(k3)];
}

function ntlmResponse(nt, challenge8) {
  const [k1, k2, k3] = desKeysFromNtHash(nt);
  return Buffer.concat([
    desEncryptBlock(k1, challenge8),
    desEncryptBlock(k2, challenge8),
    desEncryptBlock(k3, challenge8),
  ]);
}

function checkPassword(line, password) {
  const { username, domain, lmResponse, ntResponse, serverChallenge } = parseNetNTLMv1(line);
  const nt = ntHash(password);

  // Extended Session Security (NTLM2 Session): the LM response field holds
  // an 8-byte client challenge followed by 16 zero bytes. This is the same
  // heuristic hashcat/impacket use to auto-detect the ESS variant.
  const isESS = lmResponse.subarray(8, 24).equals(Buffer.alloc(16));

  let challenge;
  if (isESS) {
    const clientChallenge = lmResponse.subarray(0, 8);
    challenge = md5(Buffer.concat([serverChallenge, clientChallenge])).subarray(0, 8);
  } else {
    challenge = serverChallenge;
  }

  const computed = ntlmResponse(nt, challenge);

  return {
    username,
    domain,
    variant: isESS ? 'NTLMv1-ESS' : 'NTLMv1',
    match: computed.toString('hex') === ntResponse,
  };
}

module.exports = { checkPassword, parseNetNTLMv1 };
