'use strict';

const ntlmv1 = require('./ntlmv1');
const ntlmv2 = require('./ntlmv2');

// Both formats share the shape username::domain:F1:F2:F3(...).
// NetNTLMv1  (hashcat -m 5500): F1=LMresponse(48 hex) F2=NTresponse(48 hex) F3=serverChallenge(16 hex)
// NetNTLMv2  (hashcat -m 5600): F1=serverChallenge(16 hex) F2=NTProofStr(32 hex) F3=blob(hex, variable)
function detectVariant(line) {
  const parts = line.trim().split(':');
  if (parts.length < 6) return null;
  const [, , , f1, f2] = parts;

  if (/^[0-9a-fA-F]{16}$/.test(f1) && /^[0-9a-fA-F]{32}$/.test(f2)) return 'v2';
  if (parts.length === 6 && /^[0-9a-fA-F]{48}$/.test(f1) && /^[0-9a-fA-F]{48}$/.test(f2)) return 'v1';
  return null;
}

function checkPassword(line, password) {
  const variant = detectVariant(line);
  if (variant === 'v2') return ntlmv2.checkPassword(line, password);
  if (variant === 'v1') return ntlmv1.checkPassword(line, password);
  throw new Error(
    'Unrecognized hash format. Expected NetNTLMv1 (hashcat -m 5500): user::domain:LMresponse:NTresponse:challenge, ' +
      'or NetNTLMv2 (hashcat -m 5600): user::domain:challenge:NTProofStr:blob'
  );
}

module.exports = { checkPassword, detectVariant };
