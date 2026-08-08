# NetNTLM Checker

A small static web tool for checking whether a guessed password matches a
captured NetNTLMv1 / NetNTLMv1-ESS / NetNTLMv2 hash (the same formats used
by `hashcat -m 5500` / `-m 5600`, or produced by tools like Responder). All
hashing runs in your browser — nothing is sent anywhere.

Use it only on hashes you're authorized to test (your own accounts, or an
engagement you have permission for).

## Usage

Just open `index.html` — double-click it, or `file:///path/to/index.html`.
Everything (MD4, DES, MD5/HMAC-MD5) runs in pure JS in the tab; there's no
backend and no network calls, so it works fully offline.

It's also a plain static file, so it can be hosted anywhere that serves
static assets (GitHub Pages, S3, nginx, ...) with zero configuration.

## Hash formats

- **NetNTLMv1** (`hashcat -m 5500`, including the ESS/NTLM2-Session variant):
  `user::domain:LMresponse:NTresponse:serverChallenge` — or just a bare
  48-hex NT response, which assumes the conventional fixed challenge
  `1122334455667788` used by public NetNTLMv1 lookup services.
- **NetNTLMv2** (`hashcat -m 5600`):
  `user::domain:serverChallenge:NTProofStr:blob`

The format is auto-detected from the field lengths — paste any of the above
into the same box.

## Why pure-JS crypto

`index.html` implements MD4 and single-DES itself instead of relying on the
browser's Web Crypto API, because Web Crypto never exposed either (MD5/HMAC-MD5
it does through workarounds, but MD4 and raw DES aren't available at all) —
yet both are required by the NTLM spec. Each primitive is verified against
its official test vectors (RFC 1320 for MD4, FIPS 46-3 for DES, RFC 1321 for
MD5) — see the inline comments for where.

## Files

| File | Purpose |
|---|---|
| `index.html` | The entire app — UI, styling, and all crypto logic |
| `og.png` | Link-preview image (Open Graph / Telegram / Twitter) |
