# NetNTLM Checker

A small Windows 95-styled web tool for checking whether a guessed password
matches a captured NetNTLMv1 / NetNTLMv1-ESS / NetNTLMv2 hash
(the same formats used by `hashcat -m 5500` / `-m 5600`, or produced by tools
like Responder). All hashing runs locally — nothing is sent anywhere.

Use it only on hashes you're authorized to test (your own accounts, or an
engagement you have permission for).

## Two ways to run it

### 1. Standalone, no server (`standalone.html`)

Just open the file directly in a browser — double-click it, or
`file:///path/to/standalone.html`. Everything (MD4, DES, MD5/HMAC-MD5) runs
in pure JS in the tab; there's no backend and no network calls, so it works
offline.

### 2. Local web server (`server.js`)

```
npm install
npm start          # listens on 0.0.0.0:3000 by default
```

Override the port/host with env vars:

```
PORT=3141 HOST=127.0.0.1 npm start
```

Open `http://localhost:<port>/` (or the machine's LAN IP, if you want to
check it from another device).

## Hash formats

- **NetNTLMv1** (`hashcat -m 5500`, including the ESS/NTLM2-Session variant):
  `user::domain:LMresponse:NTresponse:serverChallenge`
- **NetNTLMv2** (`hashcat -m 5600`):
  `user::domain:serverChallenge:NTProofStr:blob`

The format is auto-detected from the field lengths — paste either kind into
the same box.

## Why pure-JS crypto

Both the Node server and the standalone HTML implement MD4 and single-DES
themselves (`md4.js`, `des.js`) instead of using Node's `crypto` module or
the browser's Web Crypto API, because neither exposes MD4 or raw DES
anymore (OpenSSL 3 dropped them as legacy, and Web Crypto never had them) —
yet both are required by the NTLM spec. Each primitive is verified against
its official test vectors (RFC 1320 for MD4, FIPS 46-3 for DES, RFC 1321 for
MD5) — see the inline comments for where.

## Files

| File | Purpose |
|---|---|
| `standalone.html` | Self-contained, no-server version |
| `server.js` | Express app (UI + `/check`, `/check/live`) |
| `ntlm.js` | Format detection + dispatch to v1/v2 |
| `ntlmv1.js` / `ntlmv2.js` | Per-variant verification logic |
| `des.js` / `md4.js` / `crypto-utils.js` | Crypto primitives (server side) |
