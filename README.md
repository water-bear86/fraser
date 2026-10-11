# FRASER — Solana Paper Wallet

**Foldable Recovery And Seed Export Renderer.**

*Generate. Print. Fold.*

FRASER generates Solana keypairs
**entirely in the browser** — nothing is ever written to disk, stored, or
transmitted.

## Run it

```sh
node server.js          # http://127.0.0.1:8123  (loopback only)
```

or just open `index.html` straight from disk — the page is buildless and
fully self-contained, so it also works from a USB stick on an air-gapped
machine.

## What it does

- Generates a BIP-39 secret phrase (24 or 12 words) from
  `crypto.getRandomValues` (the OS CSPRNG).
- Derives the Solana keypair via PBKDF2-SHA512 → SLIP-0010 ed25519 at
  **m/44'/501'/n'/0'** — the same path Phantom, Solflare, and the original
  Sollet use, so the phrase restores anywhere.
- Shows the address (+ QR), the phrase, and the private key in both Phantom
  (base58) and `solana-keygen` (JSON array) formats.
- Prints a fold-in-half paper wallet (public side / secret side).
- "Verify a phrase" re-derives an address from a written-down phrase to
  confirm a printed wallet before funding it.

## Why keys can't leak

- **No persistence**: no localStorage, no cookies, no IndexedDB, no files.
  Keys exist only in page memory; "Clear everything" reloads the page.
- **No network**: the page ships a Content-Security-Policy with
  `connect-src 'none'` — the browser itself refuses to transmit anything.
  The server is loopback-only, static, GET-only, and logs nothing.
- **No build step, no dependencies to audit at install time**: the only
  vendored code is `tweetnacl` (public domain), `qrcode-generator` (MIT),
  and the standard BIP-39 English wordlist, all pinned in `vendor/`.

## Correctness

`wallet.js` runs identically in Node and the browser. The derivation is
cross-checked against the established ecosystem libraries
(`bip39`, `ed25519-hd-key`, `tweetnacl`, `bs58`), including the standard
BIP-39 test vector (`abandon … about` →
`HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk`) and randomized round-trips.

## Files

| file                     | purpose                                    |
|--------------------------|--------------------------------------------|
| `index.html`             | UI + print stylesheet                      |
| `app.js`                 | UI wiring (memory-only state)              |
| `wallet.js`              | BIP-39 / SLIP-0010 / base58 derivation     |
| `server.js`              | optional zero-dep loopback static server   |
| `vendor/nacl-fast.min.js`| tweetnacl 1.0.3 (public domain)            |
| `vendor/qrcode.js`       | qrcode-generator 1.4.4 (MIT)               |
| `vendor/english.js(.json)`| BIP-39 English wordlist (2048 words)      |

## Donate

If you found this to be useful, consider donating by sending magic internet monies to:

```text
sol: 79TNuyFNZWhDeFF1RUNA5Xk9Pccvb7xPYqLukBxCeWbb
evm: 0xa2c0abd1a1fcb5aee12f80651ae7f646371a66ed
```
