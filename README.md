# FRASER — Solana Paper Wallet

**Foldable Recovery And Seed Export Renderer.**

*Generate. Print. Fold.*

FRASER generates paper wallets for **Solana, Ethereum/EVM, and Bitcoin**
from one secret phrase, **entirely in the browser**. Nothing is ever
written to disk, stored, or transmitted.

New to cold storage? Start with the **[user guide](GUIDE.md)**: offline
setup, funding, getting back out, cleanup, and how many copies to make.

## Run it

```sh
node server.js          # http://127.0.0.1:8123  (loopback only)
```

or just open `index.html` straight from disk. The page is buildless and
fully self-contained, so it also works from a USB stick on an air-gapped
machine.

## What it does

- Generates a BIP-39 secret phrase (24 or 12 words) from
  `crypto.getRandomValues` (the OS CSPRNG).
- Derives three chains from that one phrase, at the standard paths every
  major wallet uses, so it restores anywhere:
  - **SOL**: SLIP-0010 ed25519 at `m/44'/501'/n'/0'` (Phantom, Solflare)
  - **ETH/EVM**: BIP-32 secp256k1 at `m/44'/60'/0'/0/n` (MetaMask, Rabby),
    EIP-55 checksummed
  - **BTC**: BIP-84 native segwit at `m/84'/0'/0'/0/n` (Sparrow, Electrum),
    bech32 `bc1q…`
- Chains selector: one combined wallet covering all three chains, or a
  single-chain wallet so each chain gets its own independent phrase and
  can be restored later without exposing the others.
- Shows each address (+ scannable half-block QR), the phrase, and the
  private keys in wallet-import formats: base58 and `solana-keygen` JSON
  for SOL, hex for ETH, WIF for BTC.
- Prints a fold-in-half paper wallet: all three addresses with QRs on the
  public side, the secret phrase on the inside.
- "Verify a phrase" re-derives all three addresses from a written-down
  phrase to confirm a printed wallet before funding it.

## Why keys can't leak

- **No persistence**: no localStorage, no cookies, no IndexedDB, no files.
  Keys exist only in page memory; "Clear" reloads the page.
- **No network**: the page ships a Content-Security-Policy with
  `connect-src 'none'`, so the browser itself refuses to transmit anything.
  The page probes this live at boot. The server is loopback-only, static,
  GET-only, and logs nothing.
- **No build step, no dependencies to audit at install time**: the only
  vendored code is `tweetnacl` (public domain), `qrcode-generator` and
  `js-sha3` (MIT), and the standard BIP-39 English wordlist, all pinned in
  `vendor/`. secp256k1, BIP-32, RIPEMD-160, bech32, and WIF are implemented
  in `wallet.js` itself and cross-checked (below).

## Correctness

`wallet.js` runs identically in Node and the browser. Every chain's
derivation is cross-checked against the established ecosystem libraries:
`ethers` (ETH), `@scure/bip32` + `@noble/hashes` + `bech32` + `bs58check`
(BTC), and `bip39` + `ed25519-hd-key` + `tweetnacl` + `bs58` (SOL), over
randomized phrases and accounts plus the published test vectors. The
standard `abandon … about` phrase derives:

| chain | address |
|-------|---------|
| SOL | `HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk` |
| ETH | `0x9858EfFD232B4033E47d90003D41EC34EcaEda94` |
| BTC | `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu` (BIP-84 official vector) |

Type that phrase into "Verify a phrase" and the page must show exactly
these addresses; anything else means a corrupted copy.

## Files

| file                     | purpose                                    |
|--------------------------|--------------------------------------------|
| `index.html`             | UI + print stylesheet + social meta tags   |
| `app.js`                 | UI wiring (memory-only state)              |
| `wallet.js`              | BIP-39, SLIP-0010, BIP-32/84, secp256k1, keccak/EIP-55, bech32, WIF |
| `server.js`              | optional zero-dep loopback static server   |
| `og.png`                 | social preview card (rebuild: `social/card.html`) |
| `vendor/nacl-fast.min.js`| tweetnacl 1.0.3 (public domain)            |
| `vendor/qrcode.js`       | qrcode-generator 1.4.4 (MIT)               |
| `vendor/sha3.min.js`     | js-sha3 0.8.0 (MIT), keccak-256 for ETH    |
| `vendor/english.js(.json)`| BIP-39 English wordlist (2048 words)      |

## License

Copyright (C) 2026 Angus Durrie.

FRASER's original source code is licensed under the
[GNU General Public License, version 3](LICENSE) (`GPL-3.0-only`).
You may redistribute and/or modify it under version 3 of the GNU GPL
as published by the Free Software Foundation.

FRASER is provided without any warranty, including the implied warranties
of merchantability or fitness for a particular purpose. See `LICENSE`
for the full terms.

Bundled third-party libraries and wordlists retain their original
licenses and copyright notices.

## Donate

If you found this to be useful, consider donating by sending magic internet monies to:

```text
sol: 79TNuyFNZWhDeFF1RUNA5Xk9Pccvb7xPYqLukBxCeWbb
evm: 0xa2c0abd1a1fcb5aee12f80651ae7f646371a66ed
```
