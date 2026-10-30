# FRASER: Multichain Paper Wallet

**Foldable Recovery And Seed Export Renderer.**

*Generate. Print. Fold.*

FRASER generates paper wallets for **Solana, Ethereum/EVM, and Bitcoin**
from one secret phrase, **entirely in the browser**. The application keeps
wallet material in page memory and does not intentionally persist or transmit it.

New to cold storage? Start with the **[user guide](GUIDE.md)**: offline
setup, funding, getting back out, cleanup, and how many copies to make.

## Download and verify

Get the attached **fraser-v1.0.0.zip** and **SHA256SUMS** from
[GitHub Releases](https://github.com/water-bear86/fraser/releases).
Use those named assets; GitHub's automatic "Source code" archives are different
files and will not match this checksum.

Put both files in the same directory and check the ZIP before extracting:

```sh
# macOS
shasum -a 256 -c SHA256SUMS

# Linux
sha256sum --check SHA256SUMS
```

On Windows, run `Get-FileHash .\fraser-v1.0.0.zip -Algorithm SHA256` in
PowerShell and compare its complete digest with `SHA256SUMS`. Stop if it differs.
Copy both files to the offline machine and verify again before extracting.

For the published immutable release, GitHub CLI can also verify the release
and that the local ZIP is its authentic attached asset:

```sh
gh release verify v1.0.0 --repo water-bear86/fraser
gh release verify-asset v1.0.0 fraser-v1.0.0.zip --repo water-bear86/fraser
```

A checksum needs a trusted expected value. Signed release verification adds
origin verification; neither check is an independent cryptographic audit.

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
- Derives three chains from that one phrase at these standard paths.
  When restoring, select a wallet that supports the printed path and account:
  - **SOL**: SLIP-0010 ed25519 at `m/44'/501'/n'/0'` (Phantom, Solflare)
  - **ETH/EVM**: BIP-32 secp256k1 at `m/44'/60'/0'/0/n` (MetaMask, Rabby),
    EIP-55 checksummed
  - **BTC**: BIP-84 native segwit at `m/84'/0'/0'/0/n` (Sparrow, Electrum),
    bech32 `bc1q…`
- Chains selector: one combined wallet covering all three chains, or any
  combination of them, so chains can live on independent phrases and be
  restored later without exposing the others. Toggling all three
  collapses back to all chains.
- Shows each address (+ scannable half-block QR), the phrase, and the
  private keys in wallet-import formats: base58 and `solana-keygen` JSON
  for SOL, hex for ETH, WIF for BTC.
- Prints a fold-in-half paper wallet: all three addresses with QRs on the
  public side, the secret phrase on the inside.
- "Verify a phrase" re-derives all three addresses from a written-down
  phrase to confirm a printed wallet before funding it.

## Security model and limits

- **Application state stays in memory**: no wallet writes to localStorage,
  cookies, IndexedDB, or downloaded files. "Clear" reloads the page. Browser
  memory, operating-system swap/crash dumps, and printer spooling remain outside
  this application's control. Redaction hides the screen; print markup still
  contains the phrase, and JavaScript cannot guarantee memory zeroization.
- **Local operation**: runtime scripts and assets are bundled. The CSP includes
  `connect-src 'none'` and is probed at boot. This is one defense layer, not a
  guarantee against malicious replacement code or a compromised browser.
  The optional server is static, loopback-only, GET/HEAD-only, and logs no requests.
  The hosted page is online; actual air-gapped use requires disconnecting the
  machine and using the verified download.
- **No build step, no dependencies to audit at install time**: the only
  vendored code is `tweetnacl` (public domain), `qrcode-generator` and
  `js-sha3` (MIT), and the standard BIP-39 English wordlist, all pinned in
  `vendor/`. secp256k1, BIP-32, RIPEMD-160, bech32, and WIF are implemented
  in `wallet.js` itself. See [third-party notices](THIRD_PARTY_NOTICES.md)
  for licenses and upstream versions, and `vendor/SHA256SUMS` for the pinned bytes.

Read [SECURITY.md](SECURITY.md) for the threat model, reporting channel, and
security invariants. Report vulnerabilities
[privately](https://github.com/water-bear86/fraser/security/advisories/new),
using public test vectors or disposable wallets. Never send a real phrase or key.

## Correctness

The committed tests check published chain addresses and SLIP-0010 vectors,
account/path validation, chain subsets, generation, server resilience, CSP and
vendored-file integrity, and release packaging. They run without installing
packages, using Node.js 24+, Git, and `unzip`:

```sh
node --test --test-reporter=spec tests/*.test.cjs
```

For the public 12-word test vector (eleven `abandon` words followed by `about`),
account zero derives these addresses. **Never fund this public test wallet.**

| chain | address |
|-------|---------|
| SOL | `HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk` |
| ETH | `0x9858EfFD232B4033E47d90003D41EC34EcaEda94` |
| BTC | `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu` (BIP-84 official vector) |

At account zero, "Verify a phrase" must show these addresses for that exact
test vector. A mismatch needs investigation before using the copy. Passing
these checks is not an independent security or cryptographic audit.

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
| `vendor/SHA256SUMS`      | reviewed hashes of bundled third-party files |
| `SECURITY.md`           | security model and private reporting policy |
| `RELEASING.md`          | maintainer release and verification procedure |
| `scripts/release.cjs`   | tagged-source ZIP and SHA-256 packaging     |

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
