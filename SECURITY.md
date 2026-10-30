# Security Policy

## Supported Versions and Reporting

Security fixes are delivered in new releases of the latest stable version.
Use the attached, checksummed release ZIP for offline use. The main branch is a
development branch and is not a substitute for a verified release.

Report vulnerabilities privately at:
https://github.com/water-bear86/fraser/security/advisories/new

Include the affected version or commit, a description of the security impact,
and minimal reproduction steps using public test vectors or disposable wallets.
Never include a real recovery phrase, private key, funded wallet, access token,
or personal information in a report. Use ordinary GitHub issues for nonsensitive
support. Do not publish an unfixed exploit or sensitive report in a public issue.
Reports are handled on a best-effort basis; no response deadline or bounty is
promised.

## System and Scope

FRASER is a buildless browser application for generating, verifying, and printing
Solana, Ethereum/EVM, and Bitcoin paper wallets. It does not broadcast
transactions, connect to wallets, or provide a backend custody service.

This policy covers index.html, app.js, wallet.js, server.js, vendor/, the print
and QR output, tests, release tooling, GitHub workflows, release assets, and the
hosted site's delivery of those files. Third-party code is in scope when its
use in FRASER creates a reachable security problem.

The optional Node server serves the trusted application directory on
127.0.0.1 using GET and HEAD. GitHub Pages hosts the public preview and source
delivery. Actual offline use requires a verified download on a trustworthy
machine disconnected from networks.

## Threat Model and Trust Boundaries

Protected assets include entropy, mnemonics, optional BIP-39 passphrases,
derived seeds, private keys, the integrity of deposit addresses and QR codes,
and the integrity and origin of downloaded release files.

Relevant attacker-controlled inputs include phrases and account/path arguments,
HTTP request paths, contributions, dependency updates, workflow inputs, and
replacement or modified downloads. Review their effects across the UI,
cryptography module, local file server, and release pipeline.

The browser, operating system, printer, physical storage, and maintainer account
are separate trust boundaries. The application cannot make a compromised host
safe, securely erase all copies from JavaScript memory, or control printer
storage. A checksum alone does not authenticate a release if an attacker can
replace both the ZIP and its expected checksum.

## Security Invariants

1. Wallet generation uses the platform cryptographic random-number generator.
   There must be no predictable entropy source, fixed seed, or silent fallback.
2. Mnemonic validation and key derivation preserve the documented standards,
   chain paths, account semantics, and published test vectors. Invalid account
   indices and noncanonical path segments must fail rather than wrap, truncate,
   or silently derive a different wallet.
3. Application code must not persist or transmit secret wallet material through
   storage, URLs, network requests, logs, analytics, telemetry, downloads, or
   unrequested clipboard operations. Reveal and print are explicit user actions.
4. Screen redaction is visual protection. The print view intentionally contains
   the phrase, and the phrase remains available in the page's memory. It must
   not be described as isolated from same-process code.
5. User-controlled text must not become executable markup or script. Public and
   printed addresses, chain labels, paths, and QR payloads must agree with the
   wallet actually derived from the phrase.
6. The local server stays loopback-only, read-only, and limited to GET/HEAD.
   Malformed URL encodings and NULs must be handled without crashing it, and
   request-path traversal must not escape its intended root.
7. Runtime scripts and assets remain locally bundled. The existing CSP is a
   defense layer, including connect-src 'none'; weakening it, adding remote
   code, or adding new data egress requires explicit security review.
8. Release ZIPs are produced from the exact tagged Git commit. Untracked files,
   local drafts, credentials, generated wallets, and machine-specific state
   must not enter the archive. The published SHA-256 must match the uploaded
   ZIP's actual bytes.
9. Published versions are never silently replaced. Corrections use a new tag
   and release. Immutable releases remain enabled, with the archive and checksum
   attached before publication.
10. Vendored changes require an explicit diff, updated digests, upstream
    provenance, retained license notices, and passing tests. Workflow actions
    are pinned to reviewed full commit SHAs; untrusted pull-request code must
    not receive release credentials or a write-capable execution context.

## Change and Release Controls

Changes use pull requests and must pass the required tests, security-invariant
checks, vendor-digest checks, and code scanning before merging. CODEOWNERS routes
review to the maintainer. FRASER currently has a single maintainer, so these
controls do not claim independent review of the maintainer's own changes.

Only an authorized maintainer creates release tags and publishes releases.
Release automation prepares a draft with its ZIP, SHA256SUMS, source commit,
and validation results. The maintainer verifies the downloaded ZIP before
publication. The release guide documents checksum and signed release
verification, including rechecking the file after transfer to an offline device.

## Reportable Findings and Severity Context

Report biased or predictable generation, incorrect or attacker-influenced key
derivation, secret disclosure, unintended persistence, script injection, address
or QR substitution, server boundary violations, and release or workflow
tampering. Assess impact using a realistic attacker-controlled path.

Secret compromise and deposit-address substitution can cause irreversible loss
even if the application is usually used offline. A loopback-only availability
problem should not be described as an internet-facing service compromise
without evidence of that exposure.

The BIP-39 dictionary and explicitly identified public test vectors are public
data. Their presence alone is not evidence of a leaked wallet. Diagnostics that
read storage names are not, by themselves, writes or transmission of secrets;
trace the actual data flow.

## Limitations and Exclusions

Passing tests, code scanning, a matching checksum, and a valid release
attestation do not constitute an independent cryptographic audit or a guarantee
against loss. The JavaScript implementation does not promise constant-time
execution or guaranteed memory zeroization.

This policy introduces no blanket finding-class exclusions and accepts no
identified exploitable vulnerability. Environmental assumptions do not suppress
a concrete application vulnerability that crosses one of the boundaries above.
