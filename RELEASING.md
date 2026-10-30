# Releasing FRASER

Releases freeze the current application in a named ZIP from a version tag.
Published assets are immutable. Fixes require a new version; never replace an
old ZIP or move its published tag.

## Prerequisites and controls

The maintainer account must use strong authentication and protect its recovery
credentials. Keep private vulnerability reporting, secret scanning, push
protection, and immutable releases enabled. Do not add long-lived workflow
tokens.

Changes go through a pull request with successful Tests and CodeQL checks.
CODEOWNERS requests review from @water-bear86. With one maintainer, an author's
own PR can pass and merge; this is not independent review. External contributions
need maintainer review. Do not bypass a failing check to make a release.

CI uses Node.js 24, and packaging uses Node.js and Git. The full test suite also
uses unzip. The application itself still requires no package installation.
Vendored changes require upstream version/byte verification, license review,
and a deliberate update to vendor/SHA256SUMS.

## Prepare a version

1. Review the final diff, policy changes, licenses, and validation results.
   Keep the exact Donate section last in README.md. Do not include local drafts
   or generated wallet material in Git.
2. Merge the passing PR. Check that Tests and CodeQL succeed on the final main
   commit, and review any code-scanning alerts.
3. Choose a fresh stable version such as v1.0.0. Confirm it does not exist.
   Tag the reviewed main commit and push the tag:

   ```sh
   git switch main
   git pull --ff-only
   git tag -a v1.0.0 -m "FRASER v1.0.0"
   git push origin v1.0.0
   ```

   Version-tag creation and modification are restricted to administrators.
4. The Prepare release workflow reruns the tests, requires successful Tests and
   CodeQL checks on that exact commit, checks for open code-scanning alerts,
   and creates a draft with fraser-v1.0.0.zip, SHA256SUMS, and RELEASE.json.
   It uses an ephemeral write token only in the trusted draft job.
5. If automation fails, investigate before retrying. It does not overwrite an
   existing release. Confirm the tag, commit, previous job outputs, and draft
   asset state; do not automatically delete or replace anything.

## Local packaging

For inspection or a recovery workflow, use a fresh output directory:

```sh
node scripts/release.cjs v1.0.0 dist
```

The script requires an existing stable version tag. It packages the tagged Git
commit, even if the working directory contains local edits or untracked files.
It rejects symlinks, submodules, unsafe archive paths, and incomplete application
trees, and refuses an existing output directory.

The ZIP has one fraser-v1.0.0/ directory and records the source commit in its ZIP
comment. SHA256SUMS covers the completed ZIP. RELEASE.json records its tag,
commit, filename, size, digest, and packaging tool versions. RELEASE_NOTES.md
supplies the release description. These generated files belong in ignored dist/
or another fresh output directory, not in Git.

The digest is for the uploaded bytes. Identical output across arbitrary Git or
compression-library versions is not promised.

## Verify the actual draft download

Download the attached ZIP and SHA256SUMS from the draft using the maintainer
account. Run the checksum check in the download directory:

```sh
# macOS
shasum -a 256 -c SHA256SUMS

# Linux
sha256sum --check SHA256SUMS
```

On Windows, use Get-FileHash in PowerShell and compare the entire 64-character
SHA-256 digest. The automatic Source code ZIP is not the named release asset.

Inspect the ZIP's entries, check archive integrity, and extract into a fresh
directory. Compare every extracted file against the tagged Git tree and run
the extracted tests and local-asset checks. Confirm RELEASE.json identifies the
same source commit and archive digest. A disposable copy modified by one byte
must fail the checksum check.

Use public test vectors or disposable wallets only. Never fund release test
wallets, capture real phrases, or send secrets to a CI job.

## Publish and verify

Before publishing, confirm repository release immutability is enabled and all
assets are attached and verified. Publication locks the assets and version tag.
Obtain the release owner's final publication decision after presenting the
concrete draft, source commit, digest, and checks.

After publication, use a current GitHub CLI:

```sh
gh release verify v1.0.0 --repo water-bear86/fraser
gh release verify-asset v1.0.0 fraser-v1.0.0.zip --repo water-bear86/fraser
```

Download the published asset again and verify it. The signed release attestation
binds the uploaded assets, version tag, and source commit to the GitHub release.
It does not prove that the source is free of vulnerabilities or protect a
compromised generation machine.

Users should verify the ZIP on the download machine and again after transferring
it to an offline device. Report suspected tampering privately via SECURITY.md.

References:
- https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases
- https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/verify-release-integrity
