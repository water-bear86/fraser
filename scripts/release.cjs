'use strict';

// Snapshot a version tag, never the working directory. No install or build step.
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { execFileSync } = require('node:child_process');

function git(args, cwd) {
  return execFileSync('git', args, { cwd, maxBuffer: 64 * 1024 * 1024 });
}

function prepareRelease(tag, output) {
  const match = /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/.exec(tag || '');
  if (!match || match[0] !== tag || tag.length > 64) {
    throw new Error('Expected a stable version tag, such as v1.0.0');
  }
  const root = git(['rev-parse', '--show-toplevel']).toString().trim();
  const commit = git(['rev-parse', '--verify', '--end-of-options', 'refs/tags/' + tag + '^{commit}'], root).toString().trim();
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(commit)) throw new Error('Invalid source commit');

  const files = git(['ls-tree', '-r', '-z', '--full-tree', commit], root).toString().split('\0').filter(Boolean).map(entry => {
    const tab = entry.indexOf('\t');
    const [mode, type] = entry.slice(0, tab).split(' ');
    const name = entry.slice(tab + 1);
    if (!['100644', '100755'].includes(mode) || type !== 'blob') {
      throw new Error('Release trees must contain regular files, not symlinks or submodules');
    }
    if (tab < 0 || !name || /[\\\x00-\x1f\x7f:]/.test(name) || name.startsWith('/') || name.split('/').some(part => !part || ['.', '..', '.git'].includes(part))) {
      throw new Error('Unsafe release path: ' + JSON.stringify(name));
    }
    return name;
  });
  const required = [
    'index.html', 'app.js', 'wallet.js', 'server.js', 'README.md', 'GUIDE.md',
    'SECURITY.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'vendor/SHA256SUMS',
    'vendor/english.js', 'vendor/english.json', 'vendor/nacl-fast.min.js',
    'vendor/qrcode.js', 'vendor/sha3.min.js', 'assets/charcoal-grain.png'
  ];
  for (const file of required) {
    if (!files.includes(file)) throw new Error('Release is missing required file: ' + file);
  }

  const directory = path.resolve(root, output || 'dist');
  // Requiring a fresh directory prevents overwriting any earlier release files.
  if (fs.existsSync(directory)) throw new Error('Output directory already exists; choose a fresh directory');
  const archive = 'fraser-' + tag + '.zip';
  const bytes = git(['-c', 'core.attributesFile=', 'archive', '-9', '--format=zip', '--prefix=fraser-' + tag + '/', commit], root);
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  const metadata = {
    project: 'FRASER', repository: 'https://github.com/water-bear86/fraser',
    tag, commit, archive, sha256, bytes: bytes.length,
    git: git(['--version'], root).toString().trim(), node: process.version
  };
  const notes = [
    '# FRASER ' + tag, '',
    'Generate. Print. Fold. A buildless paper-wallet generator for SOL, ETH/EVM and BTC.', '',
    'Source commit: `' + commit + '`.', '',
    'Download **' + archive + '** and **SHA256SUMS** from the attached assets.',
    'The automatically generated Source code downloads are different archives.', '',
    'SHA-256 of `' + archive + '`:', '', '```text', sha256, '```', '',
    'Verify the ZIP before extracting it:', '',
    '```sh', '# macOS', 'shasum -a 256 -c SHA256SUMS', '',
    '# Linux', 'sha256sum --check SHA256SUMS', '```', '',
    'On Windows: `Get-FileHash .\\' + archive + ' -Algorithm SHA256`; compare the complete digest.', '',
    'After publication, verify the immutable GitHub release and this attached ZIP:', '',
    '```sh', 'gh release verify ' + tag + ' --repo water-bear86/fraser',
    'gh release verify-asset ' + tag + ' ' + archive + ' --repo water-bear86/fraser', '```', '',
    'Copy the verified ZIP to the offline machine and verify it again there. Extract the whole',
    'folder, then open index.html or use the optional loopback server. Read GUIDE.md first.', '',
    'This release adds security and release policies, CI/CodeQL checks, vendored-file',
    'digests, retained third-party notices, and verified-download instructions.',
    'The existing application UI, cryptography and runtime dependencies are preserved.', '',
    'Passing checks and release verification are not an independent cryptographic audit.',
    'No real recovery phrase, funded transaction, or physical printer-memory test is used.', '',
    'Vulnerabilities: https://github.com/water-bear86/fraser/security/advisories/new', ''
  ].join('\n');

  fs.mkdirSync(directory);
  fs.writeFileSync(path.join(directory, archive), bytes, { flag: 'wx' });
  fs.writeFileSync(path.join(directory, 'SHA256SUMS'), sha256 + '  ' + archive + '\n', { flag: 'wx' });
  fs.writeFileSync(path.join(directory, 'RELEASE.json'), JSON.stringify(metadata, null, 2) + '\n', { flag: 'wx' });
  fs.writeFileSync(path.join(directory, 'RELEASE_NOTES.md'), notes, { flag: 'wx' });
  return metadata;
}

if (require.main === module) {
  try {
    if (process.argv.length < 3 || process.argv.length > 4) throw new Error('Usage: node scripts/release.cjs v1.0.0 [fresh-output-directory]');
    console.log(JSON.stringify(prepareRelease(process.argv[2], process.argv[3]), null, 2));
  } catch (error) {
    console.error('Release preparation failed: ' + error.message);
    process.exitCode = 1;
  }
}

module.exports = { prepareRelease };
