'use strict';

// Packaging tests use Git and unzip, with disposable repositories and no secrets.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { execFileSync, spawnSync } = require('node:child_process');
const script = path.join(__dirname, '..', 'scripts', 'release.cjs');
const required = [
  'index.html', 'app.js', 'wallet.js', 'server.js', 'README.md', 'GUIDE.md',
  'SECURITY.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'vendor/SHA256SUMS',
  'vendor/english.js', 'vendor/english.json', 'vendor/nacl-fast.min.js',
  'vendor/qrcode.js', 'vendor/sha3.min.js', 'assets/charcoal-grain.png'
];

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'fraser-release-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const env = { ...process.env, GIT_CONFIG_GLOBAL: os.devNull, GIT_CONFIG_NOSYSTEM: '1' };
  const git = (args, input) => execFileSync('git', args, { cwd: directory, env, input, encoding: 'utf8' }).trim();
  git(['init', '--quiet', '--initial-branch=main']);
  git(['config', 'user.name', 'FRASER release fixture']);
  git(['config', 'user.email', 'fixture@example.invalid']);
  for (const file of required) {
    fs.mkdirSync(path.dirname(path.join(directory, file)), { recursive: true });
    fs.writeFileSync(path.join(directory, file), 'committed fixture: ' + file + '\n');
  }
  git(['add', '.']);
  git(['-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'Public packaging fixture']);
  git(['tag', 'v1.0.0']);
  const run = (tag, output) => spawnSync(process.execPath, [script, tag, output], { cwd: directory, env, encoding: 'utf8' });
  return { directory, git, run };
}

test('release ZIP contains tagged bytes and omits dirty files and local drafts', t => {
  const { directory, git, run } = fixture(t);
  const commit = git(['rev-parse', 'HEAD']);
  fs.writeFileSync(path.join(directory, 'wallet.js'), 'uncommitted fixture change\n');
  fs.mkdirSync(path.join(directory, 'docs'));
  fs.writeFileSync(path.join(directory, 'docs', 'draft.md'), 'untracked fixture\n');
  const output = path.join(directory, 'release-one');
  const result = run('v1.0.0', output);
  assert.equal(result.status, 0, result.stderr);
  const metadata = JSON.parse(fs.readFileSync(path.join(output, 'RELEASE.json'), 'utf8'));
  assert.equal(metadata.commit, commit);
  const archive = path.join(output, metadata.archive);
  const bytes = fs.readFileSync(archive);
  const digest = createHash('sha256').update(bytes).digest('hex');
  assert.equal(metadata.sha256, digest);
  assert.equal(fs.readFileSync(path.join(output, 'SHA256SUMS'), 'utf8'), digest + '  fraser-v1.0.0.zip\n');
  const names = execFileSync('unzip', ['-Z1', archive], { encoding: 'utf8' }).trim().split('\n');
  assert.ok(names.every(name => name.startsWith('fraser-v1.0.0/')));
  assert.ok(!names.some(name => name.includes('/docs/') || name.includes('/.git/')));
  assert.equal(execFileSync('unzip', ['-p', archive, 'fraser-v1.0.0/wallet.js'], { encoding: 'utf8' }), 'committed fixture: wallet.js\n');
  assert.equal(run('v1.0.0', path.join(directory, 'release-two')).status, 0);
  assert.ok(fs.readFileSync(path.join(directory, 'release-two', metadata.archive)).equals(bytes));
  const altered = Buffer.from(bytes);
  altered[12] ^= 1;
  assert.notEqual(createHash('sha256').update(altered).digest('hex'), digest);
  const retry = run('v1.0.0', output);
  assert.notEqual(retry.status, 0);
  assert.match(retry.stderr, /already exists/);
  assert.ok(fs.readFileSync(archive).equals(bytes), 'existing output must remain untouched');
});

test('release input rejects malformed versions, absent tags and incomplete trees', t => {
  const { directory, git, run } = fixture(t);
  const output = path.join(directory, 'must-not-exist');
  for (const tag of ['main', '--help', 'v1.0', 'v01.0.0', 'v1.0.0-rc.1', 'v1.0.0\n', 'v1.0.0/../../other', 'v99.0.0']) {
    assert.notEqual(run(tag, output).status, 0, JSON.stringify(tag));
    assert.equal(fs.existsSync(output), false);
  }
  git(['rm', 'vendor/sha3.min.js']);
  git(['-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'Incomplete fixture']);
  git(['tag', 'v2.0.0']);
  const result = run('v2.0.0', output);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /missing required file/);
});

for (const mode of ['120000', '160000']) {
  test('release rejects nonregular Git entries: ' + mode, t => {
    const { directory, git, run } = fixture(t);
    const object = mode === '120000' ? git(['hash-object', '-w', '--stdin'], 'README.md') : git(['rev-parse', 'HEAD']);
    git(['update-index', '--add', '--cacheinfo', mode + ',' + object + ',unsafe-entry']);
    git(['-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'Nonregular fixture']);
    git(['tag', 'v2.0.0']);
    const result = run('v2.0.0', path.join(directory, 'must-not-exist'));
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /regular files/);
  });
}
