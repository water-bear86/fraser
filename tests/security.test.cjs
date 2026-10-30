'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const vm = require('node:vm');

const root = path.join(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
function attributes(tag) {
  return Object.fromEntries(Array.from(tag.matchAll(/([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g), match => [match[1].toLowerCase(), match[2] ?? match[3]]));
}

test('the application encoder protects text and quoted attributes', () => {
  const source = fs.readFileSync(path.join(root, 'app.js'), 'utf8');
  const match = /function esc\(s\) \{([\s\S]*?)\n  \}/.exec(source);
  assert.ok(match, 'test the actual application encoder');
  const encode = vm.runInNewContext('(function(s) {' + match[1] + '\n})', {}, { timeout: 1000 });
  assert.equal(encode('&<>"\''), '&amp;&lt;&gt;&quot;&#39;');
  assert.equal(encode('" onfocus="public fixture'), '&quot; onfocus=&quot;public fixture');
  for (const chain of ['sol', 'eth', 'btc']) assert.equal(encode(chain), chain);
});

test('wallet CSP retains the reviewed offline boundaries', () => {
  const policies = Array.from(html.matchAll(/<meta\b[^>]*>/gi), match => attributes(match[0])).filter(attrs => attrs['http-equiv']?.toLowerCase() === 'content-security-policy');
  assert.equal(policies.length, 1);
  const entries = policies[0].content.split(';').map(value => value.trim().split(/\s+/)).filter(parts => parts[0]);
  assert.equal(new Set(entries.map(parts => parts[0])).size, entries.length, 'duplicate directives can hide an accidental policy change');
  const actual = Object.fromEntries(entries.map(([name, ...values]) => [name, values.sort()]));
  const expected = {
    'default-src': ["'none'"], 'script-src': ["'self'", 'file:'],
    'style-src': ["'unsafe-inline'"], 'img-src': ["'self'", 'data:', 'file:'],
    'connect-src': ["'none'"], 'form-action': ["'none'"], 'base-uri': ["'none'"]
  };
  assert.deepEqual(actual, expected);
});

function verifyRuntimeScripts(input) {
  let remaining = input;
  for (const source of [
    'vendor/nacl-fast.min.js', 'vendor/sha3.min.js', 'vendor/qrcode.js',
    'vendor/english.js', 'wallet.js', 'app.js'
  ]) {
    // Accept only reviewed declarations; malformed browser-tolerated tags fail closed.
    const declaration = '<script src="' + source + '"></script>';
    assert.equal(remaining.split(declaration).length - 1, 1, source);
    remaining = remaining.replace(declaration, '');
    assert.ok(fs.statSync(path.join(root, source)).isFile());
    assert.equal(fs.realpathSync(path.join(root, source)), path.join(fs.realpathSync(root), source));
  }
  assert.ok(!/<\/?script\b/i.test(remaining), 'unreviewed script markup');
}

test('runtime scripts are the reviewed local files, without inline executable code', () => {
  verifyRuntimeScripts(html);
  for (const match of html.matchAll(/url\((?:"([^"]*)"|'([^']*)'|([^)]*))\)/g)) {
    const url = (match[1] ?? match[2] ?? match[3]).trim();
    if (url.startsWith('data:image/svg+xml,')) continue;
    assert.equal(url, 'assets/charcoal-grain.png', 'new runtime assets need an explicit review');
    assert.ok(fs.statSync(path.join(root, url)).isFile());
  }
});

test('script guard rejects malformed endings, duplicate declarations and added inline code', () => {
  for (const ending of ['</script foo>', '</script\t\n bar>', '</SCRIPT/>']) {
    assert.throws(() => verifyRuntimeScripts(html.replace('</script>', ending)));
  }
  assert.throws(() => verifyRuntimeScripts(html + '<script src="app.js"></script>'));
  assert.throws(() => verifyRuntimeScripts(html + '<script>alert("public test fixture")</script>'));
});

test('vendored runtime files match the complete reviewed SHA-256 lock', () => {
  const expected = ['english.js', 'english.json', 'nacl-fast.min.js', 'qrcode.js', 'sha3.min.js'];
  const entries = fs.readFileSync(path.join(root, 'vendor/SHA256SUMS'), 'utf8').trimEnd().split('\n').map(line => {
    const match = /^([a-f0-9]{64})  ([a-zA-Z0-9.-]+)$/.exec(line);
    assert.ok(match, 'invalid vendor digest entry');
    return { digest: match[1], file: match[2] };
  });
  assert.deepEqual(entries.map(entry => entry.file).sort(), expected);
  assert.deepEqual(fs.readdirSync(path.join(root, 'vendor')).filter(file => file !== 'SHA256SUMS').sort(), expected);
  for (const entry of entries) {
    const file = path.join(root, 'vendor', entry.file);
    assert.ok(fs.lstatSync(file).isFile());
    assert.equal(createHash('sha256').update(fs.readFileSync(file)).digest('hex'), entry.digest, entry.file);
  }
});

test('browser and Node BIP-39 dictionaries agree on the same 2048 words', () => {
  const source = fs.readFileSync(path.join(root, 'vendor/english.js'), 'utf8');
  const match = /var BIP39_ENGLISH = (\[[\s\S]*\]);\s*$/.exec(source);
  assert.ok(match);
  const words = JSON.parse(fs.readFileSync(path.join(root, 'vendor/english.json'), 'utf8'));
  assert.deepEqual(JSON.parse(match[1]), words);
  assert.equal(words.length, 2048);
  assert.equal(new Set(words).size, 2048);
  assert.deepEqual(words.slice().sort(), words);
});

test('repository workflows pin actions and keep untrusted PRs away from privileged triggers', () => {
  for (const file of ['ci.yml', 'release.yml']) {
    const yaml = fs.readFileSync(path.join(root, '.github/workflows', file), 'utf8');
    const actions = Array.from(yaml.matchAll(/^\s*-?\s*uses:\s*([^\s#]+)/gm), match => match[1]);
    assert.ok(actions.length > 0);
    for (const action of actions) assert.match(action, /^[\w.-]+\/[\w./-]+@[0-9a-f]{40}$/);
    assert.ok(!yaml.includes('pull_request_target'));
    assert.match(yaml, /^permissions:\n  contents: read$/m);
  }
});
