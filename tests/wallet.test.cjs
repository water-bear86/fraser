'use strict';

// Public test vectors only. Never fund the wallets produced by these fixtures.
// Run from the repository with: node --test tests/*.test.cjs
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto, createHash } = require('node:crypto');

const root = path.join(__dirname, '..');
const mnemonic = Array(11).fill('abandon').concat('about').join(' ');
const nacl = require(path.join(root, 'vendor/nacl-fast.min.js'));
const keccak256 = require(path.join(root, 'vendor/sha3.min.js')).keccak256;
const wordlist = JSON.parse(fs.readFileSync(path.join(root, 'vendor/english.json'), 'utf8'));
const source = fs.readFileSync(path.join(root, 'wallet.js'), 'utf8');

function loadWallet() {
  let entropyCalls = 0;
  const context = vm.createContext({
    TextEncoder, Uint8Array, nacl, keccak256, BIP39_ENGLISH: wordlist,
    crypto: {
      subtle: webcrypto.subtle,
      getRandomValues(bytes) {
        entropyCalls++;
        return bytes.fill(0);
      }
    }
  });
  vm.runInContext(source, context, { filename: 'wallet.js' });
  return { context, entropyCalls: () => entropyCalls };
}

function fingerprint(value) {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

const invalidAccounts = [
  ['hardened-bit boundary', 0x80000000], ['32-bit overflow', 0x100000000],
  ['unsafe integer', Number.MAX_SAFE_INTEGER + 1], ['negative', -1],
  ['fraction', 1.5], ['NaN', NaN], ['infinity', Infinity], ['negative infinity', -Infinity],
  ['numeric string', '1'], ['numeric prefix', '1junk'], ['empty string', ''],
  ['path injection', "1'/0"], ['null', null], ['false', false], ['true', true],
  ['array', [1]], ['object', { valueOf: () => 1 }], ['boxed number', new Number(1)],
  ['bigint', 1n], ['symbol', Symbol('account')]
];

test('both public names expose the same API', () => {
  const { context } = loadWallet();
  assert.equal(context.FraserWallet, context.SolletWallet);
});

for (const name of ['FraserWallet', 'SolletWallet']) {
  test(name + ' rejects invalid accounts through every high-level entry point', async () => {
    const { context, entropyCalls } = loadWallet();
    const W = context[name];
    const calls = [
      ['keypairFromMnemonic', account => W.keypairFromMnemonic(mnemonic, account)],
      ['generateWallet', account => W.generateWallet(128, account)],
      ['multichain default', account => W.multichainFromMnemonic(mnemonic, account)],
      ['generateMultichain default', account => W.generateMultichainWallet(128, account)]
    ];
    for (const chain of ['sol', 'eth', 'btc']) {
      calls.push(['multichain ' + chain, account => W.multichainFromMnemonic(mnemonic, account, undefined, [chain])]);
      calls.push(['generateMultichain ' + chain, account => W.generateMultichainWallet(128, account, [chain])]);
    }
    for (const [label, account] of invalidAccounts) {
      for (const [method, call] of calls) {
        await assert.rejects(() => call(account), /account must be an integer/, method + ': ' + label);
      }
    }
    assert.equal(entropyCalls(), 0, 'invalid generators must reject before requesting entropy');
  });
}

test('valid account outputs and passphrase handling match the pre-fix revision', async () => {
  const W = loadWallet().context.FraserWallet;
  // SHA-256 of complete wallet results at b021950, using the public phrase above.
  const baseline = {
    0: '667f565ba23b7af60c497a2bb86c567964af370e9a28787ebe78a4af2ee038c6',
    1: '9769487dd6df992777b7d2fc23c25130be73e7b357adc44e0c0f4fd29a64d026',
    1000000: 'e1d4a9865de8b6599f4440c8fe462db906967435c17be3866ff99a10c6b2c601',
    2147483647: 'c37e99825f054b52665b18a07bfb0b58271c448e6c4864f39c89870d4e7923cb'
  };
  for (const [account, expected] of Object.entries(baseline)) {
    const wallet = await W.multichainFromMnemonic(mnemonic, Number(account));
    assert.equal(fingerprint(wallet), expected, 'account ' + account);
    const sol = await W.keypairFromMnemonic(mnemonic, Number(account));
    assert.equal(sol.address, wallet.chains.sol.address);
    assert.equal(sol.path, wallet.chains.sol.path);
  }
  assert.equal(fingerprint(await W.multichainFromMnemonic(mnemonic, 1, 'TREZOR')),
    'd05f0260c2c5ea51f0a92e003b442416f1aa025c1127beb342f201a7d82cd572');
  assert.equal(fingerprint(await W.multichainFromMnemonic(mnemonic)), baseline[0]);
  const negativeZero = await W.multichainFromMnemonic(mnemonic, -0);
  assert.equal(fingerprint(negativeZero), baseline[0]);
  assert.equal(Object.is(negativeZero.account, -0), false);
  assert.equal((await W.keypairFromMnemonic(mnemonic)).path, "m/44'/501'/0'/0'");
});

test('published account-zero addresses and every chain subset remain consistent', async () => {
  const W = loadWallet().context.FraserWallet;
  const wallet = await W.multichainFromMnemonic(mnemonic);
  assert.equal(wallet.chains.sol.address, 'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk');
  assert.equal(wallet.chains.eth.address, '0x9858EfFD232B4033E47d90003D41EC34EcaEda94');
  assert.equal(wallet.chains.btc.address, 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu');
  for (const ids of [['sol'], ['eth'], ['btc'], ['sol', 'eth'], ['sol', 'btc'], ['eth', 'btc']]) {
    const subset = await W.multichainFromMnemonic(mnemonic, undefined, undefined, ids);
    assert.deepEqual(Object.keys(subset.chains), ids);
    for (const id of ids) assert.equal(JSON.stringify(subset.chains[id]), JSON.stringify(wallet.chains[id]));
  }
});

test('12/24-word generation and omitted accounts still produce recoverable wallets', async () => {
  const { context, entropyCalls } = loadWallet();
  const W = context.FraserWallet;
  for (const strength of [128, 256]) {
    const expectedPhrase = Array(strength === 128 ? 11 : 23).fill('abandon').concat(strength === 128 ? 'about' : 'art').join(' ');
    const expected = await W.multichainFromMnemonic(expectedPhrase);
    const generated = await W.generateMultichainWallet(strength);
    assert.equal(generated.mnemonic, expectedPhrase);
    assert.equal(fingerprint(generated), fingerprint(expected));
    assert.equal(await W.validateMnemonic(generated.mnemonic), true);
    const sol = await W.generateWallet(strength);
    assert.equal(sol.mnemonic, expectedPhrase);
    assert.equal(sol.path, expected.chains.sol.path);
    assert.equal(sol.address, expected.chains.sol.address);
    for (const id of ['sol', 'eth', 'btc']) {
      const subset = await W.generateMultichainWallet(strength, 0, [id]);
      assert.deepEqual(Object.keys(subset.chains), [id]);
      assert.equal(subset.chains[id].address, expected.chains[id].address);
    }
  }
  assert.equal(entropyCalls(), 10);
});

test('direct derivation paths reject non-canonical syntax and overflowing indices', async () => {
  const W = loadWallet().context.FraserWallet;
  const seed = Uint8Array.from(Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex'));
  const badSegments = ['', '00', '01', '+1', '-1', '1.5', '1junk', '1e2', '0x10', ' 1', '1 ', '1\n', '1\r', '1\u2028', '1\0', '\u0661', '2147483648', '4294967296', '9007199254740992'];
  for (const segment of badSegments) {
    await assert.rejects(() => W.deriveEd25519Path(seed, 'm/' + segment + "'"), /bad path segment/, JSON.stringify(segment));
    for (const suffix of ['', "'"]) {
      await assert.rejects(() => W._bip32DerivePath(seed, 'm/' + segment + suffix), /bad path segment/, JSON.stringify(segment + suffix));
    }
  }
  for (const badPath of ["m/1'\n", "m/1'\r", "m/1''", 'm//0', 'm/0/']) {
    await assert.rejects(() => W.deriveEd25519Path(seed, badPath));
    await assert.rejects(() => W._bip32DerivePath(seed, badPath));
  }
  await assert.rejects(() => W.deriveEd25519Path(seed, 'm/0'), /bad path segment/);
  await assert.rejects(() => W._bip32DerivePath(seed, 'M/0'));
});

test('published SLIP-0010 vectors preserve root, hardened and non-hardened derivation', async () => {
  const W = loadWallet().context.FraserWallet;
  const seed = Uint8Array.from(Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex'));
  // https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vectors
  const ed25519 = [
    ['m', 'a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed'],
    ["m/0'", '8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c'],
    ["m/0'/1'", '1932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187'],
    ["m/0'/1'/2'/2'/1000000000'", '3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a']
  ];
  for (const [derivationPath, expected] of ed25519) {
    const key = await W.deriveEd25519Path(seed, derivationPath);
    assert.equal(Buffer.from(nacl.sign.keyPair.fromSeed(key).publicKey).toString('hex'), expected);
  }
  const secp256k1 = [
    ['m', '0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2'],
    ["m/0'", '035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56'],
    ["m/0'/1", '03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c'],
    ["m/0'/1/2'/2/1000000000", '022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011']
  ];
  for (const [derivationPath, expected] of secp256k1) {
    assert.equal(Buffer.from(W._secpPublicKey(await W._bip32DerivePath(seed, derivationPath), true)).toString('hex'), expected);
  }
  for (const derivationPath of ["m/2147483647'", 'm/2147483647']) {
    assert.equal((await W._bip32DerivePath(seed, derivationPath)).length, 32);
  }
  assert.equal((await W.deriveEd25519Path(seed, "m/2147483647'")).length, 32);
});
