/*
 * Sollet paper wallet — key derivation module.
 *
 * Runs identically in the browser and in Node (for cross-checking against
 * established libraries). All cryptography happens in memory via WebCrypto +
 * tweetnacl; nothing is ever written to disk or sent over the network.
 *
 * Standards implemented:
 *   - BIP-39  mnemonic generation / validation / seed derivation
 *   - SLIP-0010 ed25519 hardened derivation
 *   - Solana standard path m/44'/501'/{account}'/0' (Phantom/Solflare compatible)
 *
 * Expects globals: crypto (WebCrypto), nacl (tweetnacl), BIP39_ENGLISH (wordlist).
 */
(function () {
  'use strict';

  var subtle = globalThis.crypto.subtle;

  function wordlist() {
    return globalThis.BIP39_ENGLISH;
  }

  function naclLib() {
    return globalThis.nacl;
  }

  // ---------------------------------------------------------------- utils

  var B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

  function base58Encode(bytes) {
    var digits = [0];
    for (var i = 0; i < bytes.length; i++) {
      var carry = bytes[i];
      for (var j = 0; j < digits.length; j++) {
        carry += digits[j] << 8;
        digits[j] = carry % 58;
        carry = (carry / 58) | 0;
      }
      while (carry > 0) {
        digits.push(carry % 58);
        carry = (carry / 58) | 0;
      }
    }
    // leading zero bytes
    var out = '';
    for (var k = 0; k < bytes.length && bytes[k] === 0; k++) out += '1';
    for (var d = digits.length - 1; d >= 0; d--) out += B58_ALPHABET[digits[d]];
    return out;
  }

  function bytesToBits(bytes) {
    var bits = '';
    for (var i = 0; i < bytes.length; i++) {
      bits += bytes[i].toString(2).padStart(8, '0');
    }
    return bits;
  }

  function concatBytes() {
    var total = 0;
    for (var i = 0; i < arguments.length; i++) total += arguments[i].length;
    var out = new Uint8Array(total);
    var off = 0;
    for (var j = 0; j < arguments.length; j++) {
      out.set(arguments[j], off);
      off += arguments[j].length;
    }
    return out;
  }

  function utf8(str) {
    return new TextEncoder().encode(str);
  }

  // ---------------------------------------------------------------- BIP-39

  async function sha256(bytes) {
    return new Uint8Array(await subtle.digest('SHA-256', bytes));
  }

  async function entropyToMnemonic(entropy) {
    var ENT = entropy.length * 8;
    if (ENT !== 128 && ENT !== 160 && ENT !== 192 && ENT !== 224 && ENT !== 256) {
      throw new Error('entropy must be 16-32 bytes');
    }
    var checksumBits = ENT / 32;
    var hash = await sha256(entropy);
    var bits = bytesToBits(entropy) + bytesToBits(hash).slice(0, checksumBits);
    var words = [];
    for (var i = 0; i < bits.length; i += 11) {
      words.push(wordlist()[parseInt(bits.slice(i, i + 11), 2)]);
    }
    return words.join(' ');
  }

  async function generateMnemonic(strengthBits) {
    strengthBits = strengthBits || 256;
    var entropy = new Uint8Array(strengthBits / 8);
    globalThis.crypto.getRandomValues(entropy);
    return entropyToMnemonic(entropy);
  }

  function normalizeMnemonic(mnemonic) {
    return mnemonic.normalize('NFKD').trim().toLowerCase().split(/\s+/).join(' ');
  }

  async function validateMnemonic(mnemonic) {
    var words = normalizeMnemonic(mnemonic).split(' ');
    if ([12, 15, 18, 21, 24].indexOf(words.length) === -1) return false;
    var bits = '';
    for (var i = 0; i < words.length; i++) {
      var idx = wordlist().indexOf(words[i]);
      if (idx === -1) return false;
      bits += idx.toString(2).padStart(11, '0');
    }
    var checksumLen = words.length / 3; // ENT/32 where ENT = words*11 - words/3
    var entropyBits = bits.slice(0, bits.length - checksumLen);
    var checksum = bits.slice(bits.length - checksumLen);
    var entropy = new Uint8Array(entropyBits.length / 8);
    for (var j = 0; j < entropy.length; j++) {
      entropy[j] = parseInt(entropyBits.slice(j * 8, j * 8 + 8), 2);
    }
    var hash = await sha256(entropy);
    return bytesToBits(hash).slice(0, checksumLen) === checksum;
  }

  async function mnemonicToSeed(mnemonic, passphrase) {
    var password = utf8(normalizeMnemonic(mnemonic));
    var salt = utf8('mnemonic' + (passphrase || '').normalize('NFKD'));
    var key = await subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits']);
    var bits = await subtle.deriveBits(
      { name: 'PBKDF2', salt: salt, iterations: 2048, hash: 'SHA-512' },
      key,
      512
    );
    return new Uint8Array(bits);
  }

  // ------------------------------------------------------------- SLIP-0010

  async function hmacSha512(keyBytes, data) {
    var key = await subtle.importKey(
      'raw', keyBytes, { name: 'HMAC', hash: 'SHA-512' }, false, ['sign']
    );
    return new Uint8Array(await subtle.sign('HMAC', key, data));
  }

  function ser32(index) {
    var out = new Uint8Array(4);
    out[0] = (index >>> 24) & 0xff;
    out[1] = (index >>> 16) & 0xff;
    out[2] = (index >>> 8) & 0xff;
    out[3] = index & 0xff;
    return out;
  }

  // path like "m/44'/501'/0'/0'" — ed25519 requires every segment hardened
  async function deriveEd25519Path(seed, path) {
    var segments = path.split('/');
    if (segments[0] !== 'm') throw new Error('path must start with m');
    var I = await hmacSha512(utf8('ed25519 seed'), seed);
    var key = I.slice(0, 32);
    var chainCode = I.slice(32);
    for (var i = 1; i < segments.length; i++) {
      var seg = segments[i];
      if (!/^\d+'$/.test(seg)) throw new Error('ed25519 derivation requires hardened segments');
      var index = parseInt(seg.slice(0, -1), 10) + 0x80000000;
      var data = concatBytes(new Uint8Array([0]), key, ser32(index));
      I = await hmacSha512(chainCode, data);
      key = I.slice(0, 32);
      chainCode = I.slice(32);
    }
    return key;
  }

  // ---------------------------------------------------------------- wallet

  async function keypairFromMnemonic(mnemonic, account, passphrase) {
    account = account || 0;
    var path = "m/44'/501'/" + account + "'/0'";
    var seed = await mnemonicToSeed(mnemonic, passphrase);
    var derived = await deriveEd25519Path(seed, path);
    var kp = naclLib().sign.keyPair.fromSeed(derived);
    return {
      mnemonic: normalizeMnemonic(mnemonic),
      path: path,
      address: base58Encode(kp.publicKey),
      secretKeyBase58: base58Encode(kp.secretKey),          // Phantom import format
      secretKeyJson: '[' + Array.from(kp.secretKey).join(',') + ']' // solana-keygen format
    };
  }

  async function generateWallet(strengthBits, account) {
    var mnemonic = await generateMnemonic(strengthBits);
    return keypairFromMnemonic(mnemonic, account);
  }

  globalThis.SolletWallet = {
    generateMnemonic: generateMnemonic,
    validateMnemonic: validateMnemonic,
    normalizeMnemonic: normalizeMnemonic,
    mnemonicToSeed: mnemonicToSeed,
    deriveEd25519Path: deriveEd25519Path,
    keypairFromMnemonic: keypairFromMnemonic,
    generateWallet: generateWallet,
    base58Encode: base58Encode
  };
})();
