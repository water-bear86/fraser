/*
 * Sollet paper wallet key derivation module.
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

  function validateAccount(account) {
    if (account === undefined) return 0;
    if (!Number.isSafeInteger(account) || account < 0 || account >= 0x80000000) {
      throw new Error('account must be an integer from 0 to 2147483647');
    }
    return account === 0 ? 0 : account;
  }

  function parsePathSegment(segment, hardenedOnly) {
    var match = /^(0|[1-9][0-9]*)('?)$/.exec(segment);
    // An exact match also excludes the final newline allowed by a regex $.
    if (!match || match[0] !== segment || (hardenedOnly && !match[2])) {
      throw new Error('bad path segment: ' + segment);
    }
    var index = Number(match[1]);
    if (!Number.isSafeInteger(index) || index >= 0x80000000) {
      throw new Error('bad path segment: ' + segment);
    }
    return index + (match[2] ? 0x80000000 : 0);
  }

  // path like "m/44'/501'/0'/0'" — ed25519 requires every segment hardened
  async function deriveEd25519Path(seed, path) {
    var segments = path.split('/');
    if (segments[0] !== 'm') throw new Error('path must start with m');
    var I = await hmacSha512(utf8('ed25519 seed'), seed);
    var key = I.slice(0, 32);
    var chainCode = I.slice(32);
    for (var i = 1; i < segments.length; i++) {
      var index = parsePathSegment(segments[i], true);
      var data = concatBytes(new Uint8Array([0]), key, ser32(index));
      I = await hmacSha512(chainCode, data);
      key = I.slice(0, 32);
      chainCode = I.slice(32);
    }
    return key;
  }

  // ============================================================ multichain
  // EVM (BIP-32 secp256k1 + keccak-256, EIP-55) and Bitcoin (BIP-84 bech32).
  // secp256k1 here is generation-time scalar math only: derive public key from
  // private key. No signing, no secret-dependent network or storage I/O exists
  // anywhere on this page.

  function bytesToBig(b) {
    var x = 0n;
    for (var i = 0; i < b.length; i++) x = (x << 8n) | BigInt(b[i]);
    return x;
  }
  function bigToBytes(x, len) {
    var out = new Uint8Array(len);
    for (var i = len - 1; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
    return out;
  }
  function bytesToHex(b) {
    var s = '';
    for (var i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
    return s;
  }

  // --------------------------------------------------- secp256k1 (BigInt)
  var SECP_P = 2n ** 256n - 2n ** 32n - 977n;
  var SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
  var SECP_G = {
    x: 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n,
    y: 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n
  };

  function fmod(a) { var r = a % SECP_P; return r < 0n ? r + SECP_P : r; }
  function fpow(b, e) {
    var r = 1n; b = fmod(b);
    while (e > 0n) { if (e & 1n) r = r * b % SECP_P; b = b * b % SECP_P; e >>= 1n; }
    return r;
  }
  function finv(a) { return fpow(a, SECP_P - 2n); } // P is prime

  // Jacobian coordinates; null = point at infinity
  function jDouble(P) {
    if (!P) return null;
    var X = P[0], Y = P[1], Z = P[2];
    if (Y === 0n) return null;
    var S = fmod(4n * X * fmod(Y * Y));
    var M = fmod(3n * X * X); // a = 0 for secp256k1
    var X3 = fmod(M * M - 2n * S);
    var Y3 = fmod(M * (S - X3) - 8n * fpow(Y, 4n));
    var Z3 = fmod(2n * Y * Z);
    return [X3, Y3, Z3];
  }
  function jAdd(P, Q) {
    if (!P) return Q;
    if (!Q) return P;
    var Z1Z1 = fmod(P[2] * P[2]), Z2Z2 = fmod(Q[2] * Q[2]);
    var U1 = fmod(P[0] * Z2Z2), U2 = fmod(Q[0] * Z1Z1);
    var S1 = fmod(P[1] * Z2Z2 * Q[2]), S2 = fmod(Q[1] * Z1Z1 * P[2]);
    if (U1 === U2) return S1 === S2 ? jDouble(P) : null;
    var H = fmod(U2 - U1), R = fmod(S2 - S1);
    var HH = fmod(H * H), HHH = fmod(HH * H);
    var V = fmod(U1 * HH);
    var X3 = fmod(R * R - HHH - 2n * V);
    var Y3 = fmod(R * (V - X3) - S1 * HHH);
    var Z3 = fmod(H * P[2] * Q[2]);
    return [X3, Y3, Z3];
  }
  function mulG(k) { // k * G, affine result
    var acc = null;
    var add = [SECP_G.x, SECP_G.y, 1n];
    while (k > 0n) {
      if (k & 1n) acc = jAdd(acc, add);
      add = jDouble(add);
      k >>= 1n;
    }
    if (!acc) throw new Error('point at infinity');
    var zi = finv(acc[2]);
    var zi2 = fmod(zi * zi);
    return { x: fmod(acc[0] * zi2), y: fmod(acc[1] * zi2 * zi) };
  }

  function secpPublicKey(privBytes, compressed) {
    var k = bytesToBig(privBytes);
    if (k <= 0n || k >= SECP_N) throw new Error('private key out of range');
    var P = mulG(k);
    if (compressed) {
      return concatBytes(new Uint8Array([P.y & 1n ? 3 : 2]), bigToBytes(P.x, 32));
    }
    return concatBytes(new Uint8Array([4]), bigToBytes(P.x, 32), bigToBytes(P.y, 32));
  }

  // ------------------------------------------------------- BIP-32 derive
  // Private-key derivation: child = (IL + parent) mod n. Non-hardened steps
  // need the parent compressed public key in the HMAC input.
  async function bip32DerivePath(seed, path) {
    var segments = path.split('/');
    if (segments[0] !== 'm') throw new Error('path must start with m');
    var I = await hmacSha512(utf8('Bitcoin seed'), seed);
    var key = I.slice(0, 32);
    var chain = I.slice(32);
    for (var i = 1; i < segments.length; i++) {
      var idx = parsePathSegment(segments[i], false);
      var hardened = idx >= 0x80000000;
      var data = hardened
        ? concatBytes(new Uint8Array([0]), key, ser32(idx))
        : concatBytes(secpPublicKey(key, true), ser32(idx));
      I = await hmacSha512(chain, data);
      var IL = bytesToBig(I.slice(0, 32));
      var child = (IL + bytesToBig(key)) % SECP_N;
      if (IL >= SECP_N || child === 0n) {
        // probability ~2^-127; BIP-32 says skip to the next index, but for a
        // generator it is safer to make the caller start over
        throw new Error('invalid child key, regenerate the phrase');
      }
      key = bigToBytes(child, 32);
      chain = I.slice(32);
    }
    return key;
  }

  // ------------------------------------------------------ EVM / ethereum
  function keccakBytes(bytes) {
    if (typeof globalThis.keccak256 === 'undefined') throw new Error('keccak (vendor/sha3.min.js) not loaded');
    return new Uint8Array(globalThis.keccak256.array(bytes));
  }

  function eip55(addrHexLower) {
    var h = bytesToHex(keccakBytes(utf8(addrHexLower)));
    var out = '';
    for (var i = 0; i < addrHexLower.length; i++) {
      out += parseInt(h[i], 16) >= 8 ? addrHexLower[i].toUpperCase() : addrHexLower[i];
    }
    return '0x' + out;
  }

  async function evmFromSeed(seed, account) {
    var path = "m/44'/60'/0'/0/" + account;
    var key = await bip32DerivePath(seed, path);
    var pub = secpPublicKey(key, false);
    var addrBytes = keccakBytes(pub.slice(1)).slice(12);
    return {
      symbol: 'ETH',
      name: 'ethereum + evm',
      path: path,
      address: eip55(bytesToHex(addrBytes)),
      uriPrefix: 'ethereum:',
      keys: [{ label: 'hex / metamask, rabby import', value: '0x' + bytesToHex(key) }]
    };
  }

  // ----------------------------------------------------------- RIPEMD-160
  // Tables generated from the spec's rho/pi permutations (RIPEMD-160,
  // Dobbertin-Bosselaers-Preneel 1996).
  var RMD = (function () {
    var rho = [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8];
    var idxL = [[]], idxR = [[]];
    for (var i = 0; i < 16; i++) { idxL[0][i] = i; idxR[0][i] = (9 * i + 5) % 16; }
    for (var r = 1; r < 5; r++) {
      idxL[r] = idxL[r - 1].map(function (k) { return rho[k]; });
      idxR[r] = idxR[r - 1].map(function (k) { return rho[k]; });
    }
    var S = [
      [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
      [12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7],
      [13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9],
      [14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6],
      [15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5]
    ];
    var sL = idxL.map(function (idx, r) { return idx.map(function (j) { return S[r][j]; }); });
    var sR = idxR.map(function (idx, r) { return idx.map(function (j) { return S[r][j]; }); });
    return {
      idxL: idxL, idxR: idxR, sL: sL, sR: sR,
      Kl: [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e],
      Kr: [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000]
    };
  })();

  function rotl32(x, s) { return ((x << s) | (x >>> (32 - s))) >>> 0; }
  function rmdF(r, x, y, z) {
    if (r === 0) return (x ^ y ^ z) >>> 0;
    if (r === 1) return ((x & y) | (~x & z)) >>> 0;
    if (r === 2) return ((x | ~y) ^ z) >>> 0;
    if (r === 3) return ((x & z) | (y & ~z)) >>> 0;
    return (x ^ (y | ~z)) >>> 0;
  }

  function ripemd160(data) {
    var h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
    var bitLen = data.length * 8;
    // pad: 0x80, zeros, 64-bit little-endian bit length
    var padded = new Uint8Array((Math.floor((data.length + 8) / 64) + 1) * 64);
    padded.set(data);
    padded[data.length] = 0x80;
    for (var b = 0; b < 8; b++) {
      padded[padded.length - 8 + b] = Math.floor(bitLen / Math.pow(2, 8 * b)) & 0xff;
    }
    var X = new Uint32Array(16);
    for (var off = 0; off < padded.length; off += 64) {
      for (var w = 0; w < 16; w++) {
        X[w] = padded[off + 4 * w] | (padded[off + 4 * w + 1] << 8) |
               (padded[off + 4 * w + 2] << 16) | (padded[off + 4 * w + 3] << 24);
      }
      var al = h[0], bl = h[1], cl = h[2], dl = h[3], el = h[4];
      var ar = h[0], br = h[1], cr = h[2], dr = h[3], er = h[4];
      for (var j = 0; j < 80; j++) {
        var r = j >> 4, k = j & 15;
        var tl = (rotl32((al + rmdF(r, bl, cl, dl) + X[RMD.idxL[r][k]] + RMD.Kl[r]) >>> 0, RMD.sL[r][k]) + el) >>> 0;
        al = el; el = dl; dl = rotl32(cl, 10); cl = bl; bl = tl;
        var tr = (rotl32((ar + rmdF(4 - r, br, cr, dr) + X[RMD.idxR[r][k]] + RMD.Kr[r]) >>> 0, RMD.sR[r][k]) + er) >>> 0;
        ar = er; er = dr; dr = rotl32(cr, 10); cr = br; br = tr;
      }
      var t = (h[1] + cl + dr) >>> 0;
      h[1] = (h[2] + dl + er) >>> 0;
      h[2] = (h[3] + el + ar) >>> 0;
      h[3] = (h[4] + al + br) >>> 0;
      h[4] = (h[0] + bl + cr) >>> 0;
      h[0] = t;
    }
    var out = new Uint8Array(20);
    for (var wi = 0; wi < 5; wi++) {
      out[4 * wi] = h[wi] & 0xff;
      out[4 * wi + 1] = (h[wi] >>> 8) & 0xff;
      out[4 * wi + 2] = (h[wi] >>> 16) & 0xff;
      out[4 * wi + 3] = (h[wi] >>> 24) & 0xff;
    }
    return out;
  }

  // -------------------------------------------------- bech32 (BIP-173 v0)
  var B32_CHARS = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  function b32Polymod(values) {
    var GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    var chk = 1;
    for (var i = 0; i < values.length; i++) {
      var b = chk >>> 25;
      chk = (((chk & 0x1ffffff) << 5) ^ values[i]) >>> 0;
      for (var g = 0; g < 5; g++) if ((b >>> g) & 1) chk = (chk ^ GEN[g]) >>> 0;
    }
    return chk;
  }
  function b32HrpExpand(hrp) {
    var out = [];
    for (var i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >> 5);
    out.push(0);
    for (var j = 0; j < hrp.length; j++) out.push(hrp.charCodeAt(j) & 31);
    return out;
  }
  function b32Encode(hrp, data) { // bech32 (const 1), not bech32m: witness v0
    var values = b32HrpExpand(hrp).concat(data);
    var polymod = b32Polymod(values.concat([0, 0, 0, 0, 0, 0])) ^ 1;
    var out = hrp + '1';
    for (var i = 0; i < data.length; i++) out += B32_CHARS[data[i]];
    for (var c = 0; c < 6; c++) out += B32_CHARS[(polymod >>> (5 * (5 - c))) & 31];
    return out;
  }
  function convertBits8to5(bytes) {
    var out = [], acc = 0, bits = 0;
    for (var i = 0; i < bytes.length; i++) {
      acc = ((acc << 8) | bytes[i]) >>> 0;
      bits += 8;
      while (bits >= 5) { bits -= 5; out.push((acc >>> bits) & 31); }
    }
    if (bits > 0) out.push((acc << (5 - bits)) & 31);
    return out;
  }
  function segwitV0Address(pubCompressed, h160) {
    return b32Encode('bc', [0].concat(convertBits8to5(h160)));
  }

  // -------------------------------------------------------------- bitcoin
  async function wifFromKey(key) { // compressed-pubkey WIF, mainnet
    var payload = concatBytes(new Uint8Array([0x80]), key, new Uint8Array([0x01]));
    var check = (await sha256(await sha256(payload))).slice(0, 4);
    return base58Encode(concatBytes(payload, check));
  }

  async function btcFromSeed(seed, account) {
    var path = "m/84'/0'/0'/0/" + account;
    var key = await bip32DerivePath(seed, path);
    var pub = secpPublicKey(key, true);
    var h160 = ripemd160(await sha256(pub));
    return {
      symbol: 'BTC',
      name: 'bitcoin, native segwit',
      path: path,
      address: segwitV0Address(pub, h160),
      uriPrefix: 'bitcoin:',
      keys: [{ label: 'wif / electrum, sparrow import', value: await wifFromKey(key) }]
    };
  }

  // ---------------------------------------------------------------- solana
  async function solFromSeed(seed, account) {
    var path = "m/44'/501'/" + account + "'/0'";
    var derived = await deriveEd25519Path(seed, path);
    var kp = naclLib().sign.keyPair.fromSeed(derived);
    return {
      symbol: 'SOL',
      name: 'solana',
      path: path,
      address: base58Encode(kp.publicKey),
      uriPrefix: 'solana:',
      keys: [
        { label: 'base58 / phantom import', value: base58Encode(kp.secretKey) },
        { label: 'json / solana-keygen', value: '[' + Array.from(kp.secretKey).join(',') + ']' }
      ]
    };
  }

  // ------------------------------------------------------- multichain API
  // chainIds: optional subset like ['sol'] for a single-chain wallet whose
  // phrase is independent of any other wallet. Default is all three.
  async function multichainFromMnemonic(mnemonic, account, passphrase, chainIds) {
    account = validateAccount(account);
    var ids = chainIds && chainIds.length ? chainIds : ['sol', 'eth', 'btc'];
    var seed = await mnemonicToSeed(mnemonic, passphrase);
    var chains = {};
    for (var i = 0; i < ids.length; i++) {
      var id = ids[i];
      if (id === 'sol') chains.sol = await solFromSeed(seed, account);
      else if (id === 'eth') chains.eth = await evmFromSeed(seed, account);
      else if (id === 'btc') chains.btc = await btcFromSeed(seed, account);
      else throw new Error('unknown chain: ' + id);
    }
    return {
      mnemonic: normalizeMnemonic(mnemonic),
      account: account,
      chains: chains
    };
  }

  async function generateMultichainWallet(strengthBits, account, chainIds) {
    account = validateAccount(account);
    var mnemonic = await generateMnemonic(strengthBits);
    return multichainFromMnemonic(mnemonic, account, undefined, chainIds);
  }

  // ---------------------------------------------------------------- wallet

  async function keypairFromMnemonic(mnemonic, account, passphrase) {
    account = validateAccount(account);
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
    account = validateAccount(account);
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
    base58Encode: base58Encode,
    multichainFromMnemonic: multichainFromMnemonic,
    generateMultichainWallet: generateMultichainWallet,
    // exposed for cross-check tests
    _bip32DerivePath: bip32DerivePath,
    _secpPublicKey: secpPublicKey,
    _ripemd160: ripemd160,
    _wifFromKey: wifFromKey,
    _segwitV0Address: segwitV0Address
  };
  globalThis.FraserWallet = globalThis.SolletWallet;
})();
