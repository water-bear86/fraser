/* FRASER paper wallet — TUI wiring. All state lives in memory only. */
(function () {
  'use strict';

  var W = globalThis.SolletWallet;
  var current = null;      // the generated wallet, memory only
  var revealed = false;
  var strength = 256;      // 24 words
  var account = 0;
  var busy = false;
  var wakeLock = null;
  var systemChecks = null;

  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
  // ------------------------------------------------------------ term output
  // Separate columns let diagnostic details wrap without splitting labels.
  function fmtLine(tag, label, detail) {
    var cls = tag === 'OK' ? 'tag-ok' : tag === 'WARN' ? 'tag-warn' : 'tag-fail';
    return '<span class="term-line"><span class="term-tag ' + cls + '">[' + esc(tag) + ']</span>' +
      '<span class="term-label">' + esc(label) + '</span>' +
      '<span class="term-detail">' + esc(detail) + '</span></span>\n';
  }

  function termLine(pre, tag, label, detail) {
    var line = document.createElement('span');
    line.className = tag ? 'term-entry' : 'term-command';
    line.innerHTML = tag ? fmtLine(tag, label, detail) : esc(label) + '\n';
    pre.appendChild(line);
    return line;
  }

  function typeLines(pre, lines, delay, done) {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      lines.forEach(function (line) { termLine(pre, line[0], line[1], line[2]); });
      if (done) done();
      return;
    }
    var i = 0;
    (function next() {
      if (i >= lines.length) { if (done) done(); return; }
      var l = lines[i++];
      termLine(pre, l[0], l[1], l[2]);
      setTimeout(next, delay);
    })();
  }

  // ------------------------------------------------------- net + lock badges
  function updateCheckSummary() {
    if (!systemChecks) return;
    var passed = systemChecks.filter(function (check) { return check[0] === 'OK'; }).length;
    var warnings = systemChecks.filter(function (check) { return check[0] === 'WARN'; }).length;
    var failed = systemChecks.filter(function (check) { return check[0] === 'FAIL'; }).length;
    if (navigator.onLine) warnings++; else passed++;
    var summary = $('systemSummary');
    summary.textContent = passed + ' OK' + (warnings ? ' · ' + warnings + ' WARN' : '') + (failed ? ' · ' + failed + ' FAIL' : '');
    summary.className = 'pcorner ' + (failed ? 'red' : warnings ? 'amber' : 'hi');
  }

  function updateNetBadge() {
    var el = $('netBadge');
    if (navigator.onLine) {
      el.textContent = '▲ ONLINE';
      el.className = 'online';
    } else {
      el.textContent = '● OFFLINE';
      el.className = 'offline';
    }
    var bootNet = $('bootNet');
    if (bootNet) {
      bootNet.innerHTML = navigator.onLine
        ? fmtLine('WARN', 'network', 'ONLINE — disconnect before generating')
        : fmtLine('OK', 'network', 'offline — ideal');
    }
    updateCheckSummary();
  }
  window.addEventListener('online', updateNetBadge);
  window.addEventListener('offline', updateNetBadge);

  function setLockBadge(state, cls) {
    var el = $('lockBadge');
    el.textContent = state;
    el.className = cls || 'dim';
  }

  async function acquireWakeLock() {
    if (!('wakeLock' in navigator)) { setLockBadge('n/a'); return; }
    try {
      wakeLock = await navigator.wakeLock.request('screen');
      setLockBadge('● screen held', 'hi');
      wakeLock.addEventListener('release', function () {
        if (current) setLockBadge('released', 'amber'); else setLockBadge('idle');
      });
    } catch (e) {
      setLockBadge('unavailable', 'amber');
    }
  }
  function releaseWakeLock() {
    if (wakeLock) { wakeLock.release().catch(function () {}); wakeLock = null; }
    setLockBadge('idle');
  }
  document.addEventListener('visibilitychange', function () {
    // OS drops wake locks on tab hide; re-acquire while a wallet is on screen
    if (current && document.visibilityState === 'visible') acquireWakeLock();
  });

  // ---------------------------------------------------------------- boot
  async function boot() {
    var pre = $('boot');
    var checks = [];

    checks.push([!!(globalThis.crypto && globalThis.crypto.getRandomValues) ? 'OK' : 'FAIL',
      'entropy', 'crypto.getRandomValues (OS CSPRNG)']);
    checks.push([!!(globalThis.crypto && globalThis.crypto.subtle) ? 'OK' : 'FAIL',
      'webcrypto', 'SubtleCrypto available']);
    checks.push([typeof nacl !== 'undefined' ? 'OK' : 'FAIL',
      'ed25519', 'tweetnacl loaded']);
    checks.push([(typeof BIP39_ENGLISH !== 'undefined' && BIP39_ENGLISH.length === 2048) ? 'OK' : 'FAIL',
      'wordlist', 'BIP-39 english, 2048 words']);

    // live CSP probe: connect-src 'none' must block a fetch even to our own origin
    var cspBlocked = await fetch(location.href, { cache: 'no-store' })
      .then(function () { return false; })
      .catch(function () { return true; });
    checks.push([cspBlocked ? 'OK' : 'FAIL', 'csp firewall',
      cspBlocked ? "probe blocked — connect-src 'none' enforced" : 'PROBE ESCAPED — do not use this build']);

    // fraser writes nothing; anything found here is foreign state from other
    // apps on this origin (localhost cookies are shared across ports)
    var leftovers = [];
    try {
      document.cookie.split(';').forEach(function (c) {
        var name = c.split('=')[0].trim();
        if (name) leftovers.push('cookie:' + name);
      });
      Object.keys(localStorage).forEach(function (k) { leftovers.push('localStorage:' + k); });
      Object.keys(sessionStorage).forEach(function (k) { leftovers.push('sessionStorage:' + k); });
    } catch (e) { /* storage blocked entirely — even better */ }
    checks.push(leftovers.length === 0
      ? ['OK', 'persistence', 'none — no cookies, no storage, no disk']
      : ['WARN', 'persistence', 'foreign state on this origin (not fraser): ' +
          leftovers.slice(0, 3).join(', ') + (leftovers.length > 3 ? ' +' + (leftovers.length - 3) + ' more' : '') +
          ' — file:// avoids shared localhost state']);

    systemChecks = checks;
    updateCheckSummary();
    typeLines(pre, checks, 90, function () {
      var net = document.createElement('span');
      net.id = 'bootNet';
      pre.appendChild(net);
      updateNetBadge();
      var ready = document.createElement('span');
      ready.className = 'term-ready';
      ready.innerHTML = '<span class="tag-ok">ready.</span> press <span class="tag-ok">g</span> to generate. <span class="cursor" aria-hidden="true"></span>';
      pre.appendChild(ready);
    });
  }

  // ------------------------------------------------------------- ascii QR
  // Half-block rendering, dark modules on a light box — same trick as
  // `qrencode -t ANSIUTF8`, and scanners still read it.
  function asciiQr(text) {
    var qr = globalThis.qrcode(0, 'M');
    qr.addData(text);
    qr.make();
    var n = qr.getModuleCount();
    var lines = [];
    for (var y = 0; y < n; y += 2) {
      var row = '';
      for (var x = 0; x < n; x++) {
        var top = qr.isDark(y, x);
        var bot = y + 1 < n ? qr.isDark(y + 1, x) : false;
        row += top && bot ? '█' : top ? '▀' : bot ? '▄' : ' ';
      }
      lines.push(row);
    }
    return lines.join('\n');
  }

  function svgQr(text, cellSize) { // crisp vector QR for the printed sheet
    var qr = globalThis.qrcode(0, 'M');
    qr.addData(text);
    qr.make();
    return qr.createSvgTag({ cellSize: cellSize || 3, margin: 2 });
  }

  // -------------------------------------------------------------- controls
  function setStrength(bits) {
    strength = bits;
    $('opt24').setAttribute('aria-pressed', bits === 256 ? 'true' : 'false');
    $('opt12').setAttribute('aria-pressed', bits === 128 ? 'true' : 'false');
    $('opt24').querySelector('.k').textContent = bits === 256 ? '(●)' : '( )';
    $('opt12').querySelector('.k').textContent = bits === 128 ? '(●)' : '( )';
  }
  $('opt24').addEventListener('click', function () { setStrength(256); });
  $('opt12').addEventListener('click', function () { setStrength(128); });
  $('accDown').addEventListener('click', function () {
    account = Math.max(0, account - 1);
    $('accVal').textContent = account;
  });
  $('accUp').addEventListener('click', function () {
    account = Math.min(1000000, account + 1);
    $('accVal').textContent = account;
  });

  // -------------------------------------------------------------- generate
  function generate() {
    if (busy) return;
    busy = true;
    revealed = false;
    $('generateBtn').disabled = true;
    $('generateBtn').setAttribute('aria-busy', 'true');
    $('generateLabel').textContent = 'GENERATING…';
    var log = $('genLog');
    log.textContent = '';
    termLine(log, null, '$ fraser generate --words ' + (strength === 256 ? 24 : 12) + ' --account ' + account);

    var steps = [
      ['OK', 'entropy', strength + ' bits from CSPRNG'],
      ['OK', 'mnemonic', (strength === 256 ? 24 : 12) + ' words, checksum embedded'],
      ['OK', 'seed', 'PBKDF2-SHA512, 2048 rounds'],
      ['OK', 'derive', "m/44'/501'/" + account + "'/0' (SLIP-0010)"],
      ['OK', 'keypair', 'ed25519']
    ];

    W.generateWallet(strength, account).then(function (wallet) {
      current = wallet;
      typeLines(log, steps, 80, function () {
        renderWallet(wallet);
        acquireWakeLock();
        busy = false;
        $('generateBtn').disabled = false;
        $('generateBtn').setAttribute('aria-busy', 'false');
        $('generateLabel').textContent = 'GENERATE';
      });
    }).catch(function (err) {
      termLine(log, 'FAIL', 'generate', String(err && err.message || err));
      busy = false;
      $('generateBtn').disabled = false;
      $('generateBtn').setAttribute('aria-busy', 'false');
      $('generateLabel').textContent = 'GENERATE';
    });
  }
  $('generateBtn').addEventListener('click', generate);

  // -------------------------------------------------------------- render
  var REDACT_WORD = '██████';
  function redactB58(s) { return '█'.repeat(24) + '  <hidden — press r>'; }

  function renderWallet(wallet) {
    $('result').style.display = 'block';
    $('addressText').textContent = wallet.address;
    $('pathText').textContent = wallet.path;
    $('addressQr').textContent = asciiQr('solana:' + wallet.address);

    var list = $('wordsList');
    list.innerHTML = '';
    wallet.mnemonic.split(' ').forEach(function (_, i) {
      var li = document.createElement('li');
      var n = document.createElement('span');
      n.className = 'n';
      n.textContent = (i + 1) + '.';
      var w = document.createElement('span');
      w.className = 'w redacted';
      w.textContent = REDACT_WORD;
      li.appendChild(n);
      li.appendChild(w);
      list.appendChild(li);
    });
    $('secretB58').textContent = redactB58();
    $('secretB58').className = 'keyline redacted';
    $('secretJson').textContent = redactB58();
    $('secretJson').className = 'keyline redacted';
    $('revealBtn').innerHTML = 'REVEAL <span class="k">(r)</span>';

    renderPaperWallet(wallet);
    $('result').scrollIntoView({
      behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth',
      block: 'start'
    });
  }

  // Secrets only enter the visible DOM while revealed; hiding puts blocks back.
  function setRevealed(on) {
    if (!current) return;
    revealed = on;
    var words = current.mnemonic.split(' ');
    var items = document.querySelectorAll('#wordsList li .w');
    items.forEach(function (el, i) {
      el.textContent = on ? words[i] : REDACT_WORD;
      el.className = on ? 'w' : 'w redacted';
    });
    $('secretB58').textContent = on ? current.secretKeyBase58 : redactB58();
    $('secretB58').className = on ? 'keyline' : 'keyline redacted';
    $('secretJson').textContent = on ? current.secretKeyJson : redactB58();
    $('secretJson').className = on ? 'keyline' : 'keyline redacted';
    $('revealBtn').innerHTML = (on ? 'HIDE' : 'REVEAL') + ' <span class="k">(r)</span>';
  }
  $('revealBtn').addEventListener('click', function () { setRevealed(!revealed); });

  // ----------------------------------------------------------------- print
  function renderPaperWallet(wallet) {
    var words = wallet.mnemonic.split(' ').map(function (w) {
      return '<li>' + esc(w) + '</li>';
    }).join('');
    $('paperWallet').innerHTML =
      '<div class="pw-half">' +
        '<div class="pw-title">FRASER — Solana deposit (public)</div>' +
        '<div class="pw-sub">Share this side freely. Funds sent here are controlled by the secret phrase below.</div>' +
        '<div class="pw-flex">' +
          svgQr('solana:' + wallet.address, 3) +
          '<div><div class="pw-mono">' + esc(wallet.address) + '</div>' +
          '<div class="pw-sub" style="margin-top:8px">Derivation path: ' + esc(wallet.path) + '</div></div>' +
        '</div>' +
      '</div>' +
      '<div class="pw-half">' +
        '<div class="pw-title">FRASER — Secret phrase (keep hidden)</div>' +
        '<div class="pw-sub">Anyone with these words has full, irreversible control of the funds.</div>' +
        '<ol class="pw-words">' + words + '</ol>' +
        '<div class="pw-danger">Do not photograph. Do not store digitally. Restore in Phantom/Solflare with path ' + esc(wallet.path) + '.</div>' +
        '<div class="pw-fold">▲ fold here so the secret phrase faces inward ▲</div>' +
      '</div>';
  }
  $('printBtn').addEventListener('click', function () {
    if (current) window.print();
  });

  // ----------------------------------------------------------------- clear
  $('clearBtn').addEventListener('click', function () {
    current = null;
    releaseWakeLock();
    $('paperWallet').innerHTML = '';
    location.reload(); // drop all in-memory state
  });

  // ---------------------------------------------------------------- verify
  function verify() {
    var phrase = $('verifyInput').value;
    var out = $('verifyOut');
    out.textContent = '';
    if (!phrase.trim()) return;
    W.validateMnemonic(phrase).then(function (valid) {
      if (!valid) {
        termLine(out, 'FAIL', 'checksum', 'not a valid BIP-39 phrase (bad word or checksum)');
        return null;
      }
      return W.keypairFromMnemonic(phrase, account).then(function (wallet) {
        termLine(out, 'OK', 'checksum', 'valid BIP-39 phrase');
        termLine(out, 'OK', 'derived', wallet.path);
        var addr = document.createElement('span');
        addr.innerHTML = 'address: <span class="tag-ok" id="verifyAddress">' + esc(wallet.address) + '</span>\n';
        out.appendChild(addr);
      });
    }).catch(function (err) {
      termLine(out, 'FAIL', 'error', String(err && err.message || err));
    });
  }
  $('verifyBtn').addEventListener('click', verify);

  // --------------------------------------------------------------- hotkeys
  document.addEventListener('keydown', function (e) {
    var t = e.target;
    var typing = t && (t.tagName === 'TEXTAREA' || t.tagName === 'INPUT');
    if (typing) {
      if (e.key === 'Escape') t.blur();
      return;
    }
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    switch (e.key.toLowerCase()) {
      case 'g': e.preventDefault(); generate(); break;
      case 'r': if (current) { e.preventDefault(); setRevealed(!revealed); } break;
      case 'p': if (current) { e.preventDefault(); window.print(); } break;
      case 'c': if (current) { e.preventDefault(); $('clearBtn').click(); } break;
      case 'v': e.preventDefault(); $('verifyInput').focus(); break;
    }
  });

  updateNetBadge();
  boot();
})();
