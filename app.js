/* FRASER paper wallet: TUI wiring. All state lives in memory only. */
(function () {
  'use strict';

  var W = globalThis.FraserWallet;
  var current = null;      // the generated multichain wallet, memory only
  var selectedChain = 'sol';
  var revealed = false;
  var strength = 256;      // 24 words
  var account = 0;
  var chainSel = 'all';    // 'all' | array of chain ids, e.g. ['sol','btc']
  var busy = false;
  var wakeLock = null;
  var systemChecks = null;
  var CHAIN_ORDER = ['sol', 'eth', 'btc'];

  function activeChains() {
    return current ? CHAIN_ORDER.filter(function (id) { return current.chains[id]; }) : [];
  }

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
        ? fmtLine('WARN', 'network', 'ONLINE. disconnect before generating')
        : fmtLine('OK', 'network', 'offline, ideal');
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
      'ed25519', 'tweetnacl loaded (SOL)']);
    checks.push([typeof keccak256 !== 'undefined' ? 'OK' : 'FAIL',
      'keccak-256', 'js-sha3 loaded (ETH), secp256k1 built in (ETH+BTC)']);
    checks.push([(typeof BIP39_ENGLISH !== 'undefined' && BIP39_ENGLISH.length === 2048) ? 'OK' : 'FAIL',
      'wordlist', 'BIP-39 english, 2048 words']);

    // live CSP probe: connect-src 'none' must block a fetch even to our own origin
    var cspBlocked = await fetch(location.href, { cache: 'no-store' })
      .then(function () { return false; })
      .catch(function () { return true; });
    checks.push([cspBlocked ? 'OK' : 'FAIL', 'csp firewall',
      cspBlocked ? "probe blocked: connect-src 'none' enforced" : 'PROBE ESCAPED. do not use this build']);

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
    } catch (e) { /* storage blocked entirely, even better */ }
    checks.push(leftovers.length === 0
      ? ['OK', 'persistence', 'none: no cookies, no storage, no disk']
      : ['WARN', 'persistence', 'foreign state on this origin (not fraser): ' +
          leftovers.slice(0, 3).join(', ') + (leftovers.length > 3 ? ' +' + (leftovers.length - 3) + ' more' : '') +
          '. file:// avoids shared localhost state']);

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
  // Half-block rendering, dark modules on a light box, same trick as
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
  // Individual chains toggle like checkboxes; picking all three (or none)
  // collapses to the "all chains" state automatically.
  function setChainSel(sel) {
    if (Array.isArray(sel)) {
      sel = CHAIN_ORDER.filter(function (id) { return sel.indexOf(id) !== -1; });
      if (sel.length === 0 || sel.length === CHAIN_ORDER.length) sel = 'all';
    }
    chainSel = sel;
    document.querySelectorAll('.chain-opt').forEach(function (btn) {
      var id = btn.dataset.chains;
      var on = id === 'all'
        ? chainSel === 'all'
        : chainSel !== 'all' && chainSel.indexOf(id) !== -1;
      btn.setAttribute('aria-pressed', on ? 'true' : 'false');
      btn.querySelector('.k').textContent = on ? '(●)' : '( )';
    });
  }
  document.querySelectorAll('.chain-opt').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var id = btn.dataset.chains;
      if (id === 'all') { setChainSel('all'); return; }
      var next = chainSel === 'all' ? [] : chainSel.slice();
      var at = next.indexOf(id);
      if (at === -1) next.push(id); else next.splice(at, 1);
      setChainSel(next);
    });
  });
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
    if (busy || tourDialog.open) return;
    busy = true;
    revealed = false;
    $('generateBtn').disabled = true;
    tourReplay.disabled = true;
    $('generateBtn').setAttribute('aria-busy', 'true');
    $('generateLabel').textContent = 'GENERATING…';
    var ids = chainSel === 'all' ? CHAIN_ORDER.slice() : chainSel.slice();
    var log = $('genLog');
    log.textContent = '';
    termLine(log, null, '$ fraser generate --words ' + (strength === 256 ? 24 : 12) +
      ' --account ' + account + ' --chains ' + ids.join(','));

    var deriveSteps = {
      sol: ['OK', 'sol', "m/44'/501'/" + account + "'/0' (SLIP-0010 ed25519)"],
      eth: ['OK', 'eth', "m/44'/60'/0'/0/" + account + ' (BIP-32 secp256k1)'],
      btc: ['OK', 'btc', "m/84'/0'/0'/0/" + account + ' (BIP-84 native segwit)']
    };
    var steps = [
      ['OK', 'entropy', strength + ' bits from CSPRNG'],
      ['OK', 'mnemonic', (strength === 256 ? 24 : 12) + ' words, checksum embedded'],
      ['OK', 'seed', 'PBKDF2-SHA512, 2048 rounds']
    ].concat(ids.map(function (id) { return deriveSteps[id]; }));

    W.generateMultichainWallet(strength, account, ids).then(function (wallet) {
      current = wallet;
      typeLines(log, steps, 80, function () {
        renderWallet(wallet);
        acquireWakeLock();
        busy = false;
        $('generateBtn').disabled = false;
        tourReplay.disabled = false;
        $('generateBtn').setAttribute('aria-busy', 'false');
        $('generateLabel').textContent = 'GENERATE';
      });
    }).catch(function (err) {
      termLine(log, 'FAIL', 'generate', String(err && err.message || err));
      busy = false;
      $('generateBtn').disabled = false;
      tourReplay.disabled = false;
      $('generateBtn').setAttribute('aria-busy', 'false');
      $('generateLabel').textContent = 'GENERATE';
    });
  }
  $('generateBtn').addEventListener('click', generate);

  // -------------------------------------------------------------- render
  var REDACT_WORD = '██████';
  function redactKey() { return '█'.repeat(24) + '  <hidden, press r>'; }

  function renderChainFocus() {
    if (!current) return;
    var active = activeChains();
    var chain = current.chains[selectedChain];
    document.querySelectorAll('.chain-tab').forEach(function (tab) {
      tab.style.display = current.chains[tab.dataset.chain] ? '' : 'none';
      tab.setAttribute('aria-pressed', tab.dataset.chain === selectedChain ? 'true' : 'false');
    });
    $('chainNote').textContent = chain.name + (active.length === 1 ? ' · single-chain wallet' : '');
    $('addressQr').textContent = asciiQr(chain.uriPrefix + chain.address);
    $('addressText').textContent = chain.address;
    $('pathText').textContent = chain.path;

    // the combined list only earns its place when there is more than one chain
    var multi = active.length > 1;
    $('allAddressesHeading').style.display = multi ? '' : 'none';
    var all = $('allAddresses');
    all.style.display = multi ? '' : 'none';
    all.innerHTML = '';
    if (multi) {
      active.forEach(function (id) {
        var c = current.chains[id];
        var row = document.createElement('div');
        row.className = 'addr-row' + (id === selectedChain ? ' active' : '');
        row.innerHTML = '<span class="sym">' + esc(c.symbol) + '</span><span class="a">' + esc(c.address) + '</span>';
        all.appendChild(row);
      });
    }
    renderChainKeys();
  }

  // Secrets only enter the visible DOM while revealed; hiding puts blocks back.
  function renderChainKeys() {
    if (!current) return;
    var chain = current.chains[selectedChain];
    var wrap = $('chainKeys');
    wrap.innerHTML = '';
    chain.keys.forEach(function (key) {
      var h = document.createElement('h3');
      h.className = 'sec';
      h.innerHTML = 'PRIVATE KEY <span class="dim">' + esc(chain.symbol.toLowerCase() + ' · ' + key.label) + '</span>';
      var line = document.createElement('div');
      line.className = revealed ? 'keyline' : 'keyline redacted';
      line.textContent = revealed ? key.value : redactKey();
      wrap.appendChild(h);
      wrap.appendChild(line);
    });
  }

  function renderWallet(wallet) {
    $('result').style.display = 'block';
    selectedChain = activeChains()[0];
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
    $('revealBtn').innerHTML = 'REVEAL <span class="k">(r)</span>';
    renderChainFocus();
    renderPaperWallet(wallet);
    $('result').scrollIntoView({
      behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth',
      block: 'start'
    });
  }

  document.querySelectorAll('.chain-tab').forEach(function (tab) {
    tab.addEventListener('click', function () {
      selectedChain = tab.dataset.chain;
      renderChainFocus();
    });
  });

  function setRevealed(on) {
    if (!current) return;
    revealed = on;
    var words = current.mnemonic.split(' ');
    var items = document.querySelectorAll('#wordsList li .w');
    items.forEach(function (el, i) {
      el.textContent = on ? words[i] : REDACT_WORD;
      el.className = on ? 'w' : 'w redacted';
    });
    renderChainKeys();
    $('revealBtn').innerHTML = (on ? 'HIDE' : 'REVEAL') + ' <span class="k">(r)</span>';
  }
  $('revealBtn').addEventListener('click', function () { setRevealed(!revealed); });

  // ----------------------------------------------------------------- print
  function renderPaperWallet(wallet) {
    var words = wallet.mnemonic.split(' ').map(function (w) {
      return '<li>' + esc(w) + '</li>';
    }).join('');
    var active = CHAIN_ORDER.filter(function (id) { return wallet.chains[id]; });
    var restoreHints = {
      sol: 'Phantom (SOL)', eth: 'MetaMask or Rabby (ETH)', btc: 'Sparrow or Electrum (BTC)'
    };
    var chainRows = active.map(function (id) {
      var c = wallet.chains[id];
      return '<div class="pw-chain">' +
        svgQr(c.uriPrefix + c.address, 2) +
        '<div><span class="pw-sym">' + esc(c.symbol) + '</span>' +
        '<div class="pw-mono">' + esc(c.address) + '</div>' +
        '<div class="pw-sub" style="margin-top:4px">' + esc(c.name) + ' · ' + esc(c.path) + '</div></div>' +
      '</div>';
    }).join('');
    $('paperWallet').innerHTML =
      '<div class="pw-half">' +
        '<div class="pw-title">FRASER: deposit address' + (active.length > 1 ? 'es' : '') + ' (public)</div>' +
        '<div class="pw-sub">Share this side freely. Funds sent ' + (active.length > 1 ? 'to any of these addresses' : 'here') + ' are controlled by the secret phrase below.</div>' +
        chainRows +
      '</div>' +
      '<div class="pw-half">' +
        '<div class="pw-title">FRASER: secret phrase (keep hidden)</div>' +
        '<div class="pw-sub">Anyone with these words has full, irreversible control of the funds' + (active.length > 1 ? ' on every chain' : '') + '.</div>' +
        '<ol class="pw-words">' + words + '</ol>' +
        '<div class="pw-danger">Do not photograph. Do not store digitally. Restores in ' +
          active.map(function (id) { return restoreHints[id]; }).join(', ') +
          ' at the path' + (active.length > 1 ? 's' : '') + ' above. Account index: ' + esc(String(wallet.account)) + '.</div>' +
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
      return W.multichainFromMnemonic(phrase, account).then(function (wallet) {
        termLine(out, 'OK', 'checksum', 'valid BIP-39 phrase · account ' + account);
        CHAIN_ORDER.forEach(function (id) {
          var c = wallet.chains[id];
          var line = document.createElement('span');
          line.className = 'term-entry';
          line.innerHTML = '<span class="term-line"><span class="term-tag tag-ok">[OK]</span>' +
            '<span class="term-label">' + esc(c.symbol.toLowerCase()) + '</span>' +
            '<span class="term-detail verify-address hi" data-chain="' + esc(id) + '">' + esc(c.address) + '</span></span>\n';
          out.appendChild(line);
        });
      });
    }).catch(function (err) {
      termLine(out, 'FAIL', 'error', String(err && err.message || err));
    });
  }
  $('verifyBtn').addEventListener('click', verify);

  // ---------------------------------------------------------- quick tour
  // Completion stays in the page heap: no cookies, storage, or URL flags.
  var tourDialog = $('tourDialog');
  var tourCard = $('tourCard');
  var tourReplay = $('tourReplay');
  var tourIndex = 0;
  var tourFrame = 0;
  var tourReturnFocus = null;
  var tourSteps = [
    {
      target: $('systemCheck'), compact: $('systemCheck').querySelector('summary'),
      title: 'Start offline',
      text: 'Review the system checks. For a wallet you plan to fund, download FRASER and use it offline.'
    },
    {
      target: $('walletControls'), compact: document.querySelector('[aria-labelledby="chainsLabel"]'),
      title: 'Choose your wallet',
      text: 'Choose phrase length and chains. SOL, EVM and BTC can share one phrase, or select just the chains you need.'
    },
    {
      target: $('generateBtn'),
      title: 'Generate. Print. Fold.',
      text: 'Generate creates a new phrase. Use Reveal to read it, Print for the sheet, and Clear when finished.'
    },
    {
      target: $('verifyInput'),
      title: 'Check the paper',
      text: 'Type the words from your paper. Compare its addresses with the derived addresses before funding the wallet.'
    }
  ];
  var tourObserver = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(queueTourPosition) : null;

  function setTourRect(el, left, top, width, height) {
    el.style.left = left + 'px';
    el.style.top = top + 'px';
    el.style.width = Math.max(0, width) + 'px';
    el.style.height = Math.max(0, height) + 'px';
  }

  function positionTour() {
    if (!tourDialog.open) return;
    var width = tourDialog.clientWidth;
    var height = tourDialog.clientHeight;
    var margin = 12;
    var gap = 14;
    var padding = 6;
    var cardWidth = tourCard.offsetWidth;
    var cardHeight = tourCard.offsetHeight;
    var step = tourSteps[tourIndex];
    var target = step.target;
    var rect = target.getBoundingClientRect();
    var sideFits = rect.left - padding - gap >= cardWidth + margin ||
      width - rect.right - padding - gap >= cardWidth + margin;

    // A short viewport highlights the chain group or check summary instead
    // of forcing a large panel and the callout into the same vertical space.
    if (!sideFits && step.compact && rect.height + cardHeight + gap + padding * 2 + margin * 2 > height) {
      target = step.compact;
      rect = target.getBoundingClientRect();
    }
    // Reflow can move the anchor off-screen without changing the step.
    // Allow subpixel rounding at the edge so scroll events settle once.
    if (rect.top < margin + padding - 1 || rect.bottom > height - margin - padding + 1) {
      target.scrollIntoView({ behavior: 'auto', block: 'center', inline: 'nearest' });
      rect = target.getBoundingClientRect();
    }
    sideFits = rect.left - padding - gap >= cardWidth + margin ||
      width - rect.right - padding - gap >= cardWidth + margin;
    if (!sideFits && height - rect.bottom - padding - gap < cardHeight + margin &&
        rect.top - padding - gap < cardHeight + margin) {
      window.scrollBy({ top: rect.top - margin - padding, behavior: 'auto' });
      rect = target.getBoundingClientRect();
    }

    var left = Math.min(width, Math.max(0, rect.left - padding));
    var top = Math.min(height, Math.max(0, rect.top - padding));
    var right = Math.min(width, Math.max(left, rect.right + padding));
    var bottom = Math.min(height, Math.max(top, rect.bottom + padding));
    setTourRect($('tourShadeTop'), 0, 0, width, top);
    setTourRect($('tourShadeBottom'), 0, bottom, width, height - bottom);
    setTourRect($('tourShadeLeft'), 0, top, left, bottom - top);
    setTourRect($('tourShadeRight'), right, top, width - right, bottom - top);
    setTourRect($('tourSpotlight'), left, top, right - left, bottom - top);

    var x = Math.min(Math.max(left, margin), width - cardWidth - margin);
    var y;
    if (width - right - gap >= cardWidth + margin) {
      x = right + gap;
      y = top + (bottom - top - cardHeight) / 2;
    } else if (left - gap >= cardWidth + margin) {
      x = left - gap - cardWidth;
      y = top + (bottom - top - cardHeight) / 2;
    } else if (height - bottom - gap >= cardHeight + margin) {
      y = bottom + gap;
    } else {
      y = top - gap - cardHeight;
    }
    tourCard.style.left = Math.max(margin, x) + 'px';
    tourCard.style.top = Math.max(margin, Math.min(y, height - cardHeight - margin)) + 'px';
  }

  function queueTourPosition() {
    if (!tourDialog.open || tourFrame) return;
    tourFrame = requestAnimationFrame(function () {
      tourFrame = 0;
      positionTour();
    });
  }

  function showTourStep(index) {
    tourIndex = index;
    var step = tourSteps[index];
    $('tourTitle').textContent = step.title;
    $('tourDescription').textContent = step.text;
    $('tourProgress').textContent = (index + 1) + ' / ' + tourSteps.length;
    $('tourProgress').setAttribute('aria-label', 'Step ' + (index + 1) + ' of ' + tourSteps.length);
    $('tourBack').disabled = index === 0;
    $('tourNext').textContent = index === tourSteps.length - 1 ? 'DONE' : 'NEXT';
    step.target.scrollIntoView({ behavior: 'auto', block: 'center', inline: 'nearest' });
    if (tourObserver) {
      tourObserver.disconnect();
      tourObserver.observe(step.target);
      if (step.compact) tourObserver.observe(step.compact);
      tourObserver.observe(tourCard);
    }
    positionTour();
    $('tourNext').focus({ preventScroll: true });
  }

  function cleanUpTour() {
    document.documentElement.classList.remove('tour-active');
    if (tourObserver) tourObserver.disconnect();
    if (tourFrame) { cancelAnimationFrame(tourFrame); tourFrame = 0; }
  }

  function endTour() {
    if (!tourDialog.open) return;
    tourDialog.close();
    cleanUpTour();
    var focus = tourReturnFocus && tourReturnFocus !== document.body && tourReturnFocus.isConnected
      ? tourReturnFocus : $('generateBtn');
    focus.focus();
  }

  function startTour() {
    if (tourDialog.open || busy) return;
    if (typeof tourDialog.showModal !== 'function') { tourReplay.style.display = 'none'; return; }
    tourReturnFocus = document.activeElement;
    document.documentElement.classList.add('tour-active');
    tourDialog.showModal();
    showTourStep(0);
  }

  tourReplay.addEventListener('click', startTour);
  $('tourSkip').addEventListener('click', endTour);
  $('tourBack').addEventListener('click', function () { if (tourIndex > 0) showTourStep(tourIndex - 1); });
  $('tourNext').addEventListener('click', function () {
    if (tourIndex === tourSteps.length - 1) endTour(); else showTourStep(tourIndex + 1);
  });
  tourDialog.addEventListener('cancel', function (e) { e.preventDefault(); endTour(); });
  tourDialog.addEventListener('close', function () { if (!tourDialog.open) cleanUpTour(); });
  tourDialog.addEventListener('keydown', function (e) {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === 'Tab') {
      var buttons = Array.from(tourCard.querySelectorAll('button:not(:disabled)'));
      var first = buttons[0];
      var last = buttons[buttons.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  });
  window.addEventListener('resize', queueTourPosition);
  window.addEventListener('scroll', queueTourPosition, true);
  window.addEventListener('beforeprint', endTour);

  // ------------------------------------------------------ wordmark parallax
  function initBannerParallax() {
    var stage = document.querySelector('.brand-lockup');
    var banner = stage && stage.querySelector('pre.banner');
    if (!banner) return;
    var enabled = window.matchMedia('(hover: hover) and (pointer: fine) and (min-width: 901px) and (prefers-reduced-motion: no-preference) and (forced-colors: none)');
    var frame = 0;
    var pointerX = 0;
    var pointerY = 0;

    function reset() {
      if (frame) cancelAnimationFrame(frame);
      frame = 0;
      stage.style.removeProperty('--banner-pitch');
      stage.style.removeProperty('--banner-yaw');
    }

    function paint() {
      frame = 0;
      if (!enabled.matches || document.hidden || tourDialog.open) { reset(); return; }
      var rect = stage.getBoundingClientRect();
      if (!rect.width || !rect.height) { reset(); return; }
      var x = Math.max(0, Math.min(1, (pointerX - rect.left) / rect.width));
      var y = Math.max(0, Math.min(1, (pointerY - rect.top) / rect.height));
      stage.style.setProperty('--banner-pitch', ((.5 - y) * 8).toFixed(2) + 'deg');
      stage.style.setProperty('--banner-yaw', ((x - .5) * 8).toFixed(2) + 'deg');
    }

    // Pointer batches schedule one frame; the wordmark never runs an idle loop.
    stage.addEventListener('pointermove', function (event) {
      if (event.pointerType !== 'mouse' || !enabled.matches) { reset(); return; }
      pointerX = event.clientX;
      pointerY = event.clientY;
      if (!frame) frame = requestAnimationFrame(paint);
    }, { passive: true });
    stage.addEventListener('pointerleave', reset);
    stage.addEventListener('pointercancel', reset);
    if (typeof enabled.addEventListener === 'function') enabled.addEventListener('change', reset);
    window.addEventListener('blur', reset);
    window.addEventListener('resize', reset);
    window.addEventListener('scroll', reset, { passive: true });
    document.addEventListener('visibilitychange', reset);
  }

  // --------------------------------------------------------------- hotkeys
  document.addEventListener('keydown', function (e) {
    if (tourDialog.open) return;
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
      case '1': if (current && current.chains.sol) { selectedChain = 'sol'; renderChainFocus(); } break;
      case '2': if (current && current.chains.eth) { selectedChain = 'eth'; renderChainFocus(); } break;
      case '3': if (current && current.chains.btc) { selectedChain = 'btc'; renderChainFocus(); } break;
    }
  });

  initBannerParallax();
  updateNetBadge();
  boot();
  startTour();
})();
