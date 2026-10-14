'use strict';

// Run from the repository with: node --test tests/*.test.cjs
const assert = require('node:assert/strict');
const { before, after, test } = require('node:test');
const { mkdtemp, mkdir, copyFile, writeFile, rm } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const http = require('node:http');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { once } = require('node:events');

let fixture;
let child;
let port;
let stderr = '';

function request(requestPath, method = 'GET') {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: requestPath, method, agent: false }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
      res.on('error', reject);
    });
    req.setTimeout(2000, () => req.destroy(new Error('request timeout')));
    req.on('error', reject);
    req.end();
  });
}

before(async () => {
  fixture = await mkdtemp(path.join(tmpdir(), 'fraser-server-test-'));
  const root = path.join(fixture, 'site');
  await mkdir(root);
  await mkdir(path.join(fixture, 'site-sibling'));
  await mkdir(path.join(root, 'node_modules'));
  await copyFile(path.join(__dirname, '..', 'server.js'), path.join(root, 'server.js'));
  await writeFile(path.join(root, 'index.html'), '<!doctype html><title>FRASER test fixture</title>');
  await writeFile(path.join(root, 'script.js'), '/* static test fixture */');
  await writeFile(path.join(root, 'space file.txt'), 'encoded filename');
  await writeFile(path.join(root, 'node_modules', 'fixture.txt'), 'excluded fixture');
  await writeFile(path.join(fixture, 'outside.txt'), 'outside root');
  await writeFile(path.join(fixture, 'site-sibling', 'outside.txt'), 'outside root sibling');

  // Reserve an ephemeral loopback port without changing the server's PORT API.
  const reservation = net.createServer();
  reservation.listen(0, '127.0.0.1');
  await once(reservation, 'listening');
  port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  child = spawn(process.execPath, [path.join(root, 'server.js')], {
    env: { PORT: String(port) }, stdio: ['ignore', 'pipe', 'pipe']
  });
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', chunk => { stderr += chunk; });
  await new Promise((resolve, reject) => {
    let stdout = '';
    const timer = setTimeout(() => finish(new Error('server startup timeout')), 3000);
    const onError = err => finish(err);
    const onExit = code => finish(new Error('server exited at startup: ' + code + ' ' + stderr));
    const onData = chunk => {
      stdout += chunk;
      if (stdout.includes('http://127.0.0.1:' + port)) finish();
    };
    function finish(err) {
      clearTimeout(timer);
      child.removeListener('error', onError);
      child.removeListener('exit', onExit);
      child.stdout.removeListener('data', onData);
      if (err) reject(err); else resolve();
    }
    child.once('error', onError);
    child.once('exit', onExit);
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', onData);
  });
}, { timeout: 5000 });

after(async () => {
  if (child && child.exitCode === null && child.signalCode === null) {
    const exit = once(child, 'exit');
    child.kill();
    await exit;
  }
  if (fixture) await rm(fixture, { recursive: true, force: true });
});

test('ordinary GET/HEAD, query strings and encoded filenames still work', async () => {
  for (const method of ['GET', 'HEAD']) {
    const res = await request('/', method);
    assert.equal(res.status, 200);
    assert.equal(res.headers['content-type'], 'text/html; charset=utf-8');
    assert.equal(res.headers['cache-control'], 'no-store');
    assert.equal(res.headers['x-content-type-options'], 'nosniff');
    assert.equal(res.body, method === 'HEAD' ? '' : '<!doctype html><title>FRASER test fixture</title>');
  }
  assert.equal((await request('/script.js')).headers['content-type'], 'text/javascript; charset=utf-8');
  assert.equal((await request('/space%20file.txt')).body, 'encoded filename');
  assert.equal((await request('/index.html?ignored=%ZZ')).status, 200);
});

test('malformed encodings and decoded NUL return 400 without stopping the process', async t => {
  for (const method of ['GET', 'HEAD']) {
    for (const requestPath of ['/%', '/%ZZ', '/%E0%A4', '/%C0%AF', '/%ED%A0%80', '/%00', '/index.html%00', '/nested/%00/file']) {
      await t.test(method + ' ' + requestPath, async () => {
        const res = await request(requestPath, method);
        assert.equal(res.status, 400);
        assert.equal(res.body, method === 'HEAD' ? '' : 'bad request');
        assert.equal(child.exitCode, null, stderr);
        assert.equal((await request('/')).status, 200);
      });
    }
  }
});

test('traversal, missing files and unsupported methods retain their rejection behavior', async () => {
  for (const requestPath of ['/../outside.txt', '/%2e%2e/outside.txt', '/..%2foutside.txt', '/..%2fsite-sibling%2foutside.txt', '/node_modules/fixture.txt', '/missing', '/%2500', '/%252e%252e/outside.txt']) {
    assert.equal((await request(requestPath)).status, 404, requestPath);
  }
  for (const method of ['POST', 'PUT', 'DELETE', 'OPTIONS']) {
    assert.equal((await request('/%ZZ', method)).status, 405, method);
  }
  assert.equal((await request('/')).status, 200);
});
