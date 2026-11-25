// Offline unit tests for HttpSource.headersBuilder(), KeiSource.configureHeaders(),
// and the optional `open.defaultUserAgent` parameter.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createDexvm } from '../dexvm-host.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const WASM = process.env.DEXVM_WASM || path.join(ROOT, 'dist', 'dexvm_bridge.wasm');
const FIXTURES = path.join(ROOT, 'test', 'fixtures');

const MANHUAGUI_162_APK = 'tachiyomi-zh.manhuagui-v1.6.2.apk';
const MANHUAGUI_162_SHA256 =
  'd346f335b3211d26edb00d7b09ace3ed59758f2c1a16926fbf61fb57f2543728';
const MANHUAGUI_EXPECTED_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';
const MANHUAGUI_EXPECTED_ACCEPT_LANG = 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7';

const wasmBytes = fs.readFileSync(WASM);

function headerMap(headers) {
  const map = new Map();
  for (const [k, v] of headers || []) {
    map.set(k.toLowerCase(), v);
  }
  return map;
}

async function captureFirstPopularRequest(apkName, openArgs = {}) {
  const captured = [];
  const vm = await createDexvm({
    wasmBytes,
    http: (reqJson) => {
      const req = JSON.parse(reqJson);
      captured.push(req);
      return JSON.stringify({
        status: 200,
        headers: [['content-type', 'text/html; charset=utf-8']],
        bodyBase64: Buffer.from('<html><body></body></html>').toString('base64'),
        finalUrl: req.url,
      });
    },
  });
  const apkBase64 = fs.readFileSync(path.join(FIXTURES, apkName)).toString('base64');
  const { handle } = vm.call('open', { apkBase64, ...openArgs });
  const sources = vm.call('sources', { handle });
  assert.ok(sources.length > 0, `${apkName} should expose at least one source`);
  try {
    vm.call('popular', { handle, sourceId: sources[0].id, page: 1 });
  } catch {
    // Empty mock HTML may fail parsing; we only inspect the outgoing HTTP request.
  }
  vm.call('close', { handle });
  assert.ok(captured.length > 0, `${apkName} should emit at least one host.http request`);
  return captured[0];
}

test('tachiyomi-zh.manhuagui-v1.6.2.apk matches pinned SHA-256', () => {
  const bytes = fs.readFileSync(path.join(FIXTURES, MANHUAGUI_162_APK));
  const sha = crypto.createHash('sha256').update(bytes).digest('hex');
  assert.equal(sha, MANHUAGUI_162_SHA256);
});

test('source overriding configureHeaders() sends configured headers to host.http', async () => {
  const req = await captureFirstPopularRequest(MANHUAGUI_162_APK);
  const hdrs = headerMap(req.headers);
  assert.equal(hdrs.get('user-agent'), MANHUAGUI_EXPECTED_UA);
  assert.equal(hdrs.get('accept-language'), MANHUAGUI_EXPECTED_ACCEPT_LANG);
  assert.equal(hdrs.get('referer'), 'https://www.manhuagui.com/');
});

test('configureHeaders() User-Agent overrides host defaultUserAgent', async () => {
  const req = await captureFirstPopularRequest(MANHUAGUI_162_APK, {
    defaultUserAgent: 'HostDefaultUA/1.0',
  });
  const hdrs = headerMap(req.headers);
  assert.equal(hdrs.get('user-agent'), MANHUAGUI_EXPECTED_UA);
});

test('source without configureHeaders() preserves no-UA default when defaultUserAgent is omitted', async () => {
  const req = await captureFirstPopularRequest('tachiyomi-en.mangapill-v1.4.9.apk');
  const hdrs = headerMap(req.headers);
  assert.equal(hdrs.has('user-agent'), false);
});

test('source without configureHeaders() uses host defaultUserAgent when provided', async () => {
  const req = await captureFirstPopularRequest('tachiyomi-en.mangapill-v1.4.9.apk', {
    defaultUserAgent: 'HostDefaultUA/1.0',
  });
  const hdrs = headerMap(req.headers);
  assert.equal(hdrs.get('user-agent'), 'HostDefaultUA/1.0');
});

test('MangaDex v1.6.5 does not receive a hardcoded browser UA', async () => {
  const req = await captureFirstPopularRequest('tachiyomi-all.mangadex-v1.6.5.apk');
  const hdrs = headerMap(req.headers);
  const ua = hdrs.get('user-agent') || '';
  assert.ok(!/Mozilla\/|Chrome\/|Safari\//.test(ua), `unexpected browser UA: ${ua}`);
});
