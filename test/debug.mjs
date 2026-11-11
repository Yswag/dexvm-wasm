// test/debug.mjs <apk> [sourceIndex] — verbose single-source trace.
//
// Logs every host.http exchange (method, URL, header names, status, bytes) and
// the wasm-side log stream, then runs popular → details → chapters → pages.
//
//   DEXVM_LOG=1 node test/debug.mjs test/fixtures/tachiyomi-zh.komiic-v1.6.11.apk
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { createDexvm } from '../dexvm-host.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const WASM = process.env.DEXVM_WASM || path.join(ROOT, 'dist', 'dexvm_bridge.wasm');
const APK = process.argv[2];
const WANT = process.argv[3] !== undefined ? Number(process.argv[3]) : null;
const LOG_LEVEL = Number(process.env.DEXVM_LOG || 3);
const WORK = path.join(os.tmpdir(), 'dexvm-debug');
fs.mkdirSync(WORK, { recursive: true });

let n = 0;
function http(reqJson) {
  const req = JSON.parse(reqJson);
  n++;
  const tag = `[http ${n}] ${req.method} ${req.url}`;
  const hdrs = (req.headers || []).map(([k]) => k).join(',');
  console.log(`${tag}${hdrs ? `  headers: ${hdrs}` : '  (no headers)'}`);
  if (req.bodyBase64) console.log(`         body: ${Buffer.from(req.bodyBase64, 'base64').length} B`);

  const id = `${process.pid}-${n}`;
  const bodyFile = path.join(WORK, `b-${id}`);
  const args = ['-sS', '--max-time', '40', '-o', bodyFile, '-w', '%{http_code}'];
  for (const [k, v] of req.headers || []) args.push('-H', `${k}: ${v}`);
  if (req.bodyBase64) {
    fs.writeFileSync(`${bodyFile}.req`, Buffer.from(req.bodyBase64, 'base64'));
    args.push('--data-binary', `@${bodyFile}.req`);
  }
  if ((req.method || 'GET').toUpperCase() !== 'GET') args.push('-X', req.method);
  args.push(req.url);
  let status = 0;
  try {
    status = parseInt(execFileSync('curl', args, { encoding: 'utf8' }).trim(), 10) || 0;
  } catch (e) {
    const msg = String(e.stderr || e.message).trim().split('\n').pop();
    console.log(`         -> curl failed: ${msg}`);
    return JSON.stringify({ error: `curl: ${msg}` });
  }
  const body = fs.existsSync(bodyFile) ? fs.readFileSync(bodyFile) : Buffer.alloc(0);
  console.log(`         -> ${status}  ${body.length} B  ${JSON.stringify(body.subarray(0, 60).toString('utf8').replace(/\s+/g, ' ').slice(0, 60))}`);
  return JSON.stringify({
    status,
    headers: [['content-type', 'text/html']],
    bodyBase64: body.toString('base64'),
    finalUrl: req.url,
  });
}

const vm = await createDexvm({
  wasmBytes: fs.readFileSync(WASM),
  http,
  log: (lvl, msg) => {
    if (lvl <= LOG_LEVEL || lvl >= 3) console.log(`[wasm ${lvl}] ${msg}`);
  },
  evalJs: (src) => {
    try {
      return JSON.stringify({ ok: true, value: new Function(`"use strict"; return (${src}\n);`)() });
    } catch (e) {
      return JSON.stringify({ ok: false, error: String(e.message) });
    }
  },
});

const t0 = performance.now();
const opened = vm.call('open', { apkBase64: fs.readFileSync(APK).toString('base64'), logLevel: LOG_LEVEL });
console.log(`open ${Math.round(performance.now() - t0)}ms  ${opened.manifest?.packageId} v${opened.manifest?.versionName}`);

const sources = vm.call('sources', { handle: opened.handle });
console.log('sources:', sources.map((s, i) => `${i}:${s.name}/${s.lang}`).join(', '));

for (const [i, src] of sources.entries()) {
  if (WANT !== null && i !== WANT) continue;
  console.log(`\n=== [${i}] ${src.name} (${src.lang}) id=${src.id} base=${src.baseUrl}`);
  const t = performance.now();
  try {
    const pop = vm.call('popular', { handle: opened.handle, sourceId: src.id, page: 1 });
    console.log(`popular: ${pop.mangas.length} mangas, hasNext=${pop.hasNextPage} (${Math.round(performance.now() - t)}ms)`);
    if (!pop.mangas.length) continue;
    let done = false;
    for (const manga of pop.mangas.slice(0, 3)) {
      console.log(`  try: ${manga.title}  ${manga.url}`);
      vm.call('details', { handle: opened.handle, sourceId: src.id, manga });
      const chs = vm.call('chapters', { handle: opened.handle, sourceId: src.id, manga });
      console.log(`  chapters: ${chs.length}`);
      if (!chs.length) continue;
      const pages = vm.call('pages', { handle: opened.handle, sourceId: src.id, chapter: chs[0] });
      console.log(`  pages: ${pages.length}`);
      if (pages.length) {
        const img = vm.call('imageUrl', { handle: opened.handle, sourceId: src.id, page: pages[0] });
        console.log(`  imageUrl: ${(img.imageUrl || '').slice(0, 80)}`);
        const fetched = vm.call('fetchImage', { handle: opened.handle, sourceId: src.id, page: pages[0] });
        console.log(`  image: ${fetched.bytes}B ${fetched.mime || '?'} ${(fetched.base64 || '').slice(0, 24)}`);
        done = true;
        break;
      }
    }
    if (!done) console.log('  (no chapters/pages in the first 3 mangas)');
  } catch (e) {
    console.log(`FAILED after ${Math.round(performance.now() - t)}ms: ${e.message}`);
  }
}
vm.call('close', { handle: opened.handle });
