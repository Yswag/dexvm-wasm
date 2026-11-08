// test/run.mjs — end-to-end driver for dist/dexvm_bridge.wasm.
//
// Network is provided by the host (this file): every `host.http` import is
// answered by a *synchronous* curl call (execFileSync) — the wasm side never
// touches the network, and no SharedArrayBuffer/Atomics are involved.
//
//   node test/run.mjs fixtures       # 5 apks in fixtures/: open + sources + filters
//   node test/run.mjs live           # en.mangapill + all.comicfury full flow
//   node test/run.mjs index          # 10 popular sources from keiyoushi index
//   node test/run.mjs all            # everything, prints the result table
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createDexvm } from '../dexvm-host.js';

const ROOT = new URL('..', import.meta.url).pathname;
function findWasm() {
  if (process.env.DEXVM_WASM) return process.env.DEXVM_WASM;
  const candidates = [
    path.join(ROOT, 'dist', 'dexvm_bridge.wasm'),
    path.join(ROOT, 'dexvm-bridge', 'target', 'wasm32-wasip1', 'release', 'dexvm_bridge.wasm'),
  ];
  const hit = candidates.find((p) => fs.existsSync(p));
  if (!hit) {
    console.error('dexvm_bridge.wasm not found. Run scripts/build.sh (or set DEXVM_WASM).');
    process.exit(1);
  }
  return hit;
}
const WASM = findWasm();
const FIXTURES = process.env.DEXVM_FIXTURES || path.join(ROOT, 'test', 'fixtures');
const WORK = process.env.DEXVM_WORK || path.join(os.tmpdir(), 'dexvm-run');
const CURL = process.env.DEXVM_CURL || 'curl';

fs.mkdirSync(WORK, { recursive: true });

// ---------------------------------------------------------------------------
// synchronous HTTP through curl
// ---------------------------------------------------------------------------
const cookieJar = new Map(); // host -> Map(name -> value)

function hostOf(url) {
  try {
    return new URL(url).host;
  } catch {
    return '';
  }
}

function cookieHeader(url) {
  const jar = cookieJar.get(hostOf(url));
  if (!jar || jar.size === 0) return null;
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
}

function storeCookies(url, lines) {
  const host = hostOf(url);
  let jar = cookieJar.get(host);
  for (const line of lines) {
    const m = /^set-cookie:\s*([^=;\s]+)=([^;]*)/i.exec(line);
    if (!m) continue;
    if (!jar) cookieJar.set(host, (jar = new Map()));
    jar.set(m[1], m[2]);
  }
}

let httpCount = 0;
let httpBytes = 0;

function syncHttp(reqJson) {
  const req = JSON.parse(reqJson);
  httpCount++;
  const id = `${process.pid}-${httpCount}`;
  const bodyFile = path.join(WORK, `body-${id}.bin`);
  const hdrFile = path.join(WORK, `hdr-${id}.txt`);
  const args = ['-sS', '--max-time', '60', '-D', hdrFile, '-o', bodyFile];
  const method = (req.method || 'GET').toUpperCase();
  if (method !== 'GET') args.push('-X', method);
  const headers = [...(req.headers || [])];
  const hasUA = headers.some(([k]) => k.toLowerCase() === 'user-agent');
  if (!hasUA) headers.push(['User-Agent', 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1']);
  const ck = cookieHeader(req.url);
  if (ck && !headers.some(([k]) => k.toLowerCase() === 'cookie')) headers.push(['Cookie', ck]);
  for (const [k, v] of headers) args.push('-H', `${k}: ${v}`);
  if (req.bodyBase64) {
    const raw = Buffer.from(req.bodyBase64, 'base64');
    fs.writeFileSync(bodyFile + '.req', raw);
    args.push('--data-binary', '@' + bodyFile + '.req');
  }
  args.push(req.url);
  let status = 0;
  try {
    const out = execFileSync(CURL, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    status = parseInt(out.trim(), 10) || 0;
  } catch (e) {
    // curl exits non-zero on transport errors; -w is not set, so derive nothing
    const msg = (e.stderr || '').toString().trim().split('\n').pop() || String(e.message);
    return JSON.stringify({ error: `curl: ${msg}` });
  }
  let hdrText = '';
  try {
    hdrText = fs.readFileSync(hdrFile, 'utf8');
  } catch {}
  const headerLines = hdrText.split(/\r?\n/).filter((l) => l.includes(':'));
  // keep only the last response block (redirects emit several)
  const blocks = hdrText.split(/\r?\n\r?\n/).filter((b) => b.trim());
  const lastBlock = blocks.length ? blocks[blocks.length - 1] : '';
  const finalHeaders = (lastBlock || hdrText)
    .split(/\r?\n/)
    .filter((l) => l.includes(':'))
    .map((l) => {
      const i = l.indexOf(':');
      return [l.slice(0, i).trim(), l.slice(i + 1).trim()];
    });
  storeCookies(req.url, headerLines);
  const body = fs.existsSync(bodyFile) ? fs.readFileSync(bodyFile) : Buffer.alloc(0);
  httpBytes += body.length;
  try {
    fs.unlinkSync(bodyFile);
    fs.unlinkSync(hdrFile);
  } catch {}
  return JSON.stringify({
    status,
    headers: finalHeaders,
    bodyBase64: body.toString('base64'),
    finalUrl: req.url,
  });
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
const enc = (b) => Buffer.from(b).toString('base64');
const ms = (t0) => Math.round((performance.now() - t0) * 10) / 10;

async function newVm() {
  return createDexvm({
    wasmBytes: fs.readFileSync(WASM),
    http: syncHttp,
    log: (lvl, msg) => {
      if (process.env.DEXVM_LOG && lvl >= Number(process.env.DEXVM_LOG)) console.error(`[wasm] ${msg}`);
    },
    evalJs: (src) => {
      try {
        const v = new Function(`"use strict"; return (${src}\n);`)();
        return JSON.stringify({ ok: true, value: v === undefined ? null : v });
      } catch (e) {
        return JSON.stringify({ ok: false, error: String(e && e.message) });
      }
    },
  });
}

async function openApk(vm, apkPath) {
  const t = performance.now();
  const opened = vm.call('open', { apkBase64: enc(fs.readFileSync(apkPath)) });
  return { ...opened, ms: ms(t), path: apkPath };
}

const rows = [];
function record(row) {
  rows.push(row);
  const status = row.error ? 'FAIL' : 'ok  ';
  console.log(
    `${status} ${row.name.padEnd(28)} ${String(row.mangas ?? '-').padStart(4)} mangas ` +
      `${String(row.chapters ?? '-').padStart(4)} ch ${String(row.pages ?? '-').padStart(3)} pg ` +
      `${row.image ? 'img ' + row.image : ''} ${row.ms != null ? row.ms + 'ms' : ''}` +
      (row.error ? `  <- ${row.error}` : '')
  );
}

function short(e) {
  const m = e && e.message ? e.message : String(e);
  return m.replace(/\s+/g, ' ').slice(0, 260);
}

// Full source flow; `img` = also fetch the first page image.
async function runSource(vm, handle, source, { img = true } = {}) {
  const row = { name: `${source.name} (${source.lang})`, id: source.id };
  const t = performance.now();
  try {
    const pop = vm.call('popular', { handle, sourceId: source.id, page: 1 });
    row.mangas = pop.mangas.length;
    if (!pop.mangas.length) throw new Error('popular returned 0 mangas');
    // Some language sub-sources have no entries for the first popular manga;
    // try up to three before declaring the source broken.
    let manga = null, chapters = [], pages = [], details = null;
    for (const candidate of pop.mangas.slice(0, 3)) {
      details = vm.call('details', { handle, sourceId: source.id, manga: candidate });
      const chs = vm.call('chapters', { handle, sourceId: source.id, manga: candidate });
      if (!chs.length) continue;
      const pgs = vm.call('pages', { handle, sourceId: source.id, chapter: chs[0] });
      if (!pgs.length) continue;
      manga = candidate; chapters = chs; pages = pgs; break;
    }
    if (!manga) throw new Error('no chapters/pages in the first 3 mangas');
    row.title = manga.title;
    row.details = details.title;
    row.chapters = chapters.length;
    row.pages = pages.length;
    const page = pages[0];

    const url = vm.call('imageUrl', { handle, sourceId: source.id, page });
    row.imageUrl = (url.imageUrl || '').slice(0, 60);

    if (img) {
      const fetched = vm.call('fetchImage', { handle, sourceId: source.id, page });
      row.image = `${fetched.bytes}B ${(fetched.mime || '?').split(';')[0]} ${fetched.base64.slice(0, 0)}`.trim();
      row.imageB64 = fetched.base64;
      row.imageMime = fetched.mime;
    }
  } catch (e) {
    row.error = short(e);
  }
  row.ms = ms(t);
  record(row);
  return row;
}

// ---------------------------------------------------------------------------
// modes
// ---------------------------------------------------------------------------
const FIXTURE_APKS = [
  'tachiyomi-en.mangapill-v1.4.9.apk',
  'tachiyomi-all.comicfury-v1.4.8.apk',
  'tachiyomi-all.akuma-v1.4.10.apk',
  'tachiyomi-vi.cuutruyenmoe-v1.6.3.apk',
  'tachiyomi-vi.moetruyen-v1.6.8.apk',
];

async function modeFixtures() {
  const vm = await newVm();
  const out = [];
  for (const apk of FIXTURE_APKS) {
    const p = path.join(FIXTURES, apk);
    const t = performance.now();
    try {
      const opened = await openApk(vm, p);
      const sources = vm.call('sources', { handle: opened.handle });
      out.push({
        apk,
        openMs: Math.round(opened.ms),
        sourcesMs: ms(t + opened.ms),
        packageId: opened.manifest && opened.manifest.packageId,
        version: opened.manifest && opened.manifest.versionName,
        sources,
      });
      console.log(
        `ok   ${apk.padEnd(40)} open ${Math.round(opened.ms)}ms  ` +
          sources.map((s) => `${s.name}/${s.lang}/id=${s.id}`).join(', ')
      );
      vm.call('close', { handle: opened.handle });
    } catch (e) {
      console.log(`FAIL ${apk.padEnd(40)} ${short(e)}`);
      out.push({ apk, error: short(e) });
    }
  }
  return out;
}

async function modeLive() {
  const vm = await newVm();
  for (const apk of ['tachiyomi-en.mangapill-v1.4.9.apk', 'tachiyomi-all.comicfury-v1.4.8.apk']) {
    const t0 = performance.now();
    const opened = await openApk(vm, path.join(FIXTURES, apk));
    // cold start = open + first sources
    const cold = performance.now() - t0;
    const sources = vm.call('sources', { handle: opened.handle });
    console.log(`\n== ${apk}  cold-start(open+sources) ${Math.round(performance.now() - t0)}ms (open ${Math.round(opened.ms)}ms)`);
    for (const s of sources) {
      await runSource(vm, opened.handle, s, { img: true });
    }
    vm.call('close', { handle: opened.handle });
    console.log(`   cold-start measured: ${Math.round(cold)}ms (without sources call)`);
  }
}

async function modeIndex(limit = 10) {
  const listPath = path.join(WORK, 'index.html');
  if (!fs.existsSync(listPath)) {
    console.log('downloading keiyoushi listing…');
    execFileSync(CURL, ['-sSL', '--max-time', '120', '-o', listPath,
      'https://raw.githubusercontent.com/keiyoushi/extensions/repo/index.html']);
  }
  const html = fs.readFileSync(listPath, 'utf8');
  const all = [...html.matchAll(/<a href="([^"]+\.apk)">([^<]*)<\/a>/g)].map((m) => {
    const apk = m[1].split('/').pop();
    const lang = (/^tachiyomi-([^.]+)\./.exec(apk) || [])[1] || '';
    return { url: m[1], apk, lang, name: m[2].replace(/^Tachiyomi:\s*/, '') };
  });
  console.log(`index entries: ${all.length}`);
  const picks = pickSources(all, limit);
  console.log('picked:', picks.map((p) => `${p.name} [${p.lang}]`).join(', '), '\n');
  const vm = await newVm();
  const results = [];
  for (const entry of picks) {
    const apkPath = path.join(WORK, entry.apk);
    if (!fs.existsSync(apkPath)) {
      try {
        execFileSync(CURL, ['-sSL', '--max-time', '180', '-o', apkPath, entry.url]);
      } catch (e) {
        record({ name: entry.name, error: `download failed: ${short(e)}` });
        continue;
      }
    }
    try {
      const opened = await openApk(vm, apkPath);
      const sources = vm.call('sources', { handle: opened.handle });
      for (const s of sources) {
        const row = await runSource(vm, opened.handle, s, { img: true });
        row.name = `${s.name} (${s.lang})`;
        row.apk = entry.apk;
        results.push(row);
      }
      vm.call('close', { handle: opened.handle });
    } catch (e) {
      record({ name: entry.name, error: short(e) });
      results.push({ name: entry.name, error: short(e) });
    }
  }
  return results;
}

// 10 popular sources: 4 Chinese, 2 of which are known to descramble/relocate
// images, plus the mainstream English ones and comicfury.
const WANTED = [
  'tachiyomi-zh.baozimanhua',
  'tachiyomi-zh.manhuagui',
  'tachiyomi-zh.dm5',
  'tachiyomi-zh.komiic',
  'tachiyomi-en.mangapill',
  'tachiyomi-en.comickfan',
  'tachiyomi-en.asurascans',
  'tachiyomi-en.weebcentral',
  'tachiyomi-en.mangadex',
  'tachiyomi-all.comicfury',
];

function pickSources(all, limit) {
  const picks = [];
  const add = (e) => {
    if (e && !picks.find((p) => p.apk === e.apk)) picks.push(e);
  };
  for (const w of WANTED) {
    add(all.find((e) => e.apk.startsWith(w)));
  }
  for (const e of all) {
    if (picks.length >= limit) break;
    add(e);
  }
  return picks.slice(0, limit);
}

// ---------------------------------------------------------------------------
async function main() {
  const mode = process.argv[2] || 'all';
  const started = performance.now();
  const summary = {};
  if (mode === 'fixtures' || mode === 'all') summary.fixtures = await modeFixtures();
  if (mode === 'live' || mode === 'all') await modeLive();
  if (mode === 'index' || mode === 'all') summary.index = await modeIndex();
  console.log(`\nhttp requests: ${httpCount}, bytes: ${(httpBytes / 1024 / 1024).toFixed(1)} MiB`);
  console.log(`total: ${(ms(started) / 1000).toFixed(1)}s`);
  fs.writeFileSync(path.join(WORK, 'result.json'), JSON.stringify({ summary, rows }, null, 2));
  console.log(`rows written to ${path.join(WORK, 'result.json')} (${rows.length} rows)`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
