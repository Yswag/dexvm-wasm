// Offline reproduction tests for v0.2.6 fixes (#1-#7):
// 1. New `headers` op returning HttpSource.headers (with defaultUserAgent fallback only when absent).
// 2. `imageRequest` returns the exact outgoing headers (not clobbered by defaultUserAgent)
//    and makes 0 real HTTP requests when `page.imageUrl` is already set.
// 3. `System.getProperty("http.agent")` returns an Android Dalvik UA string (not null).
// 4. Jsoup `Element.children()` returns only child Elements (excluding text/comment nodes).
// 5. `Integer` & `Long` bit helpers (`numberOfLeadingZeros`, `numberOfTrailingZeros`, `highestOneBit`, `lowestOneBit`, `bitCount`).
// 6. `fetchImage` with a populated `page.imageUrl` makes exactly 1 HTTP request (never refetches `page.url`).
// 7. `java.util.TimeZone.getID()`, `getRawOffset()`, `getOffset(long)`, `getDefault()`, `getTimeZone(String)`.
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
const wasmBytes = fs.readFileSync(WASM);

function uleb128(n) {
  const out = [];
  do {
    let b = n & 0x7f;
    n >>>= 7;
    if (n !== 0) b |= 0x80;
    out.push(b);
  } while (n !== 0);
  return out;
}

function adler32(buf) {
  let a = 1;
  let b = 0;
  for (let i = 0; i < buf.length; i++) {
    a = (a + buf[i]) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
}

function buildTestDex({
  extraStrings = [],
  extraTypes = [],
  extraProtos = [],
  extraFields = [],
  extraMethods = [],
  customGetName = null,
}) {
  const baseStrings = [
    '<init>',
    'J',
    'L',
    'Leu/kanade/tachiyomi/source/online/HttpSource;',
    'Ljava/lang/String;',
    'Ltest/ProbeSource;',
    'ProbeSource',
    'V',
    'Z',
    'en',
    'getBaseUrl',
    'getId',
    'getLang',
    'getName',
    'getSupportsLatest',
    'https://probe.test',
  ];
  const strings = [...new Set([...baseStrings, ...extraStrings])].sort((a, b) =>
    Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'))
  );
  const sIdx = (s) => {
    const i = strings.indexOf(s);
    if (i < 0) throw new Error(`missing string: ${s}`);
    return i;
  };

  const baseTypes = [
    'J',
    'Leu/kanade/tachiyomi/source/online/HttpSource;',
    'Ljava/lang/String;',
    'Ltest/ProbeSource;',
    'V',
    'Z',
  ];
  const types = [...new Set([...baseTypes, ...extraTypes])].sort((a, b) => sIdx(a) - sIdx(b));
  const tIdx = (t) => {
    const i = types.indexOf(t);
    if (i < 0) throw new Error(`missing type: ${t}`);
    return i;
  };

  const protoMap = new Map();
  const addProto = (shorty, ret, params) => {
    const key = `${ret}|${params.join(',')}`;
    if (!protoMap.has(key)) protoMap.set(key, [shorty, ret, params]);
  };
  addProto('J', 'J', []);
  addProto('L', 'Ljava/lang/String;', []);
  addProto('V', 'V', []);
  addProto('Z', 'Z', []);
  for (const [shorty, ret, params] of extraProtos) addProto(shorty, ret, params);

  const protos = [...protoMap.values()].sort((a, b) => {
    const r = tIdx(a[1]) - tIdx(b[1]);
    if (r !== 0) return r;
    const len = Math.min(a[2].length, b[2].length);
    for (let i = 0; i < len; i++) {
      const p = tIdx(a[2][i]) - tIdx(b[2][i]);
      if (p !== 0) return p;
    }
    return a[2].length - b[2].length;
  });
  const pIdx = (ret, params) => {
    const key = `${ret}|${params.join(',')}`;
    const i = protos.findIndex(([, r, p]) => `${r}|${p.join(',')}` === key);
    if (i < 0) throw new Error(`missing proto: ${key}`);
    return i;
  };

  const fields = [...extraFields].sort((a, b) => {
    const c = tIdx(a[0]) - tIdx(b[0]);
    if (c !== 0) return c;
    const n = sIdx(a[2]) - sIdx(b[2]);
    if (n !== 0) return n;
    return tIdx(a[1]) - tIdx(b[1]);
  });

  const allMethods = [
    ['Leu/kanade/tachiyomi/source/online/HttpSource;', 'V', [], '<init>'],
    ['Ltest/ProbeSource;', 'V', [], '<init>'],
    ['Ltest/ProbeSource;', 'Ljava/lang/String;', [], 'getBaseUrl'],
    ['Ltest/ProbeSource;', 'J', [], 'getId'],
    ['Ltest/ProbeSource;', 'Ljava/lang/String;', [], 'getLang'],
    ['Ltest/ProbeSource;', 'Ljava/lang/String;', [], 'getName'],
    ['Ltest/ProbeSource;', 'Z', [], 'getSupportsLatest'],
    ...extraMethods,
  ].sort((a, b) => {
    const c = tIdx(a[0]) - tIdx(b[0]);
    if (c !== 0) return c;
    const n = sIdx(a[3]) - sIdx(b[3]);
    if (n !== 0) return n;
    return pIdx(a[1], a[2]) - pIdx(b[1], b[2]);
  });
  const mIdx = (cls, name, ret = null, params = null) => {
    const i = allMethods.findIndex(
      ([c, r, p, n]) =>
        c === cls &&
        n === name &&
        (ret === null || r === ret) &&
        (params === null || p.join(',') === params.join(','))
    );
    if (i < 0) throw new Error(`missing method: ${cls}.${name}`);
    return i;
  };

  const helpers = { sIdx, tIdx, mIdx };
  const probeMethods = [
    {
      idx: mIdx('Ltest/ProbeSource;', '<init>'),
      direct: true,
      access: 0x10001,
      code: {
        regs: 1,
        ins: 1,
        outs: 1,
        insns: [0x1070, mIdx('Leu/kanade/tachiyomi/source/online/HttpSource;', '<init>'), 0x0000, 0x000e],
      },
    },
    {
      idx: mIdx('Ltest/ProbeSource;', 'getBaseUrl'),
      direct: false,
      access: 0x1,
      code: { regs: 2, ins: 1, outs: 0, insns: [0x001a, sIdx('https://probe.test'), 0x0011] },
    },
    {
      idx: mIdx('Ltest/ProbeSource;', 'getId'),
      direct: false,
      access: 0x1,
      code: { regs: 3, ins: 1, outs: 0, insns: [0x0016, 77, 0x0010] },
    },
    {
      idx: mIdx('Ltest/ProbeSource;', 'getLang'),
      direct: false,
      access: 0x1,
      code: { regs: 2, ins: 1, outs: 0, insns: [0x001a, sIdx('en'), 0x0011] },
    },
    {
      idx: mIdx('Ltest/ProbeSource;', 'getName'),
      direct: false,
      access: 0x1,
      code: customGetName
        ? customGetName(helpers)
        : { regs: 2, ins: 1, outs: 0, insns: [0x001a, sIdx('ProbeSource'), 0x0011] },
    },
    {
      idx: mIdx('Ltest/ProbeSource;', 'getSupportsLatest'),
      direct: false,
      access: 0x1,
      code: { regs: 2, ins: 1, outs: 0, insns: [0x0012, 0x000f] },
    },
  ];

  const headerSize = 0x70;
  const stringIdsOff = headerSize;
  const typeIdsOff = stringIdsOff + strings.length * 4;
  const protoIdsOff = typeIdsOff + types.length * 4;
  const fieldIdsOff = protoIdsOff + protos.length * 12;
  const methodIdsOff = fieldIdsOff + fields.length * 8;
  const classDefsOff = methodIdsOff + allMethods.length * 8;
  const dataOff = classDefsOff + 32;

  const chunks = [];
  let cursor = dataOff;
  const pushBytes = (arr) => {
    const off = cursor;
    const b = Buffer.from(arr);
    chunks.push(b);
    cursor += b.length;
    return off;
  };
  const align4 = () => {
    const pad = (4 - (cursor % 4)) % 4;
    if (pad) pushBytes(new Uint8Array(pad));
  };

  const protoParamOffs = protos.map(([, , params]) => {
    if (!params.length) return 0;
    align4();
    const buf = Buffer.alloc(4 + params.length * 2);
    buf.writeUInt32LE(params.length, 0);
    params.forEach((p, idx) => buf.writeUInt16LE(tIdx(p), 4 + idx * 2));
    return pushBytes(buf);
  });

  const stringDataOffs = strings.map((s) => {
    const utf8 = Buffer.from(s, 'utf8');
    return pushBytes([...uleb128(s.length), ...utf8, 0]);
  });

  const codeOffs = probeMethods.map(({ code }) => {
    align4();
    const buf = Buffer.alloc(16 + code.insns.length * 2);
    buf.writeUInt16LE(code.regs, 0);
    buf.writeUInt16LE(code.ins, 2);
    buf.writeUInt16LE(code.outs, 4);
    buf.writeUInt16LE(0, 6);
    buf.writeUInt32LE(0, 8);
    buf.writeUInt32LE(code.insns.length, 12);
    code.insns.forEach((w, idx) => buf.writeUInt16LE(w, 16 + idx * 2));
    return pushBytes(buf);
  });

  const direct = probeMethods
    .map((m, i) => ({ ...m, codeOff: codeOffs[i] }))
    .filter((m) => m.direct)
    .sort((a, b) => a.idx - b.idx);
  const virtual = probeMethods
    .map((m, i) => ({ ...m, codeOff: codeOffs[i] }))
    .filter((m) => !m.direct)
    .sort((a, b) => a.idx - b.idx);

  const encodeMethodList = (list) => {
    const out = [];
    let prev = 0;
    for (const m of list) {
      out.push(...uleb128(m.idx - prev), ...uleb128(m.access), ...uleb128(m.codeOff));
      prev = m.idx;
    }
    return out;
  };
  const classData = [
    ...uleb128(0),
    ...uleb128(0),
    ...uleb128(direct.length),
    ...uleb128(virtual.length),
    ...encodeMethodList(direct),
    ...encodeMethodList(virtual),
  ];
  const classDataOff = pushBytes(classData);
  align4();

  const mapOff = cursor;
  const mapBuf = Buffer.alloc(16);
  mapBuf.writeUInt32LE(1, 0);
  mapBuf.writeUInt16LE(0x1000, 4);
  mapBuf.writeUInt32LE(1, 8);
  mapBuf.writeUInt32LE(mapOff, 12);
  pushBytes(mapBuf);

  const fileSize = cursor;
  const dex = Buffer.alloc(fileSize);

  Buffer.from('dex\n035\0', 'ascii').copy(dex, 0);
  dex.writeUInt32LE(fileSize, 32);
  dex.writeUInt32LE(headerSize, 36);
  dex.writeUInt32LE(0x12345678, 40);
  dex.writeUInt32LE(mapOff, 52);
  dex.writeUInt32LE(strings.length, 56);
  dex.writeUInt32LE(stringIdsOff, 60);
  dex.writeUInt32LE(types.length, 64);
  dex.writeUInt32LE(typeIdsOff, 68);
  dex.writeUInt32LE(protos.length, 72);
  dex.writeUInt32LE(protoIdsOff, 76);
  dex.writeUInt32LE(fields.length, 80);
  dex.writeUInt32LE(fields.length ? fieldIdsOff : 0, 84);
  dex.writeUInt32LE(allMethods.length, 88);
  dex.writeUInt32LE(methodIdsOff, 92);
  dex.writeUInt32LE(1, 96);
  dex.writeUInt32LE(classDefsOff, 100);
  dex.writeUInt32LE(fileSize - dataOff, 104);
  dex.writeUInt32LE(dataOff, 108);

  stringDataOffs.forEach((off, i) => dex.writeUInt32LE(off, stringIdsOff + i * 4));
  types.forEach((t, i) => dex.writeUInt32LE(sIdx(t), typeIdsOff + i * 4));
  protos.forEach(([shorty, ret], i) => {
    const o = protoIdsOff + i * 12;
    dex.writeUInt32LE(sIdx(shorty), o);
    dex.writeUInt32LE(tIdx(ret), o + 4);
    dex.writeUInt32LE(protoParamOffs[i], o + 8);
  });
  fields.forEach(([cls, ty, name], i) => {
    const o = fieldIdsOff + i * 8;
    dex.writeUInt16LE(tIdx(cls), o);
    dex.writeUInt16LE(tIdx(ty), o + 2);
    dex.writeUInt32LE(sIdx(name), o + 4);
  });
  allMethods.forEach(([cls, ret, params, name], i) => {
    const o = methodIdsOff + i * 8;
    dex.writeUInt16LE(tIdx(cls), o);
    dex.writeUInt16LE(pIdx(ret, params), o + 2);
    dex.writeUInt32LE(sIdx(name), o + 4);
  });

  dex.writeUInt32LE(tIdx('Ltest/ProbeSource;'), classDefsOff);
  dex.writeUInt32LE(0x1, classDefsOff + 4);
  dex.writeUInt32LE(tIdx('Leu/kanade/tachiyomi/source/online/HttpSource;'), classDefsOff + 8);
  dex.writeUInt32LE(0xffffffff, classDefsOff + 16);
  dex.writeUInt32LE(classDataOff, classDefsOff + 24);

  let pos = dataOff;
  for (const c of chunks) {
    c.copy(dex, pos);
    pos += c.length;
  }

  crypto.createHash('sha1').update(dex.subarray(32)).digest().copy(dex, 12);
  dex.writeUInt32LE(adler32(dex.subarray(12)), 8);
  return dex;
}

// ===========================================================================
// #1, #2, #3: `headers` op, `imageRequest` consistency + 0 network fetches,
//             and `System.getProperty("http.agent")` Dalvik UA
// ===========================================================================
test('#1, #2, #3: MangaDex headers & imageRequest use Tachiyomi Dalvik UA and make 0 HTTP calls', async () => {
  const apkBase64 = fs
    .readFileSync(path.join(FIXTURES, 'tachiyomi-all.mangadex-v1.6.5.apk'))
    .toString('base64');
  const seen = [];
  const vm = await createDexvm({
    wasmBytes,
    http(reqJson) {
      const req = JSON.parse(reqJson);
      seen.push(req);
      return JSON.stringify({ status: 200, headers: [], bodyBase64: '', finalUrl: req.url });
    },
  });

  const { handle } = vm.call('open', {
    apkBase64,
    defaultUserAgent: 'Mozilla/5.0 Chrome/Test',
  });
  const sources = vm.call('sources', { handle });
  const en = sources.find((s) => s.lang === 'en') || sources[0];

  // #1 + #3: `headers` op returns MangaDex's configured headers with Dalvik UA (not Chrome/Test, not null)
  const hdrRes = vm.call('headers', { handle, sourceId: en.id });
  assert.ok(Array.isArray(hdrRes.headers));
  const uaHdr = hdrRes.headers.find(([k]) => k.toLowerCase() === 'user-agent');
  assert.ok(uaHdr, `expected User-Agent in headers, got ${JSON.stringify(hdrRes.headers)}`);
  assert.ok(
    uaHdr[1].startsWith('Tachiyomi Dalvik/'),
    `expected User-Agent starting with "Tachiyomi Dalvik/", got: ${uaHdr[1]}`
  );
  assert.equal(seen.length, 0, 'headers op must not issue HTTP requests');

  // #2: `imageRequest` must NOT issue a real network GET for an already-resolved imageUrl
  // and must return the exact same Tachiyomi Dalvik UA (not defaultUserAgent).
  const coverUrl = 'https://uploads.mangadex.org/covers/abc/def.jpg';
  const ir = vm.call('imageRequest', {
    handle,
    sourceId: en.id,
    page: { index: 0, url: coverUrl, imageUrl: coverUrl },
  });
  vm.call('close', { handle });

  assert.equal(seen.length, 0, `imageRequest must not make real HTTP requests, got ${seen.length}`);
  assert.equal(ir.url, coverUrl);
  const irUa = ir.headers.find(([k]) => k.toLowerCase() === 'user-agent');
  assert.ok(irUa, `expected User-Agent in imageRequest headers, got ${JSON.stringify(ir.headers)}`);
  assert.equal(irUa[1], uaHdr[1], 'imageRequest User-Agent must match source headers');
});

test('#1b: headers op falls back to defaultUserAgent only when source sets no User-Agent', async () => {
  const dex = buildTestDex({});
  const vm = await createDexvm({
    wasmBytes,
    http() {
      return JSON.stringify({ status: 200, headers: [], bodyBase64: '', finalUrl: '' });
    },
  });

  // With defaultUserAgent
  const { handle: h1 } = vm.call('open', {
    apkBase64: dex.toString('base64'),
    defaultUserAgent: 'CustomHostUA/1.0',
  });
  const s1 = vm.call('sources', { handle: h1 });
  const r1 = vm.call('headers', { handle: h1, sourceId: s1[0].id });
  vm.call('close', { handle: h1 });
  assert.deepEqual(r1.headers, [['User-Agent', 'CustomHostUA/1.0']]);

  // Without defaultUserAgent
  const { handle: h2 } = vm.call('open', { apkBase64: dex.toString('base64') });
  const s2 = vm.call('sources', { handle: h2 });
  const r2 = vm.call('headers', { handle: h2, sourceId: s2[0].id });
  vm.call('close', { handle: h2 });
  assert.deepEqual(r2.headers, []);
});

// ===========================================================================
// #4: Jsoup Element.children() excludes text & comment nodes (GoDa pattern)
// ===========================================================================
test('#4: Jsoup Element.children() excludes text and comment nodes (GoDa h1.parent().parent().children()[4])', async () => {
  const html = `<!doctype html><html><body>
    <div class="wrapper">
      <!-- header comment -->
      <div class="title-box">
        <h1>武炼巅峰</h1>
      </div>
      <div class="meta-1">作者</div>
      <div class="meta-2">状态</div>
      <div class="meta-3">标签</div>
      <p>这是简介</p>
    </div>
  </body></html>`;

  const dex = buildTestDex({
    extraStrings: [
      'I',
      'LL',
      'LI',
      'Lorg/jsoup/Jsoup;',
      'Lorg/jsoup/nodes/Document;',
      'Lorg/jsoup/nodes/Element;',
      'Lorg/jsoup/select/Elements;',
      'Ljava/lang/Object;',
      'parse',
      'selectFirst',
      'parent',
      'children',
      'get',
      'tagName',
      'text',
      'concat',
      'h1',
      ':',
      html,
    ],
    extraTypes: [
      'I',
      'Lorg/jsoup/Jsoup;',
      'Lorg/jsoup/nodes/Document;',
      'Lorg/jsoup/nodes/Element;',
      'Lorg/jsoup/select/Elements;',
      'Ljava/lang/Object;',
    ],
    extraProtos: [
      ['LL', 'Lorg/jsoup/nodes/Document;', ['Ljava/lang/String;']],
      ['LL', 'Lorg/jsoup/nodes/Element;', ['Ljava/lang/String;']],
      ['L', 'Lorg/jsoup/nodes/Element;', []],
      ['L', 'Lorg/jsoup/select/Elements;', []],
      ['LI', 'Ljava/lang/Object;', ['I']],
      ['LL', 'Ljava/lang/String;', ['Ljava/lang/String;']],
    ],
    extraMethods: [
      ['Lorg/jsoup/Jsoup;', 'Lorg/jsoup/nodes/Document;', ['Ljava/lang/String;'], 'parse'],
      ['Lorg/jsoup/nodes/Element;', 'Lorg/jsoup/nodes/Element;', ['Ljava/lang/String;'], 'selectFirst'],
      ['Lorg/jsoup/nodes/Element;', 'Lorg/jsoup/nodes/Element;', [], 'parent'],
      ['Lorg/jsoup/nodes/Element;', 'Lorg/jsoup/select/Elements;', [], 'children'],
      ['Lorg/jsoup/select/Elements;', 'Ljava/lang/Object;', ['I'], 'get'],
      ['Lorg/jsoup/nodes/Element;', 'Ljava/lang/String;', [], 'tagName'],
      ['Lorg/jsoup/nodes/Element;', 'Ljava/lang/String;', [], 'text'],
      ['Ljava/lang/String;', 'Ljava/lang/String;', ['Ljava/lang/String;'], 'concat'],
    ],
    customGetName: ({ sIdx, tIdx, mIdx }) => ({
      regs: 5,
      ins: 1,
      outs: 2,
      insns: [
        // v0 = Jsoup.parse(html)
        0x001a, sIdx(html),
        0x1071, mIdx('Lorg/jsoup/Jsoup;', 'parse'), 0x0000,
        0x000c,
        // v0 = v0.selectFirst("h1").parent().parent().children().get(4)
        0x011a, sIdx('h1'),
        0x206e, mIdx('Lorg/jsoup/nodes/Element;', 'selectFirst'), 0x0010,
        0x000c,
        0x106e, mIdx('Lorg/jsoup/nodes/Element;', 'parent'), 0x0000,
        0x000c,
        0x106e, mIdx('Lorg/jsoup/nodes/Element;', 'parent'), 0x0000,
        0x000c,
        0x106e, mIdx('Lorg/jsoup/nodes/Element;', 'children'), 0x0000,
        0x000c,
        0x4112, // v1 = 4
        0x206e, mIdx('Lorg/jsoup/select/Elements;', 'get'), 0x0010,
        0x000c,
        0x001f, tIdx('Lorg/jsoup/nodes/Element;'),
        // v1 = v0.tagName(), v2 = v0.text()
        0x106e, mIdx('Lorg/jsoup/nodes/Element;', 'tagName'), 0x0000,
        0x010c,
        0x106e, mIdx('Lorg/jsoup/nodes/Element;', 'text'), 0x0000,
        0x020c,
        // return v1.concat(":").concat(v2)
        0x031a, sIdx(':'),
        0x206e, mIdx('Ljava/lang/String;', 'concat'), 0x0031,
        0x010c,
        0x206e, mIdx('Ljava/lang/String;', 'concat'), 0x0021,
        0x010c,
        0x0111,
      ],
    }),
  });

  const vm = await createDexvm({
    wasmBytes,
    http() {
      return JSON.stringify({ status: 200, headers: [], bodyBase64: '', finalUrl: '' });
    },
  });
  const { handle } = vm.call('open', { apkBase64: dex.toString('base64') });
  const sources = vm.call('sources', { handle });
  vm.call('close', { handle });

  assert.equal(sources[0].name, 'p:这是简介');
});

// ===========================================================================
// #5: Integer & Long bit helpers (numberOfLeadingZeros, numberOfTrailingZeros, ...)
// ===========================================================================
test('#5: Integer and Long numberOfLeadingZeros / numberOfTrailingZeros / highestOneBit / lowestOneBit / bitCount', async () => {
  const dex = buildTestDex({
    extraStrings: [
      'I',
      'II',
      'IJ',
      'JJ',
      'LI',
      'LJ',
      'LL',
      'Ljava/lang/Integer;',
      'Ljava/lang/Long;',
      'Ljava/lang/StringBuilder;',
      'numberOfLeadingZeros',
      'numberOfTrailingZeros',
      'highestOneBit',
      'lowestOneBit',
      'bitCount',
      'append',
      'toString',
      ',',
    ],
    extraTypes: [
      'I',
      'Ljava/lang/Integer;',
      'Ljava/lang/Long;',
      'Ljava/lang/StringBuilder;',
    ],
    extraProtos: [
      ['II', 'I', ['I']],
      ['IJ', 'I', ['J']],
      ['JJ', 'J', ['J']],
      ['LI', 'Ljava/lang/StringBuilder;', ['I']],
      ['LJ', 'Ljava/lang/StringBuilder;', ['J']],
      ['LL', 'Ljava/lang/StringBuilder;', ['Ljava/lang/String;']],
    ],
    extraMethods: [
      ['Ljava/lang/Integer;', 'I', ['I'], 'numberOfLeadingZeros'],
      ['Ljava/lang/Integer;', 'I', ['I'], 'numberOfTrailingZeros'],
      ['Ljava/lang/Integer;', 'I', ['I'], 'highestOneBit'],
      ['Ljava/lang/Integer;', 'I', ['I'], 'lowestOneBit'],
      ['Ljava/lang/Integer;', 'I', ['I'], 'bitCount'],
      ['Ljava/lang/Long;', 'I', ['J'], 'numberOfLeadingZeros'],
      ['Ljava/lang/Long;', 'I', ['J'], 'numberOfTrailingZeros'],
      ['Ljava/lang/Long;', 'J', ['J'], 'highestOneBit'],
      ['Ljava/lang/Long;', 'J', ['J'], 'lowestOneBit'],
      ['Ljava/lang/Long;', 'I', ['J'], 'bitCount'],
      ['Ljava/lang/StringBuilder;', 'V', [], '<init>'],
      ['Ljava/lang/StringBuilder;', 'Ljava/lang/StringBuilder;', ['I'], 'append'],
      ['Ljava/lang/StringBuilder;', 'Ljava/lang/StringBuilder;', ['J'], 'append'],
      ['Ljava/lang/StringBuilder;', 'Ljava/lang/StringBuilder;', ['Ljava/lang/String;'], 'append'],
      ['Ljava/lang/StringBuilder;', 'Ljava/lang/String;', [], 'toString'],
    ],
    customGetName: ({ sIdx, tIdx, mIdx }) => ({
      regs: 8,
      ins: 1,
      outs: 3,
      insns: [
        // v0 = new StringBuilder()
        0x0022, tIdx('Ljava/lang/StringBuilder;'),
        0x1070, mIdx('Ljava/lang/StringBuilder;', '<init>'), 0x0000,
        // v1 = 40 (0b101000): nlz=26, ntz=3, hob=32, lob=8, bc=2
        0x0113, 40,
        // v2 = ","
        0x021a, sIdx(','),
        // append Integer.numberOfLeadingZeros(40)
        0x1071, mIdx('Ljava/lang/Integer;', 'numberOfLeadingZeros'), 0x0001,
        0x030a,
        0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['I']), 0x0030,
        0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['Ljava/lang/String;']), 0x0020,
        // append Integer.numberOfTrailingZeros(40)
        0x1071, mIdx('Ljava/lang/Integer;', 'numberOfTrailingZeros'), 0x0001,
        0x030a,
        0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['I']), 0x0030,
        0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['Ljava/lang/String;']), 0x0020,
        // append Integer.lowestOneBit(40)
        0x1071, mIdx('Ljava/lang/Integer;', 'lowestOneBit'), 0x0001,
        0x030a,
        0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['I']), 0x0030,
        0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['Ljava/lang/String;']), 0x0020,
        // v4:v5 = 40L: nlz=58, ntz=3, hob=32L, lob=8L
        0x0416, 40,
        0x2071, mIdx('Ljava/lang/Long;', 'numberOfLeadingZeros'), 0x0054,
        0x030a,
        0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['I']), 0x0030,
        0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['Ljava/lang/String;']), 0x0020,
        0x2071, mIdx('Ljava/lang/Long;', 'numberOfTrailingZeros'), 0x0054,
        0x030a,
        0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['I']), 0x0030,
        0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['Ljava/lang/String;']), 0x0020,
        0x2071, mIdx('Ljava/lang/Long;', 'highestOneBit'), 0x0054,
        0x060b,
        0x306e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['J']), 0x0760,
        0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['Ljava/lang/String;']), 0x0020,
        0x2071, mIdx('Ljava/lang/Long;', 'lowestOneBit'), 0x0054,
        0x060b,
        0x306e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['J']), 0x0760,
        // return v0.toString()
        0x106e, mIdx('Ljava/lang/StringBuilder;', 'toString'), 0x0000,
        0x000c,
        0x0011,
      ],
    }),
  });

  const vm = await createDexvm({
    wasmBytes,
    http() {
      return JSON.stringify({ status: 200, headers: [], bodyBase64: '', finalUrl: '' });
    },
  });
  const { handle } = vm.call('open', { apkBase64: dex.toString('base64') });
  const sources = vm.call('sources', { handle });
  vm.call('close', { handle });

  assert.equal(sources[0].name, '26,3,8,58,3,32,8');
});

// ===========================================================================
// #6: fetchImage with existing page.imageUrl makes exactly 1 HTTP request
// ===========================================================================
test('#6: fetchImage with non-empty page.imageUrl fetches only imageUrl (1 HTTP request, never page.url)', async () => {
  const dex = buildTestDex({});
  const seenUrls = [];
  const fakeJpeg = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]);
  const vm = await createDexvm({
    wasmBytes,
    http(reqJson) {
      const req = JSON.parse(reqJson);
      seenUrls.push(req.url);
      return JSON.stringify({
        status: 200,
        headers: [['content-type', 'image/jpeg']],
        bodyBase64: fakeJpeg.toString('base64'),
        finalUrl: req.url,
      });
    },
  });

  const { handle } = vm.call('open', { apkBase64: dex.toString('base64') });
  const sources = vm.call('sources', { handle });
  const img = vm.call('fetchImage', {
    handle,
    sourceId: sources[0].id,
    page: {
      index: 0,
      url: 'https://www.1kkk.com/other1513360/',
      imageUrl: 'https://cdn.1kkk.com/page1.jpg',
    },
  });
  vm.call('close', { handle });

  assert.deepEqual(
    seenUrls,
    ['https://cdn.1kkk.com/page1.jpg'],
    `expected exactly 1 HTTP request to imageUrl, got: ${JSON.stringify(seenUrls)}`
  );
  assert.equal(img.bytes, fakeJpeg.length);
  assert.equal(img.mime, 'image/jpeg');
});

// ===========================================================================
// #7: java.util.TimeZone.getID() / getRawOffset() / getOffset(long)
// ===========================================================================
test('#7: java.util.TimeZone.getID(), getRawOffset(), and getOffset(long)', async () => {
  const dex = buildTestDex({
    extraStrings: [
      'I',
      'IJ',
      'LI',
      'LL',
      'Ljava/util/TimeZone;',
      'Ljava/lang/StringBuilder;',
      'getDefault',
      'getTimeZone',
      'getID',
      'getRawOffset',
      'getOffset',
      'Asia/Shanghai',
      'append',
      'toString',
      '|',
    ],
    extraTypes: ['I', 'Ljava/util/TimeZone;', 'Ljava/lang/StringBuilder;'],
    extraProtos: [
      ['L', 'Ljava/util/TimeZone;', []],
      ['LL', 'Ljava/util/TimeZone;', ['Ljava/lang/String;']],
      ['I', 'I', []],
      ['IJ', 'I', ['J']],
      ['LI', 'Ljava/lang/StringBuilder;', ['I']],
      ['LL', 'Ljava/lang/StringBuilder;', ['Ljava/lang/String;']],
    ],
    extraMethods: [
      ['Ljava/util/TimeZone;', 'Ljava/util/TimeZone;', [], 'getDefault'],
      ['Ljava/util/TimeZone;', 'Ljava/util/TimeZone;', ['Ljava/lang/String;'], 'getTimeZone'],
      ['Ljava/util/TimeZone;', 'Ljava/lang/String;', [], 'getID'],
      ['Ljava/util/TimeZone;', 'I', [], 'getRawOffset'],
      ['Ljava/util/TimeZone;', 'I', ['J'], 'getOffset'],
      ['Ljava/lang/StringBuilder;', 'V', [], '<init>'],
      ['Ljava/lang/StringBuilder;', 'Ljava/lang/StringBuilder;', ['I'], 'append'],
      ['Ljava/lang/StringBuilder;', 'Ljava/lang/StringBuilder;', ['Ljava/lang/String;'], 'append'],
      ['Ljava/lang/StringBuilder;', 'Ljava/lang/String;', [], 'toString'],
    ],
    customGetName: ({ sIdx, tIdx, mIdx }) => ({
      regs: 7,
      ins: 1,
      outs: 3,
      insns: [
        // v0 = new StringBuilder()
        0x0022, tIdx('Ljava/lang/StringBuilder;'),
        0x1070, mIdx('Ljava/lang/StringBuilder;', '<init>'), 0x0000,
        // v1 = "|"
        0x011a, sIdx('|'),
        // v2 = TimeZone.getDefault().getID()
        0x0071, mIdx('Ljava/util/TimeZone;', 'getDefault'), 0x0000,
        0x020c,
        0x106e, mIdx('Ljava/util/TimeZone;', 'getID'), 0x0002,
        0x020c,
        0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['Ljava/lang/String;']), 0x0020,
        0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['Ljava/lang/String;']), 0x0010,
        // v2 = TimeZone.getTimeZone("Asia/Shanghai")
        0x021a, sIdx('Asia/Shanghai'),
        0x1071, mIdx('Ljava/util/TimeZone;', 'getTimeZone'), 0x0002,
        0x020c,
        // append v2.getID() + "|" + v2.getRawOffset() + "|" + v2.getOffset(0L)
        0x106e, mIdx('Ljava/util/TimeZone;', 'getID'), 0x0002,
        0x030c,
        0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['Ljava/lang/String;']), 0x0030,
        0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['Ljava/lang/String;']), 0x0010,
        0x106e, mIdx('Ljava/util/TimeZone;', 'getRawOffset'), 0x0002,
        0x030a,
        0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['I']), 0x0030,
        0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['Ljava/lang/String;']), 0x0010,
        0x0416, 0, // v4:v5 = 0L
        0x306e, mIdx('Ljava/util/TimeZone;', 'getOffset'), 0x0542,
        0x030a,
        0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['I']), 0x0030,
        // return v0.toString()
        0x106e, mIdx('Ljava/lang/StringBuilder;', 'toString'), 0x0000,
        0x000c,
        0x0011,
      ],
    }),
  });

  const vm = await createDexvm({
    wasmBytes,
    http() {
      return JSON.stringify({ status: 200, headers: [], bodyBase64: '', finalUrl: '' });
    },
  });
  const { handle } = vm.call('open', { apkBase64: dex.toString('base64') });
  const sources = vm.call('sources', { handle });
  vm.call('close', { handle });

  assert.equal(sources[0].name, 'UTC|Asia/Shanghai|28800000|28800000');
});
