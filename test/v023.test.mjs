// Offline reproduction tests for v0.2.3 fixes (#1-#5):
// 1. No duplicate HTTP requests in details/chapters for 1.6 & legacy sources + combined `mangaUpdate` op
// 2. GlobalScope.launch fire-and-forget does not block main op; DelayKt.delay delegates to host `sleep`
// 3. kotlin.text.StringsKt.lineSequence(CharSequence): Sequence
// 4. kotlin.text.MatchResult.getDestructured() + MatchResult$Destructured.component1..10
// 5. kotlinx.serialization BooleanSerializer boxes java.lang.Boolean (not java.lang.Integer)
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

// ---------------------------------------------------------------------------
// Generic minimal DEX 035 builder for custom HttpSource subclasses where
// `getFilterList()` or `getName()` runs test bytecode.
// ---------------------------------------------------------------------------
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

function buildTestDex({ extraStrings = [], extraTypes = [], extraProtos = [], extraFields = [], extraMethods = [], customGetName }) {
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

  // Fields: [classType, fieldType, name]
  const fields = [...extraFields].sort((a, b) => {
    const c = tIdx(a[0]) - tIdx(b[0]);
    if (c !== 0) return c;
    const n = sIdx(a[2]) - sIdx(b[2]);
    if (n !== 0) return n;
    return tIdx(a[1]) - tIdx(b[1]);
  });
  const fIdx = (cls, name) => {
    const i = fields.findIndex(([c, , n]) => c === cls && n === name);
    if (i < 0) throw new Error(`missing field: ${cls}.${name}`);
    return i;
  };

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
  const mIdx = (cls, name, ret = null) => {
    const i = allMethods.findIndex(([c, r, , n]) => c === cls && n === name && (ret === null || r === ret));
    if (i < 0) throw new Error(`missing method: ${cls}.${name}`);
    return i;
  };

  const helpers = { sIdx, tIdx, fIdx, mIdx };
  const probeMethods = [
    {
      idx: mIdx('Ltest/ProbeSource;', '<init>'),
      direct: true,
      access: 0x10001,
      code: { regs: 1, ins: 1, outs: 1, insns: [0x1070, mIdx('Leu/kanade/tachiyomi/source/online/HttpSource;', '<init>'), 0x0000, 0x000e] },
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
      code: customGetName(helpers),
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

  const direct = probeMethods.map((m, i) => ({ ...m, codeOff: codeOffs[i] })).filter((m) => m.direct).sort((a, b) => a.idx - b.idx);
  const virtual = probeMethods.map((m, i) => ({ ...m, codeOff: codeOffs[i] })).filter((m) => !m.direct).sort((a, b) => a.idx - b.idx);

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
  dex.write('dex\n035\0', 0, 'ascii');
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
    const base = protoIdsOff + i * 12;
    dex.writeUInt32LE(sIdx(shorty), base);
    dex.writeUInt32LE(tIdx(ret), base + 4);
    dex.writeUInt32LE(protoParamOffs[i], base + 8);
  });
  fields.forEach(([cls, ftype, name], i) => {
    const base = fieldIdsOff + i * 8;
    dex.writeUInt16LE(tIdx(cls), base);
    dex.writeUInt16LE(tIdx(ftype), base + 2);
    dex.writeUInt32LE(sIdx(name), base + 4);
  });
  allMethods.forEach(([cls, ret, params, name], i) => {
    const base = methodIdsOff + i * 8;
    dex.writeUInt16LE(tIdx(cls), base);
    dex.writeUInt16LE(pIdx(ret, params), base + 2);
    dex.writeUInt32LE(sIdx(name), base + 4);
  });
  dex.writeUInt32LE(tIdx('Ltest/ProbeSource;'), classDefsOff);
  dex.writeUInt32LE(0x1, classDefsOff + 4);
  dex.writeUInt32LE(tIdx('Leu/kanade/tachiyomi/source/online/HttpSource;'), classDefsOff + 8);
  dex.writeUInt32LE(0, classDefsOff + 12);
  dex.writeUInt32LE(0xffffffff, classDefsOff + 16);
  dex.writeUInt32LE(0, classDefsOff + 20);
  dex.writeUInt32LE(classDataOff, classDefsOff + 24);
  dex.writeUInt32LE(0, classDefsOff + 28);

  let pos = dataOff;
  for (const c of chunks) {
    c.copy(dex, pos);
    pos += c.length;
  }
  crypto.createHash('sha1').update(dex.subarray(32)).digest().copy(dex, 12);
  dex.writeUInt32LE(adler32(dex.subarray(12)), 8);
  return dex;
}

const MANHUAGUI_DETAIL_HTML = `<!doctype html><html><body>
<div class="book-title"><h1>Test Comic</h1></div>
<div class="hcover"><img src="//cf.hamreus.com/cover.jpg" /></div>
<div id="intro-all"><p>Summary text</p></div>
<ul class="detail-list"><li><span><a href="/list/act/">Action</a></span><span><a href="/author/1/">AuthorA</a></span></li><li class="status"><span><em>连载中</em></span></li></ul>
<div class="chapter"><h4><span>单话</span></h4><div id="chapter-list-1" class="chapter-list"><ul><li><a href="/comic/123/456.html" title="Ch 1" class="status0"><span>Ch 1<i>10p</i></span></a></li></ul></div></div>
</body></html>`;

// ---------------------------------------------------------------------------
// #1 + #2a: 1.6 details / chapters single HTTP request, no GlobalScope.launch
//           blocking, and combined `mangaUpdate` op
// ---------------------------------------------------------------------------
test('#1 & #2: manhuagui v1.6.2 details/chapters/mangaUpdate each make 1 HTTP request and GlobalScope.launch does not block', async () => {
  const requests = [];
  const sleepCalls = [];
  const vm = await createDexvm({
    wasmBytes,
    sleep: (ms) => sleepCalls.push(ms),
    http: (reqJson) => {
      const req = JSON.parse(reqJson);
      requests.push(req);
      return JSON.stringify({
        status: 200,
        headers: [['content-type', 'text/html; charset=utf-8']],
        bodyBase64: Buffer.from(MANHUAGUI_DETAIL_HTML).toString('base64'),
        finalUrl: req.url,
      });
    },
  });

  const apkBase64 = fs
    .readFileSync(path.join(FIXTURES, 'tachiyomi-zh.manhuagui-v1.6.2.apk'))
    .toString('base64');
  const { handle } = vm.call('open', { apkBase64 });
  const sources = vm.call('sources', { handle });
  const sourceId = sources[0].id;

  // details: exactly 1 HTTP request (with Cache-Control), 0 sleep calls (GlobalScope.launch dropped)
  requests.length = 0;
  const det = vm.call('details', { handle, sourceId, manga: { url: '/comic/123/' } });
  assert.equal(det.title, 'Test Comic');
  assert.equal(requests.length, 1, `details should make 1 HTTP request, got ${requests.length}: ${requests.map((r) => r.url)}`);
  assert.ok(
    requests[0].headers.some(([k]) => k.toLowerCase() === 'cache-control'),
    'request should come from fetchMangaUpdate (with Cache-Control)'
  );
  assert.equal(sleepCalls.length, 0, `GlobalScope.launch should not run delay() synchronously: ${JSON.stringify(sleepCalls)}`);

  // chapters: exactly 1 HTTP request
  requests.length = 0;
  const chs = vm.call('chapters', { handle, sourceId, manga: { url: '/comic/123/' } });
  assert.equal(chs.length, 1);
  assert.equal(chs[0].name, 'Ch 1');
  assert.equal(requests.length, 1, `chapters should make 1 HTTP request, got ${requests.length}`);

  // combined mangaUpdate: both details + chapters in 1 HTTP request!
  requests.length = 0;
  const upd = vm.call('mangaUpdate', { handle, sourceId, manga: { url: '/comic/123/' } });
  assert.equal(upd.manga.title, 'Test Comic');
  assert.equal(upd.chapters.length, 1);
  assert.equal(upd.chapters[0].name, 'Ch 1');
  assert.equal(requests.length, 1, `mangaUpdate should make 1 HTTP request, got ${requests.length}`);

  vm.call('close', { handle });
});

test('#1: legacy 1.4 source details makes 1 HTTP request (no duplicate from HttpSource stub)', async () => {
  const requests = [];
  const vm = await createDexvm({
    wasmBytes,
    http: (reqJson) => {
      const req = JSON.parse(reqJson);
      requests.push(req);
      return JSON.stringify({
        status: 200,
        headers: [['content-type', 'text/html; charset=utf-8']],
        bodyBase64: Buffer.from('<html><body><h1>Legacy Title</h1></body></html>').toString('base64'),
        finalUrl: req.url,
      });
    },
  });
  const apkBase64 = fs
    .readFileSync(path.join(FIXTURES, 'tachiyomi-en.mangapill-v1.4.9.apk'))
    .toString('base64');
  const { handle } = vm.call('open', { apkBase64 });
  const sources = vm.call('sources', { handle });
  try {
    vm.call('details', { handle, sourceId: sources[0].id, manga: { url: '/manga/1/test' } });
  } catch {
    // Minimal HTML may not satisfy all selectors; we only verify 1 HTTP request was sent.
  }
  vm.call('close', { handle });
  assert.equal(requests.length, 1, `legacy details should make 1 HTTP request, got ${requests.length}`);
});

// ---------------------------------------------------------------------------
// #2b: DelayKt.delay delegates to host `sleep(ms)`
// ---------------------------------------------------------------------------
test('#2: kotlinx.coroutines.DelayKt.delay(1500) calls host sleep(≈1500)', async () => {
  const sleepCalls = [];
  const vm = await createDexvm({
    wasmBytes,
    sleep: (ms) => sleepCalls.push(ms),
    http: () => JSON.stringify({ error: 'unused' }),
  });

  const dex = buildTestDex({
    extraStrings: [
      'Lkotlin/coroutines/Continuation;',
      'Ljava/lang/Object;',
      'Lkotlinx/coroutines/DelayKt;',
      'delay',
      'LJL',
    ],
    extraTypes: [
      'Lkotlin/coroutines/Continuation;',
      'Ljava/lang/Object;',
      'Lkotlinx/coroutines/DelayKt;',
    ],
    extraProtos: [
      ['LJL', 'Ljava/lang/Object;', ['J', 'Lkotlin/coroutines/Continuation;']],
    ],
    extraMethods: [
      ['Lkotlinx/coroutines/DelayKt;', 'Ljava/lang/Object;', ['J', 'Lkotlin/coroutines/Continuation;'], 'delay'],
    ],
    customGetName: ({ sIdx, mIdx }) => ({
      regs: 4,
      ins: 1,
      outs: 3,
      // const-wide/16 v0, 1500; const/4 v2, 0; invoke-static {v0,v1,v2}, DelayKt.delay; const-string v0, "ProbeSource"; return-object v0
      insns: [
        0x0016, 1500,
        0x0212,
        0x3071, mIdx('Lkotlinx/coroutines/DelayKt;', 'delay'), 0x0210,
        0x001a, sIdx('ProbeSource'),
        0x0011,
      ],
    }),
  });

  const { handle } = vm.call('open', { apkBase64: dex.toString('base64') });
  const sources = vm.call('sources', { handle });
  assert.equal(sources[0].name, 'ProbeSource');
  vm.call('close', { handle });
  assert.equal(sleepCalls.length, 1, `expected 1 sleep call, got ${JSON.stringify(sleepCalls)}`);
  assert.ok(sleepCalls[0] >= 1490 && sleepCalls[0] <= 1510, `expected sleep(≈1500), got ${sleepCalls[0]}`);
});

// ---------------------------------------------------------------------------
// #3: kotlin.text.StringsKt.lineSequence(CharSequence): Sequence
// ---------------------------------------------------------------------------
test('#3: StringsKt.lineSequence(CharSequence) splits lines into a Sequence', async () => {
  const vm = await createDexvm({
    wasmBytes,
    http: () => JSON.stringify({ error: 'unused' }),
  });

  const dex = buildTestDex({
    extraStrings: [
      'Ljava/lang/CharSequence;',
      'Ljava/util/List;',
      'Lkotlin/sequences/Sequence;',
      'Lkotlin/sequences/SequencesKt;',
      'Lkotlin/text/StringsKt;',
      'LL',
      'lineSequence',
      'toList',
      'toString',
      'alpha\r\nbeta\ngamma',
    ],
    extraTypes: [
      'Ljava/lang/CharSequence;',
      'Ljava/util/List;',
      'Lkotlin/sequences/Sequence;',
      'Lkotlin/sequences/SequencesKt;',
      'Lkotlin/text/StringsKt;',
    ],
    extraProtos: [
      ['LL', 'Lkotlin/sequences/Sequence;', ['Ljava/lang/CharSequence;']],
      ['LL', 'Ljava/util/List;', ['Lkotlin/sequences/Sequence;']],
    ],
    extraMethods: [
      ['Lkotlin/text/StringsKt;', 'Lkotlin/sequences/Sequence;', ['Ljava/lang/CharSequence;'], 'lineSequence'],
      ['Lkotlin/sequences/SequencesKt;', 'Ljava/util/List;', ['Lkotlin/sequences/Sequence;'], 'toList'],
      ['Ljava/util/List;', 'Ljava/lang/String;', [], 'toString'],
    ],
    customGetName: ({ sIdx, mIdx }) => ({
      regs: 2,
      ins: 1,
      outs: 1,
      // v0 = "alpha\r\nbeta\ngamma"
      // v0 = StringsKt.lineSequence(v0)
      // v0 = SequencesKt.toList(v0)
      // v0 = List.toString(v0)
      insns: [
        0x001a, sIdx('alpha\r\nbeta\ngamma'),
        0x1071, mIdx('Lkotlin/text/StringsKt;', 'lineSequence'), 0x0000,
        0x000c,
        0x1071, mIdx('Lkotlin/sequences/SequencesKt;', 'toList'), 0x0000,
        0x000c,
        0x1072, mIdx('Ljava/util/List;', 'toString'), 0x0000,
        0x000c,
        0x0011,
      ],
    }),
  });

  const { handle } = vm.call('open', { apkBase64: dex.toString('base64') });
  const sources = vm.call('sources', { handle });
  assert.equal(sources[0].name, '[alpha, beta, gamma]');
  vm.call('close', { handle });
});

// ---------------------------------------------------------------------------
// #4: MatchResult.getDestructured() + component1() / component2()
// ---------------------------------------------------------------------------
test('#4: MatchResult.getDestructured() and component1/component2 extract capturing groups', async () => {
  const vm = await createDexvm({
    wasmBytes,
    http: () => JSON.stringify({ error: 'unused' }),
  });

  const dex = buildTestDex({
    extraStrings: [
      'I',
      'Ljava/lang/CharSequence;',
      'Lkotlin/text/MatchResult;',
      'Lkotlin/text/MatchResult$Destructured;',
      'Lkotlin/text/Regex;',
      'VL',
      'LLI',
      'LL',
      'find',
      'getDestructured',
      'component1',
      'component2',
      'concat',
      '(\\w+)-(\\d+)',
      'desu-42',
    ],
    extraTypes: [
      'I',
      'Ljava/lang/CharSequence;',
      'Lkotlin/text/MatchResult;',
      'Lkotlin/text/MatchResult$Destructured;',
      'Lkotlin/text/Regex;',
    ],
    extraProtos: [
      ['VL', 'V', ['Ljava/lang/String;']],
      ['LLI', 'Lkotlin/text/MatchResult;', ['Ljava/lang/CharSequence;', 'I']],
      ['L', 'Lkotlin/text/MatchResult$Destructured;', []],
      ['LL', 'Ljava/lang/String;', ['Ljava/lang/String;']],
    ],
    extraMethods: [
      ['Lkotlin/text/Regex;', 'V', ['Ljava/lang/String;'], '<init>'],
      ['Lkotlin/text/Regex;', 'Lkotlin/text/MatchResult;', ['Ljava/lang/CharSequence;', 'I'], 'find'],
      ['Lkotlin/text/MatchResult;', 'Lkotlin/text/MatchResult$Destructured;', [], 'getDestructured'],
      ['Lkotlin/text/MatchResult$Destructured;', 'Ljava/lang/String;', [], 'component1'],
      ['Lkotlin/text/MatchResult$Destructured;', 'Ljava/lang/String;', [], 'component2'],
      ['Ljava/lang/String;', 'Ljava/lang/String;', ['Ljava/lang/String;'], 'concat'],
    ],
    customGetName: ({ sIdx, tIdx, mIdx }) => ({
      regs: 4,
      ins: 1,
      outs: 3,
      // v0 = new Regex("(\\w+)-(\\d+)")
      // v1 = "desu-42", v2 = 0
      // v0 = v0.find(v1, v2)
      // v0 = v0.getDestructured()
      // v1 = v0.component1()
      // v2 = v0.component2()
      // v0 = v1.concat(v2) -> "desu42"
      insns: [
        0x0022, tIdx('Lkotlin/text/Regex;'),
        0x011a, sIdx('(\\w+)-(\\d+)'),
        0x2070, mIdx('Lkotlin/text/Regex;', '<init>'), 0x0010,
        0x011a, sIdx('desu-42'),
        0x0212,
        0x306e, mIdx('Lkotlin/text/Regex;', 'find'), 0x0210,
        0x000c,
        0x1072, mIdx('Lkotlin/text/MatchResult;', 'getDestructured'), 0x0000,
        0x000c,
        0x106e, mIdx('Lkotlin/text/MatchResult$Destructured;', 'component1'), 0x0000,
        0x010c,
        0x106e, mIdx('Lkotlin/text/MatchResult$Destructured;', 'component2'), 0x0000,
        0x020c,
        0x206e, mIdx('Ljava/lang/String;', 'concat'), 0x0021,
        0x000c,
        0x0011,
      ],
    }),
  });

  const { handle } = vm.call('open', { apkBase64: dex.toString('base64') });
  const sources = vm.call('sources', { handle });
  assert.equal(sources[0].name, 'desu42');
  vm.call('close', { handle });
});

// ---------------------------------------------------------------------------
// #5: kotlinx.serialization BooleanSerializer boxes java.lang.Boolean
// ---------------------------------------------------------------------------
test('#5: BooleanSerializer deserializes to java.lang.Boolean (passes check-cast without ClassCastException)', async () => {
  const vm = await createDexvm({
    wasmBytes,
    http: () => JSON.stringify({ error: 'unused' }),
  });

  const dex = buildTestDex({
    extraStrings: [
      'Ljava/lang/Boolean;',
      'Ljava/lang/Object;',
      'Lkotlinx/serialization/DeserializationStrategy;',
      'Lkotlinx/serialization/internal/BooleanSerializer;',
      'Lkotlinx/serialization/json/Json;',
      'Lkotlinx/serialization/json/Json$Default;',
      'Default',
      'INSTANCE',
      'LLL',
      'decodeFromString',
      'toString',
      'true',
    ],
    extraTypes: [
      'Ljava/lang/Boolean;',
      'Ljava/lang/Object;',
      'Lkotlinx/serialization/DeserializationStrategy;',
      'Lkotlinx/serialization/internal/BooleanSerializer;',
      'Lkotlinx/serialization/json/Json;',
      'Lkotlinx/serialization/json/Json$Default;',
    ],
    extraProtos: [
      ['LLL', 'Ljava/lang/Object;', ['Lkotlinx/serialization/DeserializationStrategy;', 'Ljava/lang/String;']],
    ],
    extraFields: [
      ['Lkotlinx/serialization/json/Json;', 'Lkotlinx/serialization/json/Json$Default;', 'Default'],
      ['Lkotlinx/serialization/internal/BooleanSerializer;', 'Lkotlinx/serialization/internal/BooleanSerializer;', 'INSTANCE'],
    ],
    extraMethods: [
      ['Lkotlinx/serialization/json/Json;', 'Ljava/lang/Object;', ['Lkotlinx/serialization/DeserializationStrategy;', 'Ljava/lang/String;'], 'decodeFromString'],
      ['Ljava/lang/Boolean;', 'Ljava/lang/String;', [], 'toString'],
    ],
    customGetName: ({ sIdx, tIdx, fIdx, mIdx }) => ({
      regs: 4,
      ins: 1,
      outs: 3,
      // v0 = Json.Default
      // v1 = BooleanSerializer.INSTANCE
      // v2 = "true"
      // v0 = v0.decodeFromString(v1, v2)
      // check-cast v0, Ljava/lang/Boolean;   <-- previously threw ClassCastException!
      // v0 = v0.toString() -> "true"
      insns: [
        0x0062, fIdx('Lkotlinx/serialization/json/Json;', 'Default'),
        0x0162, fIdx('Lkotlinx/serialization/internal/BooleanSerializer;', 'INSTANCE'),
        0x021a, sIdx('true'),
        0x306e, mIdx('Lkotlinx/serialization/json/Json;', 'decodeFromString'), 0x0210,
        0x000c,
        0x001f, tIdx('Ljava/lang/Boolean;'),
        0x106e, mIdx('Ljava/lang/Boolean;', 'toString'), 0x0000,
        0x000c,
        0x0011,
      ],
    }),
  });

  const { handle } = vm.call('open', { apkBase64: dex.toString('base64') });
  const sources = vm.call('sources', { handle });
  assert.equal(sources[0].name, 'true');
  vm.call('close', { handle });
});
