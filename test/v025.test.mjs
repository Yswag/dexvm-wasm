// Offline reproduction tests for v0.2.5 fixes (#1-#3):
// 1. 1.6 sources implementing `getPageList` go directly to the coroutine path
//    without first firing a legacy `pageListRequest` (`baseUrl + chapter.url`).
// 2. `java.time.ZonedDateTime.toLocalDate()` (plus `toLocalDateTime()`,
//    `OffsetDateTime.toLocalDate()`, and `LocalDateTime.toLocalDate()`).
// 3. 1.6 sources implementing `getPopularManga` / `getLatestUpdates` /
//    `getSearchManga` go directly to the coroutine path without first trying
//    legacy `*Request(I)` (so a site 403 surfaces cleanly as `HTTP 403`, not
//    `resolution error: no method popularMangaRequest`).
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
  customVirtualMethods = [],
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

  const helpers = { sIdx, tIdx, fIdx, mIdx };
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
    ...customVirtualMethods.map(({ name, ret, params, buildCode }) => ({
      idx: mIdx('Ltest/ProbeSource;', name, ret, params),
      direct: false,
      access: 0x1,
      code: buildCode(helpers),
    })),
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

  const sha1 = crypto.createHash('sha1').update(dex.subarray(32)).digest();
  sha1.copy(dex, 12);
  dex.writeUInt32LE(adler32(dex.subarray(12)), 8);
  return dex;
}

// ===========================================================================
// #1: 1.6 `pages` dispatches directly to `getPageList` (no legacy `baseUrl + chapter.url`)
// ===========================================================================
test('#1: 1.6 source pages dispatches directly to getPageList without legacy pageListRequest', async () => {
  // Synthetic 1.6 source overriding `getPageList(SChapter, Continuation)` that
  // hits `https://api.probe.test/pages` via `getClient().newCall(GET(...)).execute()`
  // and returns a single Page. It does NOT override `pageListRequest`/`pageListParse`.
  // Calling `pages` with `chapter.url = "202166"` (no leading "/") must NEVER send
  // `https://probe.test202166`.
  const dex = buildTestDex({
    extraStrings: [
      'LL',
      'LLL',
      'VLILL',
      'getPageList',
      'getClient',
      'newCall',
      'execute',
      'GET',
      'https://api.probe.test/pages/202166',
      'https://img.probe.test/1.jpg',
      'add',
      'Lokhttp3/OkHttpClient;',
      'Lokhttp3/Request;',
      'Lokhttp3/Call;',
      'Lokhttp3/Response;',
      'Lokhttp3/Headers;',
      'Lokhttp3/CacheControl;',
      'Leu/kanade/tachiyomi/network/RequestsKt;',
      'Leu/kanade/tachiyomi/source/model/SChapter;',
      'Leu/kanade/tachiyomi/source/model/Page;',
      'Landroid/net/Uri;',
      'Lkotlin/coroutines/Continuation;',
      'Ljava/lang/Object;',
      'Ljava/util/ArrayList;',
      'I',
      'LLLL',
      'ZL',
    ],
    extraTypes: [
      'Lokhttp3/OkHttpClient;',
      'Lokhttp3/Request;',
      'Lokhttp3/Call;',
      'Lokhttp3/Response;',
      'Lokhttp3/Headers;',
      'Lokhttp3/CacheControl;',
      'Leu/kanade/tachiyomi/network/RequestsKt;',
      'Leu/kanade/tachiyomi/source/model/SChapter;',
      'Leu/kanade/tachiyomi/source/model/Page;',
      'Landroid/net/Uri;',
      'Lkotlin/coroutines/Continuation;',
      'Ljava/lang/Object;',
      'Ljava/util/ArrayList;',
      'I',
    ],
    extraProtos: [
      ['LLL', 'Ljava/lang/Object;', ['Leu/kanade/tachiyomi/source/model/SChapter;', 'Lkotlin/coroutines/Continuation;']],
      ['L', 'Lokhttp3/OkHttpClient;', []],
      ['LL', 'Lokhttp3/Call;', ['Lokhttp3/Request;']],
      ['L', 'Lokhttp3/Response;', []],
      ['LLLL', 'Lokhttp3/Request;', ['Ljava/lang/String;', 'Lokhttp3/Headers;', 'Lokhttp3/CacheControl;']],
      ['VLILL', 'V', ['I', 'Ljava/lang/String;', 'Ljava/lang/String;', 'Landroid/net/Uri;']],
      ['ZL', 'Z', ['Ljava/lang/Object;']],
    ],
    extraMethods: [
      ['Ltest/ProbeSource;', 'Ljava/lang/Object;', ['Leu/kanade/tachiyomi/source/model/SChapter;', 'Lkotlin/coroutines/Continuation;'], 'getPageList'],
      ['Leu/kanade/tachiyomi/source/online/HttpSource;', 'Lokhttp3/OkHttpClient;', [], 'getClient'],
      ['Lokhttp3/OkHttpClient;', 'Lokhttp3/Call;', ['Lokhttp3/Request;'], 'newCall'],
      ['Lokhttp3/Call;', 'Lokhttp3/Response;', [], 'execute'],
      ['Leu/kanade/tachiyomi/network/RequestsKt;', 'Lokhttp3/Request;', ['Ljava/lang/String;', 'Lokhttp3/Headers;', 'Lokhttp3/CacheControl;'], 'GET'],
      ['Ljava/util/ArrayList;', 'V', [], '<init>'],
      ['Ljava/util/ArrayList;', 'Z', ['Ljava/lang/Object;'], 'add'],
      ['Leu/kanade/tachiyomi/source/model/Page;', 'V', ['I', 'Ljava/lang/String;', 'Ljava/lang/String;', 'Landroid/net/Uri;'], '<init>'],
    ],
    customVirtualMethods: [
      {
        name: 'getPageList',
        ret: 'Ljava/lang/Object;',
        params: ['Leu/kanade/tachiyomi/source/model/SChapter;', 'Lkotlin/coroutines/Continuation;'],
        buildCode: ({ sIdx, tIdx, mIdx }) => ({
          // regs: v0..v4, ins: 3 (p0=v5=this, p1=v6=chapter, p2=v7=cont)
          regs: 8,
          ins: 3,
          outs: 5,
          insns: [
            // v0 = "https://api.probe.test/pages/202166", v1 = null, v2 = null
            0x001a, sIdx('https://api.probe.test/pages/202166'),
            0x0112,
            0x0212,
            // v0 = RequestsKt.GET(v0, v1, v2)
            0x3071, mIdx('Leu/kanade/tachiyomi/network/RequestsKt;', 'GET'), 0x0210,
            0x000c,
            // v1 = this.getClient()
            0x106e, mIdx('Leu/kanade/tachiyomi/source/online/HttpSource;', 'getClient'), 0x0005,
            0x010c,
            // v1 = v1.newCall(v0)
            0x206e, mIdx('Lokhttp3/OkHttpClient;', 'newCall'), 0x0001,
            0x010c,
            // v1 = v1.execute()
            0x106e, mIdx('Lokhttp3/Call;', 'execute'), 0x0001,
            0x010c,
            // v0 = new ArrayList()
            0x0022, tIdx('Ljava/util/ArrayList;'),
            0x1070, mIdx('Ljava/util/ArrayList;', '<init>'), 0x0000,
            // v1 = new Page(0, "", "https://img.probe.test/1.jpg", null)
            0x0122, tIdx('Leu/kanade/tachiyomi/source/model/Page;'),
            0x0212, // index = 0
            0x031a, sIdx('https://img.probe.test/1.jpg'),
            0x0412, // uri = null
            0x5470, mIdx('Leu/kanade/tachiyomi/source/model/Page;', '<init>'), 0x3321,
            // v0.add(v1)
            0x206e, mIdx('Ljava/util/ArrayList;', 'add'), 0x0010,
            // return v0
            0x0011,
          ],
        }),
      },
    ],
  });

  const seenUrls = [];
  const vm = await createDexvm({
    wasmBytes,
    http(reqJson) {
      const req = JSON.parse(reqJson);
      seenUrls.push(req.url);
      return JSON.stringify({ status: 200, headers: [], bodyBase64: '', finalUrl: req.url });
    },
  });

  const { handle } = vm.call('open', { apkBase64: dex.toString('base64') });
  const sources = vm.call('sources', { handle });
  const pages = vm.call('pages', {
    handle,
    sourceId: sources[0].id,
    chapter: { url: '202166', name: 'Ch. 1' },
  });
  vm.call('close', { handle });

  assert.deepEqual(
    seenUrls,
    ['https://api.probe.test/pages/202166'],
    `expected only getPageList request, got: ${JSON.stringify(seenUrls)}`
  );
  assert.equal(pages.length, 1);
  assert.equal(pages[0].imageUrl, 'https://img.probe.test/1.jpg');
});

test('#1b: manhuagui v1.6.2 pages does not fire a legacy pageListRequest first', async () => {
  const apk = fs.readFileSync(path.join(FIXTURES, 'tachiyomi-zh.manhuagui-v1.6.2.apk'));
  const seenUrls = [];
  const vm = await createDexvm({
    wasmBytes,
    http(reqJson) {
      const req = JSON.parse(reqJson);
      seenUrls.push(req.url);
      // Return minimal 404/empty HTML so we only inspect the request URL(s)
      return JSON.stringify({ status: 404, headers: [], bodyBase64: '', finalUrl: req.url });
    },
  });

  const { handle } = vm.call('open', { apkBase64: apk.toString('base64') });
  const sources = vm.call('sources', { handle });
  try {
    vm.call('pages', {
      handle,
      sourceId: sources[0].id,
      chapter: { url: '/comic/12345/67890.html', name: 'Ch. 1' },
    });
  } catch {
    // 404 expected from mock
  }
  vm.call('close', { handle });

  // Must fire at most 1 request (the getPageList path), never 2 (legacy + coro).
  assert.equal(
    seenUrls.length,
    1,
    `expected exactly 1 HTTP request for 1.6 pages, got ${seenUrls.length}: ${JSON.stringify(seenUrls)}`
  );
});

// ===========================================================================
// #2: java.time.ZonedDateTime.toLocalDate() (and toLocalDateTime / LocalDateTime.toLocalDate)
// ===========================================================================
test('#2: ZonedDateTime.toLocalDate() returns LocalDate with matching calendar date', async () => {
  const dex = buildTestDex({
    extraStrings: [
      'I',
      'LL',
      'LLL',
      'Ljava/lang/CharSequence;',
      'Ljava/time/ZonedDateTime;',
      'Ljava/time/LocalDate;',
      'Ljava/time/LocalDateTime;',
      'Ljava/time/format/DateTimeFormatter;',
      'ofPattern',
      'parse',
      'toLocalDate',
      'toLocalDateTime',
      'format',
      'concat',
      'yyyy-MM-dd\'T\'HH:mm:ss',
      'yyyy-MM-dd',
      '2025-03-15T14:30:00',
      '|',
    ],
    extraTypes: [
      'Ljava/lang/CharSequence;',
      'Ljava/time/ZonedDateTime;',
      'Ljava/time/LocalDate;',
      'Ljava/time/LocalDateTime;',
      'Ljava/time/format/DateTimeFormatter;',
    ],
    extraProtos: [
      ['LL', 'Ljava/time/format/DateTimeFormatter;', ['Ljava/lang/String;']],
      ['LLL', 'Ljava/time/ZonedDateTime;', ['Ljava/lang/CharSequence;', 'Ljava/time/format/DateTimeFormatter;']],
      ['L', 'Ljava/time/LocalDate;', []],
      ['L', 'Ljava/time/LocalDateTime;', []],
      ['LL', 'Ljava/lang/String;', ['Ljava/time/format/DateTimeFormatter;']],
      ['LL', 'Ljava/lang/String;', ['Ljava/lang/String;']],
    ],
    extraMethods: [
      ['Ljava/time/format/DateTimeFormatter;', 'Ljava/time/format/DateTimeFormatter;', ['Ljava/lang/String;'], 'ofPattern'],
      ['Ljava/time/ZonedDateTime;', 'Ljava/time/ZonedDateTime;', ['Ljava/lang/CharSequence;', 'Ljava/time/format/DateTimeFormatter;'], 'parse'],
      ['Ljava/time/ZonedDateTime;', 'Ljava/time/LocalDate;', [], 'toLocalDate'],
      ['Ljava/time/ZonedDateTime;', 'Ljava/time/LocalDateTime;', [], 'toLocalDateTime'],
      ['Ljava/time/LocalDateTime;', 'Ljava/time/LocalDate;', [], 'toLocalDate'],
      ['Ljava/time/LocalDate;', 'Ljava/lang/String;', ['Ljava/time/format/DateTimeFormatter;'], 'format'],
      ['Ljava/lang/String;', 'Ljava/lang/String;', ['Ljava/lang/String;'], 'concat'],
    ],
    customGetName: ({ sIdx, mIdx }) => ({
      regs: 6,
      ins: 1,
      outs: 2,
      insns: [
        // v0 = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")
        0x001a, sIdx("yyyy-MM-dd'T'HH:mm:ss"),
        0x1071, mIdx('Ljava/time/format/DateTimeFormatter;', 'ofPattern'), 0x0000,
        0x000c,
        // v1 = ZonedDateTime.parse("2025-03-15T14:30:00", v0)
        0x011a, sIdx('2025-03-15T14:30:00'),
        0x2071, mIdx('Ljava/time/ZonedDateTime;', 'parse'), 0x0001,
        0x010c,
        // v2 = DateTimeFormatter.ofPattern("yyyy-MM-dd")
        0x021a, sIdx('yyyy-MM-dd'),
        0x1071, mIdx('Ljava/time/format/DateTimeFormatter;', 'ofPattern'), 0x0002,
        0x020c,
        // v3 = v1.toLocalDate().format(v2)
        0x106e, mIdx('Ljava/time/ZonedDateTime;', 'toLocalDate'), 0x0001,
        0x030c,
        0x206e, mIdx('Ljava/time/LocalDate;', 'format'), 0x0023,
        0x030c,
        // v4 = v1.toLocalDateTime().toLocalDate().format(v2)
        0x106e, mIdx('Ljava/time/ZonedDateTime;', 'toLocalDateTime'), 0x0001,
        0x040c,
        0x106e, mIdx('Ljava/time/LocalDateTime;', 'toLocalDate'), 0x0004,
        0x040c,
        0x206e, mIdx('Ljava/time/LocalDate;', 'format'), 0x0024,
        0x040c,
        // return v3.concat("|").concat(v4)
        0x001a, sIdx('|'),
        0x206e, mIdx('Ljava/lang/String;', 'concat'), 0x0003,
        0x030c,
        0x206e, mIdx('Ljava/lang/String;', 'concat'), 0x0043,
        0x030c,
        0x0311,
      ],
    }),
  });

  const vm = await createDexvm({
    wasmBytes,
    http(reqJson) {
      const req = JSON.parse(reqJson);
      return JSON.stringify({ status: 200, headers: [], bodyBase64: '', finalUrl: req.url });
    },
  });
  const { handle } = vm.call('open', { apkBase64: dex.toString('base64') });
  const sources = vm.call('sources', { handle });
  vm.call('close', { handle });

  assert.equal(sources[0].name, '2025-03-15|2025-03-15');
});

// ===========================================================================
// #3: 1.6 `popular` dispatches directly to `getPopularManga` (no legacy `popularMangaRequest`)
// ===========================================================================
test('#3: 1.6 source popular dispatches directly to getPopularManga and surfaces HTTP 403 cleanly', async () => {
  const dex = buildTestDex({
    extraStrings: [
      'I',
      'LL',
      'LLL',
      'LIL',
      'LLLL',
      'VLZ',
      'getPopularManga',
      'getClient',
      'newCall',
      'awaitSuccess',
      'GET',
      'https://api.probe.test/popular/1',
      'Lokhttp3/OkHttpClient;',
      'Lokhttp3/Request;',
      'Lokhttp3/Call;',
      'Lokhttp3/Response;',
      'Lokhttp3/Headers;',
      'Lokhttp3/CacheControl;',
      'Leu/kanade/tachiyomi/network/RequestsKt;',
      'Leu/kanade/tachiyomi/network/OkHttpExtensionsKt;',
      'Leu/kanade/tachiyomi/source/model/MangasPage;',
      'Lkotlin/coroutines/Continuation;',
      'Ljava/lang/Object;',
      'Ljava/util/ArrayList;',
      'Ljava/util/List;',
    ],
    extraTypes: [
      'I',
      'Lokhttp3/OkHttpClient;',
      'Lokhttp3/Request;',
      'Lokhttp3/Call;',
      'Lokhttp3/Response;',
      'Lokhttp3/Headers;',
      'Lokhttp3/CacheControl;',
      'Leu/kanade/tachiyomi/network/RequestsKt;',
      'Leu/kanade/tachiyomi/network/OkHttpExtensionsKt;',
      'Leu/kanade/tachiyomi/source/model/MangasPage;',
      'Lkotlin/coroutines/Continuation;',
      'Ljava/lang/Object;',
      'Ljava/util/ArrayList;',
      'Ljava/util/List;',
    ],
    extraProtos: [
      ['LIL', 'Ljava/lang/Object;', ['I', 'Lkotlin/coroutines/Continuation;']],
      ['L', 'Lokhttp3/OkHttpClient;', []],
      ['LL', 'Lokhttp3/Call;', ['Lokhttp3/Request;']],
      ['LLL', 'Ljava/lang/Object;', ['Lokhttp3/Call;', 'Lkotlin/coroutines/Continuation;']],
      ['LLLL', 'Lokhttp3/Request;', ['Ljava/lang/String;', 'Lokhttp3/Headers;', 'Lokhttp3/CacheControl;']],
      ['VLZ', 'V', ['Ljava/util/List;', 'Z']],
    ],
    extraMethods: [
      ['Ltest/ProbeSource;', 'Ljava/lang/Object;', ['I', 'Lkotlin/coroutines/Continuation;'], 'getPopularManga'],
      ['Leu/kanade/tachiyomi/source/online/HttpSource;', 'Lokhttp3/OkHttpClient;', [], 'getClient'],
      ['Lokhttp3/OkHttpClient;', 'Lokhttp3/Call;', ['Lokhttp3/Request;'], 'newCall'],
      ['Leu/kanade/tachiyomi/network/OkHttpExtensionsKt;', 'Ljava/lang/Object;', ['Lokhttp3/Call;', 'Lkotlin/coroutines/Continuation;'], 'awaitSuccess'],
      ['Leu/kanade/tachiyomi/network/RequestsKt;', 'Lokhttp3/Request;', ['Ljava/lang/String;', 'Lokhttp3/Headers;', 'Lokhttp3/CacheControl;'], 'GET'],
      ['Ljava/util/ArrayList;', 'V', [], '<init>'],
      ['Leu/kanade/tachiyomi/source/model/MangasPage;', 'V', ['Ljava/util/List;', 'Z'], '<init>'],
    ],
    customVirtualMethods: [
      {
        name: 'getPopularManga',
        ret: 'Ljava/lang/Object;',
        params: ['I', 'Lkotlin/coroutines/Continuation;'],
        buildCode: ({ sIdx, tIdx, mIdx }) => ({
          // regs: v0..v3, ins: 3 (p0=v4=this, p1=v5=page, p2=v6=cont)
          regs: 7,
          ins: 3,
          outs: 3,
          insns: [
            // v0 = RequestsKt.GET("https://api.probe.test/popular/1", null, null)
            0x001a, sIdx('https://api.probe.test/popular/1'),
            0x0112,
            0x0212,
            0x3071, mIdx('Leu/kanade/tachiyomi/network/RequestsKt;', 'GET'), 0x0210,
            0x000c,
            // v1 = this.getClient().newCall(v0)
            0x106e, mIdx('Leu/kanade/tachiyomi/source/online/HttpSource;', 'getClient'), 0x0004,
            0x010c,
            0x206e, mIdx('Lokhttp3/OkHttpClient;', 'newCall'), 0x0001,
            0x010c,
            // OkHttpExtensionsKt.awaitSuccess(v1, cont=v6) -> throws IOException("HTTP 403") on 403
            0x2071, mIdx('Leu/kanade/tachiyomi/network/OkHttpExtensionsKt;', 'awaitSuccess'), 0x0061,
            0x010c,
            // v0 = new ArrayList()
            0x0022, tIdx('Ljava/util/ArrayList;'),
            0x1070, mIdx('Ljava/util/ArrayList;', '<init>'), 0x0000,
            // v1 = new MangasPage(v0, false)
            0x0122, tIdx('Leu/kanade/tachiyomi/source/model/MangasPage;'),
            0x0212,
            0x3070, mIdx('Leu/kanade/tachiyomi/source/model/MangasPage;', '<init>'), 0x0201,
            0x0111,
          ],
        }),
      },
    ],
  });

  // Case A: 200 OK -> direct coroutine call succeeds with 1 HTTP request
  const seenOk = [];
  const vmOk = await createDexvm({
    wasmBytes,
    http(reqJson) {
      const req = JSON.parse(reqJson);
      seenOk.push(req.url);
      return JSON.stringify({ status: 200, headers: [], bodyBase64: '', finalUrl: req.url });
    },
  });
  const { handle: h1 } = vmOk.call('open', { apkBase64: dex.toString('base64') });
  const s1 = vmOk.call('sources', { handle: h1 });
  const pageRes = vmOk.call('popular', { handle: h1, sourceId: s1[0].id, page: 1 });
  vmOk.call('close', { handle: h1 });
  assert.deepEqual(seenOk, ['https://api.probe.test/popular/1']);
  assert.deepEqual(pageRes.mangas, []);

  // Case B: 403 Forbidden (reproducing Kagane v1.6.42) -> error must be HTTP 403,
  // NOT "resolution error: no method popularMangaRequest"
  const seen403 = [];
  const vm403 = await createDexvm({
    wasmBytes,
    http(reqJson) {
      const req = JSON.parse(reqJson);
      seen403.push(req.url);
      return JSON.stringify({ status: 403, headers: [], bodyBase64: '', finalUrl: req.url });
    },
  });
  const { handle: h2 } = vm403.call('open', { apkBase64: dex.toString('base64') });
  const s2 = vm403.call('sources', { handle: h2 });
  assert.throws(
    () => vm403.call('popular', { handle: h2, sourceId: s2[0].id, page: 1 }),
    (err) => {
      assert.match(err.message, /HTTP 403/);
      assert.doesNotMatch(err.message, /popularMangaRequest/);
      assert.doesNotMatch(err.message, /resolution error/);
      return true;
    }
  );
  vm403.call('close', { handle: h2 });
  assert.deepEqual(seen403, ['https://api.probe.test/popular/1']);
});
