// Offline reproduction tests for v0.2.7 fixes (#1-#3):
// 1 & 2. OkHttp Request.Builder.tag(...) / Request.tag(...) (Class, KClass, and Object)
//        are preserved across build(), newBuilder(), and the interceptor chain so
//        keiyoushi BrowserHeaders injects Referer, Accept, and Sec-Fetch-* headers.
// 3. `fetchImage` throws `HttpException: HTTP 403` on non-2xx responses instead of
//    returning 0 bytes.
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
  const methodIdsOff = protoIdsOff + protos.length * 12;
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
// #1 & #2: OkHttp Request.Builder.tag / Request.tag preserved across build() & newBuilder()
// ===========================================================================
test('#1/#2: Request.Builder.tag(Class/KClass/Object) preserved across build() and newBuilder()', async () => {
  const dex = buildTestDex({
    extraStrings: [
      'LL',
      'LLL',
      'Lokhttp3/Request;',
      'Lokhttp3/Request$Builder;',
      'Ljava/lang/Class;',
      'Ljava/lang/Object;',
      'Lkotlin/reflect/KClass;',
      'Lkotlin/jvm/internal/Reflection;',
      'url',
      'tag',
      'build',
      'newBuilder',
      'getOrCreateKotlinClass',
      'concat',
      'https://example.test/p',
      'kclass-val',
      'default-val',
      '|',
    ],
    extraTypes: [
      'Lokhttp3/Request;',
      'Lokhttp3/Request$Builder;',
      'Ljava/lang/Class;',
      'Ljava/lang/Object;',
      'Lkotlin/reflect/KClass;',
      'Lkotlin/jvm/internal/Reflection;',
    ],
    extraProtos: [
      ['LL', 'Lokhttp3/Request$Builder;', ['Ljava/lang/String;']],
      ['LL', 'Lokhttp3/Request$Builder;', ['Ljava/lang/Object;']],
      ['LLL', 'Lokhttp3/Request$Builder;', ['Lkotlin/reflect/KClass;', 'Ljava/lang/Object;']],
      ['L', 'Lokhttp3/Request;', []],
      ['L', 'Lokhttp3/Request$Builder;', []],
      ['L', 'Ljava/lang/Object;', []],
      ['LL', 'Ljava/lang/Object;', ['Ljava/lang/Class;']],
      ['LL', 'Lkotlin/reflect/KClass;', ['Ljava/lang/Class;']],
      ['LL', 'Ljava/lang/String;', ['Ljava/lang/String;']],
    ],
    extraMethods: [
      ['Lokhttp3/Request$Builder;', 'V', [], '<init>'],
      ['Lokhttp3/Request$Builder;', 'Lokhttp3/Request$Builder;', ['Ljava/lang/String;'], 'url'],
      ['Lokhttp3/Request$Builder;', 'Lokhttp3/Request$Builder;', ['Ljava/lang/Object;'], 'tag'],
      ['Lokhttp3/Request$Builder;', 'Lokhttp3/Request$Builder;', ['Lkotlin/reflect/KClass;', 'Ljava/lang/Object;'], 'tag'],
      ['Lokhttp3/Request$Builder;', 'Lokhttp3/Request;', [], 'build'],
      ['Lokhttp3/Request;', 'Lokhttp3/Request$Builder;', [], 'newBuilder'],
      ['Lokhttp3/Request;', 'Ljava/lang/Object;', [], 'tag'],
      ['Lokhttp3/Request;', 'Ljava/lang/Object;', ['Ljava/lang/Class;'], 'tag'],
      ['Lkotlin/jvm/internal/Reflection;', 'Lkotlin/reflect/KClass;', ['Ljava/lang/Class;'], 'getOrCreateKotlinClass'],
      ['Ljava/lang/String;', 'Ljava/lang/String;', ['Ljava/lang/String;'], 'concat'],
    ],
    customGetName: ({ sIdx, tIdx, mIdx }) => ({
      regs: 6,
      ins: 1,
      outs: 3,
      insns: [
        // v0 = new Request$Builder().url("https://example.test/p")
        0x0022, tIdx('Lokhttp3/Request$Builder;'),
        0x1070, mIdx('Lokhttp3/Request$Builder;', '<init>'), 0x0000,
        0x011a, sIdx('https://example.test/p'),
        0x206e, mIdx('Lokhttp3/Request$Builder;', 'url'), 0x0010,
        0x000c,
        // v1 = String.class; v2 = Reflection.getOrCreateKotlinClass(String.class)
        0x011c, tIdx('Ljava/lang/String;'),
        0x1071, mIdx('Lkotlin/jvm/internal/Reflection;', 'getOrCreateKotlinClass'), 0x0001,
        0x020c,
        // v0.tag(KClass<String>, "kclass-val").tag("default-val")
        0x031a, sIdx('kclass-val'),
        0x306e, mIdx('Lokhttp3/Request$Builder;', 'tag', null, ['Lkotlin/reflect/KClass;', 'Ljava/lang/Object;']), 0x0320,
        0x000c,
        0x031a, sIdx('default-val'),
        0x206e, mIdx('Lokhttp3/Request$Builder;', 'tag', null, ['Ljava/lang/Object;']), 0x0030,
        0x000c,
        // v0 = v0.build().newBuilder().build() (verifies tags survive build -> newBuilder -> build)
        0x106e, mIdx('Lokhttp3/Request$Builder;', 'build'), 0x0000,
        0x000c,
        0x106e, mIdx('Lokhttp3/Request;', 'newBuilder'), 0x0000,
        0x000c,
        0x106e, mIdx('Lokhttp3/Request$Builder;', 'build'), 0x0000,
        0x000c,
        // v2 = (String) v0.tag(String.class)  (cross-read KClass tag via Class!)
        0x206e, mIdx('Lokhttp3/Request;', 'tag', null, ['Ljava/lang/Class;']), 0x0010,
        0x020c,
        0x021f, tIdx('Ljava/lang/String;'),
        // v3 = (String) v0.tag()
        0x106e, mIdx('Lokhttp3/Request;', 'tag', null, []), 0x0000,
        0x030c,
        0x031f, tIdx('Ljava/lang/String;'),
        // return v2.concat("|").concat(v3)
        0x041a, sIdx('|'),
        0x206e, mIdx('Ljava/lang/String;', 'concat'), 0x0042,
        0x020c,
        0x206e, mIdx('Ljava/lang/String;', 'concat'), 0x0032,
        0x020c,
        0x0211,
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

  assert.equal(sources[0].name, 'kclass-val|default-val');
});

test('#2: Response.newBuilder() preserves body, Request.Builder.headers() replaces, Headers.iterator() yields Pair, HttpUrl.defaultPort works', async () => {
  const dex = buildTestDex({
    extraStrings: [
      'I',
      'IL',
      'LI',
      'LL',
      'LLL',
      'Lokhttp3/Request;',
      'Lokhttp3/Request$Builder;',
      'Lokhttp3/Headers;',
      'Lokhttp3/Headers$Builder;',
      'Lokhttp3/HttpUrl;',
      'Lokhttp3/HttpUrl$Builder;',
      'Lokhttp3/HttpUrl$Companion;',
      'Ljava/util/Iterator;',
      'Lkotlin/Pair;',
      'Ljava/lang/Object;',
      'Ljava/lang/StringBuilder;',
      'url',
      'addHeader',
      'headers',
      'add',
      'build',
      'size',
      'iterator',
      'next',
      'getFirst',
      'getSecond',
      'defaultPort',
      'append',
      'toString',
      'https://example.test/p',
      'https',
      'X-Old',
      'old',
      'X-New',
      'new',
      ':',
      '|',
    ],
    extraTypes: [
      'I',
      'Lokhttp3/Request;',
      'Lokhttp3/Request$Builder;',
      'Lokhttp3/Headers;',
      'Lokhttp3/Headers$Builder;',
      'Lokhttp3/HttpUrl;',
      'Ljava/util/Iterator;',
      'Lkotlin/Pair;',
      'Ljava/lang/Object;',
      'Ljava/lang/StringBuilder;',
    ],
    extraProtos: [
      ['LL', 'Lokhttp3/Request$Builder;', ['Ljava/lang/String;']],
      ['LLL', 'Lokhttp3/Request$Builder;', ['Ljava/lang/String;', 'Ljava/lang/String;']],
      ['LL', 'Lokhttp3/Request$Builder;', ['Lokhttp3/Headers;']],
      ['L', 'Lokhttp3/Request;', []],
      ['L', 'Lokhttp3/Headers;', []],
      ['LLL', 'Lokhttp3/Headers$Builder;', ['Ljava/lang/String;', 'Ljava/lang/String;']],
      ['L', 'Ljava/util/Iterator;', []],
      ['L', 'Ljava/lang/Object;', []],
      ['I', 'I', []],
      ['IL', 'I', ['Ljava/lang/String;']],
      ['LI', 'Ljava/lang/StringBuilder;', ['I']],
      ['LL', 'Ljava/lang/StringBuilder;', ['Ljava/lang/String;']],
    ],
    extraMethods: [
      ['Lokhttp3/Request$Builder;', 'V', [], '<init>'],
      ['Lokhttp3/Request$Builder;', 'Lokhttp3/Request$Builder;', ['Ljava/lang/String;'], 'url'],
      ['Lokhttp3/Request$Builder;', 'Lokhttp3/Request$Builder;', ['Ljava/lang/String;', 'Ljava/lang/String;'], 'addHeader'],
      ['Lokhttp3/Request$Builder;', 'Lokhttp3/Request$Builder;', ['Lokhttp3/Headers;'], 'headers'],
      ['Lokhttp3/Request$Builder;', 'Lokhttp3/Request;', [], 'build'],
      ['Lokhttp3/Request;', 'Lokhttp3/Headers;', [], 'headers'],
      ['Lokhttp3/Headers$Builder;', 'V', [], '<init>'],
      ['Lokhttp3/Headers$Builder;', 'Lokhttp3/Headers$Builder;', ['Ljava/lang/String;', 'Ljava/lang/String;'], 'add'],
      ['Lokhttp3/Headers$Builder;', 'Lokhttp3/Headers;', [], 'build'],
      ['Lokhttp3/Headers;', 'I', [], 'size'],
      ['Lokhttp3/Headers;', 'Ljava/util/Iterator;', [], 'iterator'],
      ['Ljava/util/Iterator;', 'Ljava/lang/Object;', [], 'next'],
      ['Lkotlin/Pair;', 'Ljava/lang/Object;', [], 'getFirst'],
      ['Lkotlin/Pair;', 'Ljava/lang/Object;', [], 'getSecond'],
      ['Lokhttp3/HttpUrl;', 'I', ['Ljava/lang/String;'], 'defaultPort'],
      ['Ljava/lang/StringBuilder;', 'V', [], '<init>'],
      ['Ljava/lang/StringBuilder;', 'Ljava/lang/StringBuilder;', ['I'], 'append'],
      ['Ljava/lang/StringBuilder;', 'Ljava/lang/StringBuilder;', ['Ljava/lang/String;'], 'append'],
      ['Ljava/lang/StringBuilder;', 'Ljava/lang/String;', [], 'toString'],
    ],
    customGetName: ({ sIdx, tIdx, mIdx }) => ({
      regs: 6,
      ins: 1,
      outs: 3,
      insns: [
        // v0 = new Headers$Builder().add("X-New", "new").build()
        0x0022, tIdx('Lokhttp3/Headers$Builder;'),
        0x1070, mIdx('Lokhttp3/Headers$Builder;', '<init>'), 0x0000,
        0x011a, sIdx('X-New'),
        0x021a, sIdx('new'),
        0x306e, mIdx('Lokhttp3/Headers$Builder;', 'add'), 0x0210,
        0x000c,
        0x106e, mIdx('Lokhttp3/Headers$Builder;', 'build'), 0x0000,
        0x000c,
        // v1 = new Request$Builder().url(...).addHeader("X-Old", "old").headers(v0).build()
        0x0122, tIdx('Lokhttp3/Request$Builder;'),
        0x1070, mIdx('Lokhttp3/Request$Builder;', '<init>'), 0x0001,
        0x021a, sIdx('https://example.test/p'),
        0x206e, mIdx('Lokhttp3/Request$Builder;', 'url'), 0x0021,
        0x010c,
        0x021a, sIdx('X-Old'),
        0x031a, sIdx('old'),
        0x306e, mIdx('Lokhttp3/Request$Builder;', 'addHeader'), 0x0321,
        0x010c,
        0x206e, mIdx('Lokhttp3/Request$Builder;', 'headers'), 0x0001,
        0x010c,
        0x106e, mIdx('Lokhttp3/Request$Builder;', 'build'), 0x0001,
        0x010c,
        // v0 = v1.headers() (must have size 1, NOT 2!)
        0x106e, mIdx('Lokhttp3/Request;', 'headers'), 0x0001,
        0x000c,
        0x106e, mIdx('Lokhttp3/Headers;', 'size'), 0x0000,
        0x040a, // v4 = size
        // v1 = (Pair) v0.iterator().next()
        0x106e, mIdx('Lokhttp3/Headers;', 'iterator'), 0x0000,
        0x010c,
        0x1072, mIdx('Ljava/util/Iterator;', 'next'), 0x0001,
        0x010c,
        0x011f, tIdx('Lkotlin/Pair;'),
        // v2 = (String) v1.getFirst(), v3 = (String) v1.getSecond()
        0x106e, mIdx('Lkotlin/Pair;', 'getFirst'), 0x0001,
        0x020c,
        0x021f, tIdx('Ljava/lang/String;'),
        0x106e, mIdx('Lkotlin/Pair;', 'getSecond'), 0x0001,
        0x030c,
        0x031f, tIdx('Ljava/lang/String;'),
        // v0 = new StringBuilder()
        0x0022, tIdx('Ljava/lang/StringBuilder;'),
        0x1070, mIdx('Ljava/lang/StringBuilder;', '<init>'), 0x0000,
        // append size + "|" + first + ":" + second + "|" + HttpUrl.defaultPort("https")
        0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['I']), 0x0040,
        0x011a, sIdx('|'),
        0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['Ljava/lang/String;']), 0x0010,
        0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['Ljava/lang/String;']), 0x0020,
        0x021a, sIdx(':'),
        0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['Ljava/lang/String;']), 0x0020,
        0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['Ljava/lang/String;']), 0x0030,
        0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['Ljava/lang/String;']), 0x0010,
        0x021a, sIdx('https'),
        0x1071, mIdx('Lokhttp3/HttpUrl;', 'defaultPort'), 0x0002,
        0x040a,
        0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', null, ['I']), 0x0040,
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

  assert.equal(sources[0].name, '1|X-New:new|443');
});

// ===========================================================================
// #3: fetchImage throws HttpException: HTTP 403 on non-2xx (never returns 0 bytes)
// ===========================================================================
test('#3: fetchImage throws HTTP 403 on 403 response instead of returning 0 bytes', async () => {
  const dex = buildTestDex({});
  const seen = [];
  const vm = await createDexvm({
    wasmBytes,
    http(reqJson) {
      const req = JSON.parse(reqJson);
      seen.push(req.url);
      return JSON.stringify({
        status: 403,
        headers: [['content-type', 'text/html']],
        bodyBase64: '',
        finalUrl: req.url,
      });
    },
  });

  const { handle } = vm.call('open', { apkBase64: dex.toString('base64') });
  const sources = vm.call('sources', { handle });
  assert.throws(
    () =>
      vm.call('fetchImage', {
        handle,
        sourceId: sources[0].id,
        page: {
          index: 0,
          url: 'https://probe.test/ch1/',
          imageUrl: 'https://cdn.probe.test/img1.jpg',
        },
      }),
    (err) => {
      assert.match(err.message, /HTTP 403/);
      return true;
    }
  );
  vm.call('close', { handle });
  assert.deepEqual(seen, ['https://cdn.probe.test/img1.jpg'], 'must not retry after HTTP 403');
});
