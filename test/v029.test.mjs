// Offline unit tests for v0.2.9 requirements:
// 1. FilterDef / FilterState (all 8 kinds + nested Group + mutating real Filter subclass instances).
// 2. PreferenceValue::StringSet (setPreference / open.prefs / exportPrefs / SharedPreferences.getStringSet).
// 3. Regex.findAll$default returning Sequence<MatchResult> (fixes comicabc `not a collection`).
// 4. Cookie jar RFC 6265 domain-match, port stripping, and merging jar cookies into existing Cookie headers.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createDexvm } from '../dexvm-host.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const WASM = process.env.DEXVM_WASM || path.join(ROOT, 'dist', 'dexvm_bridge.wasm');

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

/**
 * Minimal multi-class DEX builder supporting custom methods on `Ltest/ProbeSource;`
 * plus optional extra classes (e.g. a Filter$Select subclass or Function1 lambda).
 */
function buildDex({
  extraStrings = [],
  extraTypes = [],
  extraProtos = [],
  extraMethods = [],
  extraClasses = [], // [{ desc, superDesc, ifaces?: [], methods: ({sIdx,tIdx,mIdx}) => [...] }]
  probeExtraMethods = () => [],
  customGetName = ({ sIdx }) => ({ regs: 2, ins: 1, outs: 0, insns: [0x001a, sIdx('ProbeSource'), 0x0011] }),
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
    'https://www.example.com',
  ];
  const autoStrings = [
    ...extraStrings,
    ...extraTypes,
    ...extraClasses.flatMap((c) => [c.desc, c.superDesc, ...(c.ifaces || [])]),
    ...extraProtos.map(([s]) => s),
    ...extraMethods.map(([, , , n]) => n),
  ];
  const strings = [...new Set([...baseStrings, ...autoStrings])].sort((a, b) =>
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
  const types = [
    ...new Set([
      ...baseTypes,
      ...extraTypes,
      ...extraClasses.flatMap((c) => [c.desc, c.superDesc, ...(c.ifaces || [])]),
    ]),
  ].sort((a, b) => sIdx(a) - sIdx(b));
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
  const classDefs = [
    ...extraClasses.map((c) => ({
      desc: c.desc,
      superDesc: c.superDesc,
      ifaces: c.ifaces || [],
      methods: c.methods(helpers),
    })),
    {
      desc: 'Ltest/ProbeSource;',
      superDesc: 'Leu/kanade/tachiyomi/source/online/HttpSource;',
      ifaces: [],
      methods: [
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
          code: { regs: 2, ins: 1, outs: 0, insns: [0x001a, sIdx('https://www.example.com'), 0x0011] },
        },
        {
          idx: mIdx('Ltest/ProbeSource;', 'getId'),
          direct: false,
          access: 0x1,
          code: { regs: 3, ins: 1, outs: 0, insns: [0x0016, 0x0028, 0x0010] },
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
        ...probeExtraMethods(helpers),
      ],
    },
  ];

  const headerSize = 0x70;
  const stringIdsOff = headerSize;
  const typeIdsOff = stringIdsOff + strings.length * 4;
  const protoIdsOff = typeIdsOff + types.length * 4;
  const methodIdsOff = protoIdsOff + protos.length * 12;
  const classDefsOff = methodIdsOff + allMethods.length * 8;
  const dataOff = classDefsOff + classDefs.length * 32;

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

  const classIfaceOffs = classDefs.map((cd) => {
    if (!cd.ifaces.length) return 0;
    align4();
    const buf = Buffer.alloc(4 + cd.ifaces.length * 2);
    buf.writeUInt32LE(cd.ifaces.length, 0);
    cd.ifaces.forEach((iface, i) => buf.writeUInt16LE(tIdx(iface), 4 + i * 2));
    return pushBytes(buf);
  });

  const classDataOffs = classDefs.map((cd) => {
    const codeOffs = cd.methods.map(({ code }) => {
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
    const direct = cd.methods
      .map((m, i) => ({ ...m, codeOff: codeOffs[i] }))
      .filter((m) => m.direct)
      .sort((a, b) => a.idx - b.idx);
    const virtual = cd.methods
      .map((m, i) => ({ ...m, codeOff: codeOffs[i] }))
      .filter((m) => !m.direct)
      .sort((a, b) => a.idx - b.idx);
    const enc = [];
    enc.push(...uleb128(0), ...uleb128(0), ...uleb128(direct.length), ...uleb128(virtual.length));
    let prev = 0;
    for (const m of direct) {
      enc.push(...uleb128(m.idx - prev), ...uleb128(m.access), ...uleb128(m.codeOff));
      prev = m.idx;
    }
    prev = 0;
    for (const m of virtual) {
      enc.push(...uleb128(m.idx - prev), ...uleb128(m.access), ...uleb128(m.codeOff));
      prev = m.idx;
    }
    return pushBytes(enc);
  });

  align4();
  const mapOff = cursor;
  const mapBuf = Buffer.alloc(16);
  mapBuf.writeUInt32LE(1, 0);
  mapBuf.writeUInt16LE(0x1000, 4);
  mapBuf.writeUInt32LE(1, 8);
  mapBuf.writeUInt32LE(mapOff, 12);
  pushBytes(mapBuf);

  const fileSize = cursor;
  const out = Buffer.alloc(fileSize);
  Buffer.from('dex\n035\0', 'ascii').copy(out, 0);
  out.writeUInt32LE(fileSize, 32);
  out.writeUInt32LE(headerSize, 36);
  out.writeUInt32LE(0x12345678, 40);
  out.writeUInt32LE(mapOff, 52);
  out.writeUInt32LE(strings.length, 56);
  out.writeUInt32LE(stringIdsOff, 60);
  out.writeUInt32LE(types.length, 64);
  out.writeUInt32LE(typeIdsOff, 68);
  out.writeUInt32LE(protos.length, 72);
  out.writeUInt32LE(protoIdsOff, 76);
  out.writeUInt32LE(allMethods.length, 88);
  out.writeUInt32LE(methodIdsOff, 92);
  out.writeUInt32LE(classDefs.length, 96);
  out.writeUInt32LE(classDefsOff, 100);
  out.writeUInt32LE(fileSize - dataOff, 104);
  out.writeUInt32LE(dataOff, 108);

  stringDataOffs.forEach((off, i) => out.writeUInt32LE(off, stringIdsOff + i * 4));
  types.forEach((t, i) => out.writeUInt32LE(sIdx(t), typeIdsOff + i * 4));
  protos.forEach(([shorty, ret], i) => {
    const o = protoIdsOff + i * 12;
    out.writeUInt32LE(sIdx(shorty), o);
    out.writeUInt32LE(tIdx(ret), o + 4);
    out.writeUInt32LE(protoParamOffs[i], o + 8);
  });
  allMethods.forEach(([cls, ret, params, name], i) => {
    const o = methodIdsOff + i * 8;
    out.writeUInt16LE(tIdx(cls), o);
    out.writeUInt16LE(pIdx(ret, params), o + 2);
    out.writeUInt32LE(sIdx(name), o + 4);
  });
  classDefs.forEach((cd, i) => {
    const o = classDefsOff + i * 32;
    out.writeUInt32LE(tIdx(cd.desc), o);
    out.writeUInt32LE(0x1, o + 4);
    out.writeUInt32LE(tIdx(cd.superDesc), o + 8);
    out.writeUInt32LE(classIfaceOffs[i], o + 12);
    out.writeUInt32LE(0xffffffff, o + 16);
    out.writeUInt32LE(0, o + 20);
    out.writeUInt32LE(classDataOffs[i], o + 24);
    out.writeUInt32LE(0, o + 28);
  });

  let pos = dataOff;
  for (const c of chunks) {
    c.copy(out, pos);
    pos += c.length;
  }
  out.writeUInt32LE(adler32(out.subarray(12)), 8);
  return out;
}

// ---------------------------------------------------------------------------
// 1. Cookie jar: RFC 6265 domain-match, port stripping, and Cookie merging
// ---------------------------------------------------------------------------
test('cookies op: RFC 6265 domain-match, host-only isolation, and port stripping', async () => {
  const vm = await createDexvm({ wasmBytes: fs.readFileSync(WASM) });
  vm.call('cookies', { clear: true });

  // Domain-scoped cookie (leading dot)
  vm.call('cookies', {
    set: [
      ['.example.com', 'cf_clearance', 'tok123'],
      ['www.example.com', 'host_only', 'yes'],
      ['127.0.0.1:52987', 'local_sid', 'abc'],
    ],
  });

  // Subdomain matches .example.com AND host-only www.example.com
  const www = vm.call('cookies', { get: 'https://www.example.com/path' });
  assert.equal(www.cookie, 'cf_clearance=tok123; host_only=yes');

  // Apex matches .example.com, NOT host-only www.example.com
  const apex = vm.call('cookies', { get: 'https://example.com/' });
  assert.equal(apex.cookie, 'cf_clearance=tok123');

  // Deep subdomain matches .example.com, NOT host-only www.example.com
  const deep = vm.call('cookies', { get: 'https://sub.www.example.com/' });
  assert.equal(deep.cookie, 'cf_clearance=tok123');

  // Unrelated domain sharing suffix must NOT match
  const other = vm.call('cookies', { get: 'https://notexample.com/' });
  assert.equal(other.cookie, null);

  // Port-independent matching for host:port
  const localSame = vm.call('cookies', { get: 'http://127.0.0.1:52987/api' });
  assert.equal(localSame.cookie, 'local_sid=abc');
  const localOther = vm.call('cookies', { get: 'http://127.0.0.1:9999/api' });
  assert.equal(localOther.cookie, 'local_sid=abc');
});

test('on_http merges jar cookies into extension-crafted Cookie: a=1 header', async () => {
  const dex = buildDex({
    extraStrings: ['Cookie', 'a=1', 'https://www.example.com/list'],
    extraTypes: [
      'I',
      'Lokhttp3/Request;',
      'Lokhttp3/Request$Builder;',
      'Lokhttp3/Response;',
      'Leu/kanade/tachiyomi/source/model/MangasPage;',
      'Ljava/util/ArrayList;',
      'Ljava/util/List;',
    ],
    extraProtos: [
      ['LI', 'Lokhttp3/Request;', ['I']],
      ['LL', 'Lokhttp3/Request$Builder;', ['Ljava/lang/String;']],
      ['LLL', 'Lokhttp3/Request$Builder;', ['Ljava/lang/String;', 'Ljava/lang/String;']],
      ['L', 'Lokhttp3/Request;', []],
      ['LL', 'Leu/kanade/tachiyomi/source/model/MangasPage;', ['Lokhttp3/Response;']],
      ['VLZ', 'V', ['Ljava/util/List;', 'Z']],
    ],
    extraMethods: [
      ['Ltest/ProbeSource;', 'Lokhttp3/Request;', ['I'], 'popularMangaRequest'],
      ['Ltest/ProbeSource;', 'Leu/kanade/tachiyomi/source/model/MangasPage;', ['Lokhttp3/Response;'], 'popularMangaParse'],
      ['Lokhttp3/Request$Builder;', 'V', [], '<init>'],
      ['Lokhttp3/Request$Builder;', 'Lokhttp3/Request$Builder;', ['Ljava/lang/String;'], 'url'],
      ['Lokhttp3/Request$Builder;', 'Lokhttp3/Request$Builder;', ['Ljava/lang/String;', 'Ljava/lang/String;'], 'header'],
      ['Lokhttp3/Request$Builder;', 'Lokhttp3/Request;', [], 'build'],
      ['Ljava/util/ArrayList;', 'V', [], '<init>'],
      ['Leu/kanade/tachiyomi/source/model/MangasPage;', 'V', ['Ljava/util/List;', 'Z'], '<init>'],
    ],
    probeExtraMethods: ({ sIdx, tIdx, mIdx }) => [
      {
        idx: mIdx('Ltest/ProbeSource;', 'popularMangaRequest'),
        direct: false,
        access: 0x1,
        code: {
          regs: 5,
          ins: 2,
          outs: 3,
          insns: [
            // v0 = new Request$Builder()
            0x0022, tIdx('Lokhttp3/Request$Builder;'),
            0x1070, mIdx('Lokhttp3/Request$Builder;', '<init>'), 0x0000,
            // v0.url("https://www.example.com/list")
            0x011a, sIdx('https://www.example.com/list'),
            0x206e, mIdx('Lokhttp3/Request$Builder;', 'url'), 0x0010,
            // v0.header("Cookie", "a=1")
            0x011a, sIdx('Cookie'),
            0x021a, sIdx('a=1'),
            0x306e, mIdx('Lokhttp3/Request$Builder;', 'header'), 0x0210,
            // return v0.build()
            0x106e, mIdx('Lokhttp3/Request$Builder;', 'build'), 0x0000,
            0x000c,
            0x0011,
          ],
        },
      },
      {
        idx: mIdx('Ltest/ProbeSource;', 'popularMangaParse'),
        direct: false,
        access: 0x1,
        code: {
          regs: 5,
          ins: 2,
          outs: 3,
          insns: [
            0x0022, tIdx('Ljava/util/ArrayList;'),
            0x1070, mIdx('Ljava/util/ArrayList;', '<init>'), 0x0000,
            0x0122, tIdx('Leu/kanade/tachiyomi/source/model/MangasPage;'),
            0x0212,
            0x3070, mIdx('Leu/kanade/tachiyomi/source/model/MangasPage;', '<init>'), 0x0201,
            0x0111,
          ],
        },
      },
    ],
  });

  const seen = [];
  const vm = await createDexvm({
    wasmBytes: fs.readFileSync(WASM),
    http: (reqJson) => {
      seen.push(JSON.parse(reqJson));
      return JSON.stringify({ status: 200, headers: [], bodyBase64: '', finalUrl: 'https://www.example.com/list' });
    },
  });
  vm.call('cookies', { clear: true, set: [['.example.com', 'cf_clearance', 'tok123']] });
  const opened = vm.call('open', { apkBase64: dex.toString('base64') });
  const [src] = vm.call('sources', { handle: opened.handle });
  vm.call('popular', { handle: opened.handle, sourceId: src.id, page: 1 });

  assert.equal(seen.length, 1);
  const cookieHeaders = seen[0].headers.filter(([k]) => k.toLowerCase() === 'cookie');
  assert.equal(cookieHeaders.length, 1);
  assert.equal(cookieHeaders[0][1], 'a=1; cf_clearance=tok123');
});

// ---------------------------------------------------------------------------
// 2. PreferenceValue::StringSet (setPreference / open.prefs / exportPrefs / getStringSet)
// ---------------------------------------------------------------------------
test('PreferenceValue::StringSet round-trips through open.prefs, setPreference, exportPrefs, and getStringSet', async () => {
  const dex = buildDex({
    extraStrings: ['source_40', 'multi', ','],
    extraTypes: [
      'I',
      'Landroid/app/Application;',
      'Landroid/content/SharedPreferences;',
      'Ljava/util/Set;',
      'Ljava/util/ArrayList;',
      'Ljava/util/Collection;',
      'Ljava/util/Collections;',
      'Ljava/util/List;',
      'Ljava/lang/StringBuilder;',
      'Ljava/lang/Object;',
    ],
    extraProtos: [
      ['LL', 'Landroid/content/SharedPreferences;', ['Ljava/lang/String;', 'I']],
      ['LLL', 'Ljava/util/Set;', ['Ljava/lang/String;', 'Ljava/util/Set;']],
      ['VL', 'V', ['Ljava/util/Collection;']],
      ['VL', 'V', ['Ljava/util/List;']],
      ['LL', 'Ljava/lang/String;', ['Ljava/lang/Object;']],
      ['LL', 'Ljava/lang/String;', []],
    ],
    extraMethods: [
      ['Landroid/app/Application;', 'V', [], '<init>'],
      ['Landroid/app/Application;', 'Landroid/content/SharedPreferences;', ['Ljava/lang/String;', 'I'], 'getSharedPreferences'],
      ['Landroid/content/SharedPreferences;', 'Ljava/util/Set;', ['Ljava/lang/String;', 'Ljava/util/Set;'], 'getStringSet'],
      ['Ljava/util/ArrayList;', 'V', ['Ljava/util/Collection;'], '<init>'],
      ['Ljava/util/Collections;', 'V', ['Ljava/util/List;'], 'sort'],
      ['Ljava/lang/Object;', 'Ljava/lang/String;', [], 'toString'],
    ],
    // getName() reads SharedPreferences("source_40").getStringSet("multi", null), sorts into ArrayList, returns toString().
    customGetName: ({ sIdx, tIdx, mIdx }) => ({
      regs: 5,
      ins: 1,
      outs: 3,
      insns: [
        // v0 = new Application()
        0x0022, tIdx('Landroid/app/Application;'),
        0x1070, mIdx('Landroid/app/Application;', '<init>'), 0x0000,
        // v1 = "source_40", v2 = 0
        0x011a, sIdx('source_40'),
        0x0212,
        // v0 = v0.getSharedPreferences("source_40", 0)
        0x306e, mIdx('Landroid/app/Application;', 'getSharedPreferences'), 0x0210,
        0x000c,
        // v1 = "multi", v2 = null
        0x011a, sIdx('multi'),
        0x0212,
        // v0 = v0.getStringSet("multi", null)
        0x3072, mIdx('Landroid/content/SharedPreferences;', 'getStringSet'), 0x0210,
        0x000c,
        // v1 = new ArrayList(v0)
        0x0122, tIdx('Ljava/util/ArrayList;'),
        0x2070, mIdx('Ljava/util/ArrayList;', '<init>'), 0x0001,
        // Collections.sort(v1)
        0x1071, mIdx('Ljava/util/Collections;', 'sort'), 0x0001,
        // return v1.toString()
        0x106e, mIdx('Ljava/lang/Object;', 'toString'), 0x0001,
        0x000c,
        0x0011,
      ],
    }),
  });

  const vm = await createDexvm({ wasmBytes: fs.readFileSync(WASM) });
  // 1) Seed via open.prefs as JSON array
  const opened = vm.call('open', {
    apkBase64: dex.toString('base64'),
    prefs: { source_40: { multi: ['beta', 'alpha'] } },
  });
  const [src1] = vm.call('sources', { handle: opened.handle });
  assert.equal(src1.name, '[alpha, beta]');
  const exp1 = vm.call('exportPrefs', { handle: opened.handle });
  assert.deepEqual(exp1.source_40.multi, ['beta', 'alpha']);

  // 2) Update via setPreference with JSON array
  vm.call('setPreference', {
    handle: opened.handle,
    sourceId: src1.id,
    key: 'multi',
    value: ['z', 'x', 'y'],
  });
  const exp2 = vm.call('exportPrefs', { handle: opened.handle });
  assert.deepEqual(exp2.source_40.multi, ['z', 'x', 'y']);
  // Calling sources again re-reads getName() -> reads updated StringSet
  const [src2] = vm.call('sources', { handle: opened.handle });
  assert.equal(src2.name, '[x, y, z]');

  // 3) Empty array stores empty StringSet (not null / default)
  vm.call('setPreference', {
    handle: opened.handle,
    sourceId: src1.id,
    key: 'multi',
    value: [],
  });
  const exp3 = vm.call('exportPrefs', { handle: opened.handle });
  assert.deepEqual(exp3.source_40.multi, []);
  const [src3] = vm.call('sources', { handle: opened.handle });
  assert.equal(src3.name, '[]');
});

// ---------------------------------------------------------------------------
// 3. Regex.findAll$default returns Sequence<MatchResult> (comicabc fix)
// ---------------------------------------------------------------------------
test('Regex.findAll$default returns Sequence<MatchResult> iterable by SequencesKt.toList', async () => {
  const dex = buildDex({
    extraStrings: ['p\\d+', 'a p10 b p20 c p30'],
    extraTypes: [
      'I',
      'Ljava/lang/CharSequence;',
      'Ljava/lang/Object;',
      'Lkotlin/text/Regex;',
      'Lkotlin/sequences/Sequence;',
      'Lkotlin/sequences/SequencesKt;',
      'Ljava/util/List;',
    ],
    extraProtos: [
      ['VL', 'V', ['Ljava/lang/String;']],
      ['LLLIIL', 'Lkotlin/sequences/Sequence;', ['Lkotlin/text/Regex;', 'Ljava/lang/CharSequence;', 'I', 'I', 'Ljava/lang/Object;']],
      ['LL', 'Ljava/util/List;', ['Lkotlin/sequences/Sequence;']],
      ['I', 'I', []],
      ['LI', 'Ljava/lang/String;', ['I']],
    ],
    extraMethods: [
      ['Lkotlin/text/Regex;', 'V', ['Ljava/lang/String;'], '<init>'],
      ['Lkotlin/text/Regex;', 'Lkotlin/sequences/Sequence;', ['Lkotlin/text/Regex;', 'Ljava/lang/CharSequence;', 'I', 'I', 'Ljava/lang/Object;'], 'findAll$default'],
      ['Lkotlin/sequences/SequencesKt;', 'Ljava/util/List;', ['Lkotlin/sequences/Sequence;'], 'toList'],
      ['Ljava/util/List;', 'I', [], 'size'],
      ['Ljava/lang/String;', 'Ljava/lang/String;', ['I'], 'valueOf'],
    ],
    // getName() runs Regex("p\\d+").findAll$default(re, "a p10 b p20 c p30", 0, 2, null) -> toList() -> String.valueOf(size())
    customGetName: ({ sIdx, tIdx, mIdx }) => ({
      regs: 6,
      ins: 1,
      outs: 5,
      insns: [
        // v0 = new Regex("p\\d+")
        0x0022, tIdx('Lkotlin/text/Regex;'),
        0x011a, sIdx('p\\d+'),
        0x2070, mIdx('Lkotlin/text/Regex;', '<init>'), 0x0010,
        // v1 = "a p10 b p20 c p30", v2 = 0, v3 = 2, v4 = null
        0x011a, sIdx('a p10 b p20 c p30'),
        0x0212,
        0x2312,
        0x0412,
        // v0 = Regex.findAll$default(v0, v1, v2, v3, v4)
        0x5471, mIdx('Lkotlin/text/Regex;', 'findAll$default'), 0x3210,
        0x000c,
        // v0 = SequencesKt.toList(v0)
        0x1071, mIdx('Lkotlin/sequences/SequencesKt;', 'toList'), 0x0000,
        0x000c,
        // v0 = v0.size()
        0x1072, mIdx('Ljava/util/List;', 'size'), 0x0000,
        0x000a,
        // return String.valueOf(v0)
        0x1071, mIdx('Ljava/lang/String;', 'valueOf'), 0x0000,
        0x000c,
        0x0011,
      ],
    }),
  });

  const vm = await createDexvm({ wasmBytes: fs.readFileSync(WASM) });
  const opened = vm.call('open', { apkBase64: dex.toString('base64') });
  const [src] = vm.call('sources', { handle: opened.handle });
  assert.equal(src.name, '3');
});

// ---------------------------------------------------------------------------
// 4. FilterDef (all 8 kinds + nested Group) & FilterState applied to real subclasses
// ---------------------------------------------------------------------------
test('filters & search: all 8 Filter kinds, nested Group, and real subclass state mutation', async () => {
  const dex = buildDex({
    extraStrings: [
      'Section',
      'Region',
      'All',
      'JP',
      'Author',
      'init',
      'Completed',
      'Action',
      'Sort',
      'Popular',
      'Latest',
      'Tags',
      'TagA',
      'https://www.example.com/search?',
      'sel=',
      '&txt=',
      '&chk=',
      '&tri=',
      '&sort=',
      '&grp=',
    ],
    extraTypes: [
      'I',
      'Ljava/lang/Object;',
      '[Ljava/lang/String;',
      '[Ljava/lang/Object;',
      '[Leu/kanade/tachiyomi/source/model/Filter;',
      'Leu/kanade/tachiyomi/source/model/Filter;',
      'Leu/kanade/tachiyomi/source/model/FilterList;',
      'Leu/kanade/tachiyomi/source/model/Filter$Header;',
      'Leu/kanade/tachiyomi/source/model/Filter$Separator;',
      'Leu/kanade/tachiyomi/source/model/Filter$Select;',
      'Leu/kanade/tachiyomi/source/model/Filter$Text;',
      'Leu/kanade/tachiyomi/source/model/Filter$CheckBox;',
      'Leu/kanade/tachiyomi/source/model/Filter$TriState;',
      'Leu/kanade/tachiyomi/source/model/Filter$Sort;',
      'Leu/kanade/tachiyomi/source/model/Filter$Sort$Selection;',
      'Leu/kanade/tachiyomi/source/model/Filter$Group;',
      'Ltest/RegionSelect;',
      'Ljava/util/ArrayList;',
      'Ljava/util/List;',
      'Ljava/lang/StringBuilder;',
      'Lokhttp3/Request;',
      'Lokhttp3/Request$Builder;',
      'Lokhttp3/Response;',
      'Leu/kanade/tachiyomi/source/model/MangasPage;',
    ],
    extraProtos: [
      ['L', 'Leu/kanade/tachiyomi/source/model/FilterList;', []],
      ['VL', 'V', ['Ljava/lang/String;']],
      ['VLL', 'V', ['Ljava/lang/String;', 'Ljava/lang/String;']],
      ['VLZ', 'V', ['Ljava/lang/String;', 'Z']],
      ['VLI', 'V', ['Ljava/lang/String;', 'I']],
      ['VLLI', 'V', ['Ljava/lang/String;', '[Ljava/lang/Object;', 'I']],
      ['VIZ', 'V', ['I', 'Z']],
      ['VLLL', 'V', ['Ljava/lang/String;', '[Ljava/lang/String;', 'Leu/kanade/tachiyomi/source/model/Filter$Sort$Selection;']],
      ['VLL', 'V', ['Ljava/lang/String;', 'Ljava/util/List;']],
      ['VL', 'V', ['[Leu/kanade/tachiyomi/source/model/Filter;']],
      ['ZL', 'Z', ['Ljava/lang/Object;']],
      ['LILL', 'Lokhttp3/Request;', ['I', 'Ljava/lang/String;', 'Leu/kanade/tachiyomi/source/model/FilterList;']],
      ['LI', 'Leu/kanade/tachiyomi/source/model/Filter;', ['I']],
      ['L', 'Ljava/lang/Object;', []],
      ['LI', 'Ljava/lang/Object;', ['I']],
      ['I', 'I', []],
      ['LL', 'Ljava/lang/StringBuilder;', ['Ljava/lang/String;']],
      ['LL', 'Ljava/lang/StringBuilder;', ['Ljava/lang/Object;']],
      ['LZ', 'Ljava/lang/StringBuilder;', ['Z']],
      ['LI', 'Ljava/lang/StringBuilder;', ['I']],
      ['LL', 'Lokhttp3/Request$Builder;', ['Ljava/lang/String;']],
      ['L', 'Lokhttp3/Request;', []],
      ['LL', 'Leu/kanade/tachiyomi/source/model/MangasPage;', ['Lokhttp3/Response;']],
      ['VLZ', 'V', ['Ljava/util/List;', 'Z']],
    ],
    extraMethods: [
      ['Ltest/RegionSelect;', 'V', ['Ljava/lang/String;', '[Ljava/lang/Object;', 'I'], '<init>'],
      ['Leu/kanade/tachiyomi/source/model/Filter$Select;', 'V', ['Ljava/lang/String;', '[Ljava/lang/Object;', 'I'], '<init>'],
      ['Leu/kanade/tachiyomi/source/model/Filter$Header;', 'V', ['Ljava/lang/String;'], '<init>'],
      ['Leu/kanade/tachiyomi/source/model/Filter$Separator;', 'V', [], '<init>'],
      ['Leu/kanade/tachiyomi/source/model/Filter$Text;', 'V', ['Ljava/lang/String;', 'Ljava/lang/String;'], '<init>'],
      ['Leu/kanade/tachiyomi/source/model/Filter$CheckBox;', 'V', ['Ljava/lang/String;', 'Z'], '<init>'],
      ['Leu/kanade/tachiyomi/source/model/Filter$TriState;', 'V', ['Ljava/lang/String;', 'I'], '<init>'],
      ['Leu/kanade/tachiyomi/source/model/Filter$TriState;', 'Z', [], 'isExcluded'],
      ['Leu/kanade/tachiyomi/source/model/Filter$Sort$Selection;', 'V', ['I', 'Z'], '<init>'],
      ['Leu/kanade/tachiyomi/source/model/Filter$Sort$Selection;', 'I', [], 'getIndex'],
      ['Leu/kanade/tachiyomi/source/model/Filter$Sort$Selection;', 'Z', [], 'getAscending'],
      ['Leu/kanade/tachiyomi/source/model/Filter$Sort;', 'V', ['Ljava/lang/String;', '[Ljava/lang/String;', 'Leu/kanade/tachiyomi/source/model/Filter$Sort$Selection;'], '<init>'],
      ['Leu/kanade/tachiyomi/source/model/Filter$Group;', 'V', ['Ljava/lang/String;', 'Ljava/util/List;'], '<init>'],
      ['Leu/kanade/tachiyomi/source/model/FilterList;', 'V', ['[Leu/kanade/tachiyomi/source/model/Filter;'], '<init>'],
      ['Leu/kanade/tachiyomi/source/model/FilterList;', 'Leu/kanade/tachiyomi/source/model/Filter;', ['I'], 'get'],
      ['Leu/kanade/tachiyomi/source/model/Filter;', 'Ljava/lang/Object;', [], 'getState'],
      ['Ljava/util/ArrayList;', 'V', [], '<init>'],
      ['Ljava/util/ArrayList;', 'Z', ['Ljava/lang/Object;'], 'add'],
      ['Ljava/util/List;', 'Ljava/lang/Object;', ['I'], 'get'],
      ['Ljava/lang/StringBuilder;', 'V', ['Ljava/lang/String;'], '<init>'],
      ['Ljava/lang/StringBuilder;', 'Ljava/lang/StringBuilder;', ['Ljava/lang/String;'], 'append'],
      ['Ljava/lang/StringBuilder;', 'Ljava/lang/StringBuilder;', ['Ljava/lang/Object;'], 'append'],
      ['Ljava/lang/StringBuilder;', 'Ljava/lang/StringBuilder;', ['Z'], 'append'],
      ['Ljava/lang/StringBuilder;', 'Ljava/lang/StringBuilder;', ['I'], 'append'],
      ['Ljava/lang/StringBuilder;', 'Ljava/lang/String;', [], 'toString'],
      ['Lokhttp3/Request$Builder;', 'V', [], '<init>'],
      ['Lokhttp3/Request$Builder;', 'Lokhttp3/Request$Builder;', ['Ljava/lang/String;'], 'url'],
      ['Lokhttp3/Request$Builder;', 'Lokhttp3/Request;', [], 'build'],
      ['Leu/kanade/tachiyomi/source/model/MangasPage;', 'V', ['Ljava/util/List;', 'Z'], '<init>'],
      ['Ltest/ProbeSource;', 'Leu/kanade/tachiyomi/source/model/FilterList;', [], 'getFilterList'],
      ['Ltest/ProbeSource;', 'Lokhttp3/Request;', ['I', 'Ljava/lang/String;', 'Leu/kanade/tachiyomi/source/model/FilterList;'], 'searchMangaRequest'],
      ['Ltest/ProbeSource;', 'Leu/kanade/tachiyomi/source/model/MangasPage;', ['Lokhttp3/Response;'], 'searchMangaParse'],
    ],
    extraClasses: [
      {
        desc: 'Ltest/RegionSelect;',
        superDesc: 'Leu/kanade/tachiyomi/source/model/Filter$Select;',
        methods: ({ mIdx }) => [
          {
            idx: mIdx('Ltest/RegionSelect;', '<init>'),
            direct: true,
            access: 0x10001,
            code: {
              regs: 4,
              ins: 4,
              outs: 4,
              insns: [
                0x4070, mIdx('Leu/kanade/tachiyomi/source/model/Filter$Select;', '<init>'), 0x3210,
                0x000e,
              ],
            },
          },
        ],
      },
    ],
    probeExtraMethods: ({ sIdx, tIdx, mIdx }) => [
      {
        idx: mIdx('Ltest/ProbeSource;', 'getFilterList'),
        direct: false,
        access: 0x1,
        code: {
          regs: 8,
          ins: 1,
          outs: 4,
          insns: [
            // v0 = new Filter[8]
            0x8112, // const/4 v1, 8 -> Wait: 0x8 is -8 in 4-bit signed! Use const/16 v1, 8
            0x0113, 0x0008,
            0x1023, tIdx('[Leu/kanade/tachiyomi/source/model/Filter;'),

            // [0] Header("Section")
            0x0222, tIdx('Leu/kanade/tachiyomi/source/model/Filter$Header;'),
            0x031a, sIdx('Section'),
            0x2070, mIdx('Leu/kanade/tachiyomi/source/model/Filter$Header;', '<init>'), 0x0032,
            0x0112,
            0x024d, 0x0100, // aput-object v2, v0, v1(0)

            // [1] Separator()
            0x0222, tIdx('Leu/kanade/tachiyomi/source/model/Filter$Separator;'),
            0x1070, mIdx('Leu/kanade/tachiyomi/source/model/Filter$Separator;', '<init>'), 0x0002,
            0x1112,
            0x024d, 0x0100,

            // [2] RegionSelect("Region", ["All", "JP"], 0)
            0x2412,
            0x4323, tIdx('[Ljava/lang/String;'),
            0x051a, sIdx('All'),
            0x0612,
            0x054d, 0x0603,
            0x051a, sIdx('JP'),
            0x1612,
            0x054d, 0x0603,
            0x0222, tIdx('Ltest/RegionSelect;'),
            0x041a, sIdx('Region'),
            0x0512,
            0x4070, mIdx('Ltest/RegionSelect;', '<init>'), 0x5342,
            0x2112,
            0x024d, 0x0100,

            // [3] Text("Author", "init")
            0x0222, tIdx('Leu/kanade/tachiyomi/source/model/Filter$Text;'),
            0x031a, sIdx('Author'),
            0x041a, sIdx('init'),
            0x3070, mIdx('Leu/kanade/tachiyomi/source/model/Filter$Text;', '<init>'), 0x0432,
            0x3112,
            0x024d, 0x0100,

            // [4] CheckBox("Completed", false)
            0x0222, tIdx('Leu/kanade/tachiyomi/source/model/Filter$CheckBox;'),
            0x031a, sIdx('Completed'),
            0x0412,
            0x3070, mIdx('Leu/kanade/tachiyomi/source/model/Filter$CheckBox;', '<init>'), 0x0432,
            0x4112,
            0x024d, 0x0100,

            // [5] TriState("Action", 0)
            0x0222, tIdx('Leu/kanade/tachiyomi/source/model/Filter$TriState;'),
            0x031a, sIdx('Action'),
            0x0412,
            0x3070, mIdx('Leu/kanade/tachiyomi/source/model/Filter$TriState;', '<init>'), 0x0432,
            0x5112,
            0x024d, 0x0100,

            // [6] Sort("Sort", ["Popular", "Latest"], Selection(0, false))
            0x2412,
            0x4323, tIdx('[Ljava/lang/String;'),
            0x051a, sIdx('Popular'),
            0x0612,
            0x054d, 0x0603,
            0x051a, sIdx('Latest'),
            0x1612,
            0x054d, 0x0603,
            0x0522, tIdx('Leu/kanade/tachiyomi/source/model/Filter$Sort$Selection;'),
            0x0612,
            0x0412,
            0x3070, mIdx('Leu/kanade/tachiyomi/source/model/Filter$Sort$Selection;', '<init>'), 0x0465,
            0x0222, tIdx('Leu/kanade/tachiyomi/source/model/Filter$Sort;'),
            0x041a, sIdx('Sort'),
            0x4070, mIdx('Leu/kanade/tachiyomi/source/model/Filter$Sort;', '<init>'), 0x5342,
            0x6112,
            0x024d, 0x0100,

            // [7] Group("Tags", [CheckBox("TagA", false)])
            0x0322, tIdx('Ljava/util/ArrayList;'),
            0x1070, mIdx('Ljava/util/ArrayList;', '<init>'), 0x0003,
            0x0422, tIdx('Leu/kanade/tachiyomi/source/model/Filter$CheckBox;'),
            0x051a, sIdx('TagA'),
            0x0612,
            0x3070, mIdx('Leu/kanade/tachiyomi/source/model/Filter$CheckBox;', '<init>'), 0x0654,
            0x206e, mIdx('Ljava/util/ArrayList;', 'add'), 0x0043,
            0x0222, tIdx('Leu/kanade/tachiyomi/source/model/Filter$Group;'),
            0x041a, sIdx('Tags'),
            0x3070, mIdx('Leu/kanade/tachiyomi/source/model/Filter$Group;', '<init>'), 0x0342,
            0x7112,
            0x024d, 0x0100,

            // return new FilterList(v0)
            0x0122, tIdx('Leu/kanade/tachiyomi/source/model/FilterList;'),
            0x2070, mIdx('Leu/kanade/tachiyomi/source/model/FilterList;', '<init>'), 0x0001,
            0x0111,
          ],
        },
      },
      // searchMangaRequest(page, query, filters): inspects real subclass `instance-of Ltest/RegionSelect;`
      // and all filter states, encoding them into the outgoing URL query!
      {
        idx: mIdx('Ltest/ProbeSource;', 'searchMangaRequest'),
        direct: false,
        access: 0x1,
        code: {
          regs: 10,
          ins: 4, // v6=this, v7=page, v8=query, v9=filters
          outs: 2,
          insns: [
            // v0 = new StringBuilder("https://www.example.com/search?")
            0x0022, tIdx('Ljava/lang/StringBuilder;'),
            0x011a, sIdx('https://www.example.com/search?'),
            0x2070, mIdx('Ljava/lang/StringBuilder;', '<init>'), 0x0010,

            // filters.get(2): check instance-of Ltest/RegionSelect; and append state
            0x011a, sIdx('sel='),
            0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', 'Ljava/lang/StringBuilder;', ['Ljava/lang/String;']), 0x0010,
            0x2112,
            0x206e, mIdx('Leu/kanade/tachiyomi/source/model/FilterList;', 'get'), 0x0019,
            0x020c,
            0x2320, tIdx('Ltest/RegionSelect;'), // instance-of v3, v2, Ltest/RegionSelect;
            0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', 'Ljava/lang/StringBuilder;', ['Z']), 0x0030,
            0x106e, mIdx('Leu/kanade/tachiyomi/source/model/Filter;', 'getState'), 0x0002,
            0x030c,
            0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', 'Ljava/lang/StringBuilder;', ['Ljava/lang/Object;']), 0x0030,

            // filters.get(3): Text
            0x011a, sIdx('&txt='),
            0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', 'Ljava/lang/StringBuilder;', ['Ljava/lang/String;']), 0x0010,
            0x3112,
            0x206e, mIdx('Leu/kanade/tachiyomi/source/model/FilterList;', 'get'), 0x0019,
            0x020c,
            0x106e, mIdx('Leu/kanade/tachiyomi/source/model/Filter;', 'getState'), 0x0002,
            0x030c,
            0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', 'Ljava/lang/StringBuilder;', ['Ljava/lang/Object;']), 0x0030,

            // filters.get(4): CheckBox
            0x011a, sIdx('&chk='),
            0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', 'Ljava/lang/StringBuilder;', ['Ljava/lang/String;']), 0x0010,
            0x4112,
            0x206e, mIdx('Leu/kanade/tachiyomi/source/model/FilterList;', 'get'), 0x0019,
            0x020c,
            0x106e, mIdx('Leu/kanade/tachiyomi/source/model/Filter;', 'getState'), 0x0002,
            0x030c,
            0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', 'Ljava/lang/StringBuilder;', ['Ljava/lang/Object;']), 0x0030,

            // filters.get(5): TriState.isExcluded()
            0x011a, sIdx('&tri='),
            0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', 'Ljava/lang/StringBuilder;', ['Ljava/lang/String;']), 0x0010,
            0x5112,
            0x206e, mIdx('Leu/kanade/tachiyomi/source/model/FilterList;', 'get'), 0x0019,
            0x020c,
            0x106e, mIdx('Leu/kanade/tachiyomi/source/model/Filter$TriState;', 'isExcluded'), 0x0002,
            0x030a,
            0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', 'Ljava/lang/StringBuilder;', ['Z']), 0x0030,

            // filters.get(6): Sort -> Selection.getIndex() + getAscending()
            0x011a, sIdx('&sort='),
            0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', 'Ljava/lang/StringBuilder;', ['Ljava/lang/String;']), 0x0010,
            0x6112,
            0x206e, mIdx('Leu/kanade/tachiyomi/source/model/FilterList;', 'get'), 0x0019,
            0x020c,
            0x106e, mIdx('Leu/kanade/tachiyomi/source/model/Filter;', 'getState'), 0x0002,
            0x020c,
            0x106e, mIdx('Leu/kanade/tachiyomi/source/model/Filter$Sort$Selection;', 'getIndex'), 0x0002,
            0x030a,
            0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', 'Ljava/lang/StringBuilder;', ['I']), 0x0030,
            0x106e, mIdx('Leu/kanade/tachiyomi/source/model/Filter$Sort$Selection;', 'getAscending'), 0x0002,
            0x030a,
            0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', 'Ljava/lang/StringBuilder;', ['Z']), 0x0030,

            // filters.get(7): Group -> state.get(0).getState()
            0x011a, sIdx('&grp='),
            0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', 'Ljava/lang/StringBuilder;', ['Ljava/lang/String;']), 0x0010,
            0x7112,
            0x206e, mIdx('Leu/kanade/tachiyomi/source/model/FilterList;', 'get'), 0x0019,
            0x020c,
            0x106e, mIdx('Leu/kanade/tachiyomi/source/model/Filter;', 'getState'), 0x0002,
            0x020c,
            0x0112,
            0x2072, mIdx('Ljava/util/List;', 'get'), 0x0012,
            0x020c,
            0x106e, mIdx('Leu/kanade/tachiyomi/source/model/Filter;', 'getState'), 0x0002,
            0x030c,
            0x206e, mIdx('Ljava/lang/StringBuilder;', 'append', 'Ljava/lang/StringBuilder;', ['Ljava/lang/Object;']), 0x0030,

            // build Request(url)
            0x106e, mIdx('Ljava/lang/StringBuilder;', 'toString'), 0x0000,
            0x010c,
            0x0222, tIdx('Lokhttp3/Request$Builder;'),
            0x1070, mIdx('Lokhttp3/Request$Builder;', '<init>'), 0x0002,
            0x206e, mIdx('Lokhttp3/Request$Builder;', 'url'), 0x0012,
            0x106e, mIdx('Lokhttp3/Request$Builder;', 'build'), 0x0002,
            0x020c,
            0x0211,
          ],
        },
      },
      {
        idx: mIdx('Ltest/ProbeSource;', 'searchMangaParse'),
        direct: false,
        access: 0x1,
        code: {
          regs: 5,
          ins: 2,
          outs: 3,
          insns: [
            0x0022, tIdx('Ljava/util/ArrayList;'),
            0x1070, mIdx('Ljava/util/ArrayList;', '<init>'), 0x0000,
            0x0122, tIdx('Leu/kanade/tachiyomi/source/model/MangasPage;'),
            0x0212,
            0x3070, mIdx('Leu/kanade/tachiyomi/source/model/MangasPage;', '<init>'), 0x0201,
            0x0111,
          ],
        },
      },
    ],
  });

  const urls = [];
  const vm = await createDexvm({
    wasmBytes: fs.readFileSync(WASM),
    http: (reqJson) => {
      const req = JSON.parse(reqJson);
      urls.push(req.url);
      return JSON.stringify({ status: 200, headers: [], bodyBase64: '', finalUrl: req.url });
    },
  });
  const opened = vm.call('open', { apkBase64: dex.toString('base64') });
  const [src] = vm.call('sources', { handle: opened.handle });

  // Verify FilterDef output for all 8 kinds + nested Group
  const defs = vm.call('filters', { handle: opened.handle, sourceId: src.id });
  assert.equal(defs.length, 8);
  assert.deepEqual(defs[0], { kind: 'header', name: 'Section', state: null, options: [] });
  assert.deepEqual(defs[1], { kind: 'separator', name: '', state: null, options: [] });
  assert.deepEqual(defs[2], { kind: 'select', name: 'Region', state: 0, options: ['All', 'JP'] });
  assert.deepEqual(defs[3], { kind: 'text', name: 'Author', state: 'init', options: [] });
  assert.deepEqual(defs[4], { kind: 'checkbox', name: 'Completed', state: false, options: [] });
  assert.deepEqual(defs[5], { kind: 'tristate', name: 'Action', state: 0, options: [] });
  assert.deepEqual(defs[6], {
    kind: 'sort',
    name: 'Sort',
    state: { index: 0, ascending: false },
    options: ['Popular', 'Latest'],
  });
  assert.deepEqual(defs[7], {
    kind: 'group',
    name: 'Tags',
    state: null,
    options: [],
    children: [{ kind: 'checkbox', name: 'TagA', state: false, options: [] }],
  });

  // Apply sparse filter states onto real subclass instances and run search
  vm.call('search', {
    handle: opened.handle,
    sourceId: src.id,
    page: 1,
    query: '',
    filters: [
      { name: 'Region', state: 1 },
      { name: 'Author', state: 'Oda' },
      { name: 'Completed', state: true },
      { name: 'Action', state: 2 },
      { name: 'Sort', state: { index: 1, ascending: true } },
      { name: 'Tags', children: [{ name: 'TagA', state: true }] },
    ],
  });
  assert.equal(urls.length, 1);
  assert.equal(
    urls[0],
    'https://www.example.com/search?sel=true1&txt=Oda&chk=true&tri=true&sort=1true&grp=true'
  );
});
