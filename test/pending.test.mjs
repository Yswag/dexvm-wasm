// Offline tests for detached coroutine pending queue, `runPending` op,
// true delay() suspension via COROUTINE_SUSPENDED, Job.isActive/isCompleted/cancel/join,
// and exception isolation.
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

const MANHUAGUI_DETAIL_HTML = `<!doctype html><html><body>
<div class="book-title"><h1>Test Comic</h1></div>
<div class="hcover"><img src="//cf.hamreus.com/cover.jpg" /></div>
<div id="intro-all"><p>Summary text</p></div>
<ul class="detail-list"><li><span><a href="/list/act/">Action</a></span><span><a href="/author/1/">AuthorA</a></span></li><li class="status"><span><em>连载中</em></span></li></ul>
<div class="chapter"><h4><span>单话</span></h4><div id="chapter-list-1" class="chapter-list"><ul><li><a href="/comic/123/456.html" title="Ch 1" class="status0"><span>Ch 1<i>10p</i></span></a></li></ul></div></div>
</body></html>`;

// ---------------------------------------------------------------------------
// Minimal DEX 035 builder for a 2-class DEX:
//   - Ltest/JobSource; extends HttpSource (has instance field `flag: String`)
//   - Ltest/JobBlock; implements kotlin.jvm.functions.Function2 (mutates `flag` or throws)
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

/**
 * Builds a synthetic DEX with `test.JobSource` + `test.JobBlock`:
 * - `mode = 'throw'`: `getFilterList()` launches a detached `GlobalScope.launch` block that throws `RuntimeException("boom")`.
 * - `mode = 'join'`:  `getFilterList()` launches a detached `GlobalScope.launch` block that sets `flag = "joined"`, then calls `job.join(null)`, and `getName()` returns `flag`.
 * - `mode = 'cancel'`: `getFilterList()` launches a detached `GlobalScope.launch` block that sets `flag = "ran"`, checks `isActive`, calls `job.cancel()`, checks `isCompleted`, and `getName()` returns `flag`.
 */
function buildJobDex(mode) {
  const strings = [
    '<init>',
    'I',
    'INSTANCE',
    'J',
    'L',
    'LL',
    'LLL',
    'LLLLLLIL',
    'Leu/kanade/tachiyomi/source/model/FilterList;',
    'Leu/kanade/tachiyomi/source/online/HttpSource;',
    'Ljava/lang/Object;',
    'Ljava/lang/RuntimeException;',
    'Ljava/lang/String;',
    'Lkotlin/coroutines/Continuation;',
    'Lkotlin/coroutines/CoroutineContext;',
    'Lkotlin/jvm/functions/Function2;',
    'Lkotlinx/coroutines/BuildersKt;',
    'Lkotlinx/coroutines/CoroutineScope;',
    'Lkotlinx/coroutines/CoroutineStart;',
    'Lkotlinx/coroutines/GlobalScope;',
    'Lkotlinx/coroutines/Job;',
    'Ltest/JobBlock;',
    'Ltest/JobSource;',
    'V',
    'VL',
    'Z',
    'boom',
    'cancel',
    'en',
    'flag',
    'getBaseUrl',
    'getFilterList',
    'getId',
    'getLang',
    'getName',
    'getSupportsLatest',
    'https://job.test',
    'init',
    'invoke',
    'isActive',
    'isCompleted',
    'join',
    'joined',
    'launch$default',
    'owner',
    'ran',
  ].sort((a, b) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8')));
  const sIdx = (s) => {
    const i = strings.indexOf(s);
    if (i < 0) throw new Error(`missing string: ${s}`);
    return i;
  };

  const types = [
    'I',
    'J',
    'Leu/kanade/tachiyomi/source/model/FilterList;',
    'Leu/kanade/tachiyomi/source/online/HttpSource;',
    'Ljava/lang/Object;',
    'Ljava/lang/RuntimeException;',
    'Ljava/lang/String;',
    'Lkotlin/coroutines/Continuation;',
    'Lkotlin/coroutines/CoroutineContext;',
    'Lkotlin/jvm/functions/Function2;',
    'Lkotlinx/coroutines/BuildersKt;',
    'Lkotlinx/coroutines/CoroutineScope;',
    'Lkotlinx/coroutines/CoroutineStart;',
    'Lkotlinx/coroutines/GlobalScope;',
    'Lkotlinx/coroutines/Job;',
    'Ltest/JobBlock;',
    'Ltest/JobSource;',
    'V',
    'Z',
  ].sort((a, b) => sIdx(a) - sIdx(b));
  const tIdx = (t) => {
    const i = types.indexOf(t);
    if (i < 0) throw new Error(`missing type: ${t}`);
    return i;
  };

  const protos = [
    ['J', 'J', []],
    ['L', 'Leu/kanade/tachiyomi/source/model/FilterList;', []],
    ['LL', 'Ljava/lang/Object;', ['Lkotlin/coroutines/Continuation;']],
    ['LLL', 'Ljava/lang/Object;', ['Ljava/lang/Object;', 'Ljava/lang/Object;']],
    ['L', 'Ljava/lang/String;', []],
    [
      'LLLLLLIL',
      'Lkotlinx/coroutines/Job;',
      [
        'Lkotlinx/coroutines/CoroutineScope;',
        'Lkotlin/coroutines/CoroutineContext;',
        'Lkotlinx/coroutines/CoroutineStart;',
        'Lkotlin/jvm/functions/Function2;',
        'I',
        'Ljava/lang/Object;',
      ],
    ],
    ['V', 'V', []],
    ['VL', 'V', ['Ljava/lang/String;']],
    ['VL', 'V', ['Ltest/JobSource;']],
    ['Z', 'Z', []],
  ].sort((a, b) => {
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

  const fields = [
    ['Lkotlinx/coroutines/GlobalScope;', 'Lkotlinx/coroutines/GlobalScope;', 'INSTANCE'],
    ['Ltest/JobBlock;', 'Ltest/JobSource;', 'owner'],
    ['Ltest/JobSource;', 'Ljava/lang/String;', 'flag'],
  ].sort((a, b) => {
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

  const methods = [
    ['Leu/kanade/tachiyomi/source/online/HttpSource;', 'V', [], '<init>'],
    ['Ljava/lang/Object;', 'V', [], '<init>'],
    ['Ljava/lang/RuntimeException;', 'V', ['Ljava/lang/String;'], '<init>'],
    [
      'Lkotlinx/coroutines/BuildersKt;',
      'Lkotlinx/coroutines/Job;',
      [
        'Lkotlinx/coroutines/CoroutineScope;',
        'Lkotlin/coroutines/CoroutineContext;',
        'Lkotlinx/coroutines/CoroutineStart;',
        'Lkotlin/jvm/functions/Function2;',
        'I',
        'Ljava/lang/Object;',
      ],
      'launch$default',
    ],
    ['Lkotlinx/coroutines/Job;', 'V', [], 'cancel'],
    ['Lkotlinx/coroutines/Job;', 'Z', [], 'isActive'],
    ['Lkotlinx/coroutines/Job;', 'Z', [], 'isCompleted'],
    ['Lkotlinx/coroutines/Job;', 'Ljava/lang/Object;', ['Lkotlin/coroutines/Continuation;'], 'join'],
    ['Ltest/JobBlock;', 'V', ['Ltest/JobSource;'], '<init>'],
    ['Ltest/JobBlock;', 'Ljava/lang/Object;', ['Ljava/lang/Object;', 'Ljava/lang/Object;'], 'invoke'],
    ['Ltest/JobSource;', 'V', [], '<init>'],
    ['Ltest/JobSource;', 'Ljava/lang/String;', [], 'getBaseUrl'],
    ['Ltest/JobSource;', 'Leu/kanade/tachiyomi/source/model/FilterList;', [], 'getFilterList'],
    ['Ltest/JobSource;', 'J', [], 'getId'],
    ['Ltest/JobSource;', 'Ljava/lang/String;', [], 'getLang'],
    ['Ltest/JobSource;', 'Ljava/lang/String;', [], 'getName'],
    ['Ltest/JobSource;', 'Z', [], 'getSupportsLatest'],
  ].sort((a, b) => {
    const c = tIdx(a[0]) - tIdx(b[0]);
    if (c !== 0) return c;
    const n = sIdx(a[3]) - sIdx(b[3]);
    if (n !== 0) return n;
    return pIdx(a[1], a[2]) - pIdx(b[1], b[2]);
  });
  const mIdx = (cls, name) => {
    const i = methods.findIndex(([c, , , n]) => c === cls && n === name);
    if (i < 0) throw new Error(`missing method: ${cls}.${name}`);
    return i;
  };

  // --- JobBlock methods ---
  // <init>(JobSource): super(); this.owner = p1; return-void
  const blockInit = {
    regs: 2,
    ins: 2,
    outs: 1,
    insns: [
      0x1070, mIdx('Ljava/lang/Object;', '<init>'), 0x0000,
      0x015b, fIdx('Ltest/JobBlock;', 'owner'),
      0x000e,
    ],
  };

  // invoke(Object, Object): either throws RuntimeException("boom") or sets owner.flag = "joined"/"ran"
  const blockInvoke =
    mode === 'throw'
      ? {
          regs: 5,
          ins: 3,
          outs: 2,
          insns: [
            0x0022, tIdx('Ljava/lang/RuntimeException;'),
            0x011a, sIdx('boom'),
            0x2070, mIdx('Ljava/lang/RuntimeException;', '<init>'), 0x0010,
            0x0027, // throw v0
          ],
        }
      : {
          regs: 5,
          ins: 3,
          outs: 0,
          // v0 = p0.owner (p0 is v2); v1 = "joined"/"ran"; v0.flag = v1; return null
          insns: [
            0x2054, fIdx('Ltest/JobBlock;', 'owner'),
            0x011a, sIdx(mode === 'join' ? 'joined' : 'ran'),
            0x015b, fIdx('Ltest/JobSource;', 'flag'),
            0x0012,
            0x0011,
          ],
        };

  // --- JobSource methods ---
  // <init>(): super(); this.flag = "init"; return-void
  const srcInit = {
    regs: 2,
    ins: 1,
    outs: 1,
    // p0 is v1
    insns: [
      0x1070, mIdx('Leu/kanade/tachiyomi/source/online/HttpSource;', '<init>'), 0x0001,
      0x001a, sIdx('init'),
      0x105b, fIdx('Ltest/JobSource;', 'flag'),
      0x000e,
    ],
  };

  // getFilterList(): launches GlobalScope.launch$default(GlobalScope.INSTANCE, null, null, new JobBlock(this), 3, null)
  // regs: v0..v5 = args for invoke-static/range, v6 = p0 (this)
  const launchPrefix = [
    0x0062, fIdx('Lkotlinx/coroutines/GlobalScope;', 'INSTANCE'), // v0 = GlobalScope.INSTANCE
    0x0112, // v1 = null
    0x0212, // v2 = null
    0x0322, tIdx('Ltest/JobBlock;'), // v3 = new JobBlock
    0x2070, mIdx('Ltest/JobBlock;', '<init>'), 0x0063, // JobBlock.<init>(v3, v6=this)
    0x3412, // v4 = 3
    0x0512, // v5 = null
    0x0677, mIdx('Lkotlinx/coroutines/BuildersKt;', 'launch$default'), 0x0000, // invoke-static/range {v0..v5}
    0x000c, // move-result-object v0 (Job)
  ];

  let filterInsns;
  if (mode === 'join') {
    // job.join(null); return null
    filterInsns = [
      ...launchPrefix,
      0x0112, // v1 = null (Continuation)
      0x2072, mIdx('Lkotlinx/coroutines/Job;', 'join'), 0x0010, // invoke-interface {v0, v1}
      0x0012,
      0x0011,
    ];
  } else if (mode === 'cancel') {
    // if (!job.isActive()) throw; job.cancel(); if (!job.isCompleted()) throw; return null
    filterInsns = [
      ...launchPrefix,
      0x1072, mIdx('Lkotlinx/coroutines/Job;', 'isActive'), 0x0000,
      0x010a, // move-result v1
      0x0138, 0x000b, // if-eqz v1, +11 (throw)
      0x1072, mIdx('Lkotlinx/coroutines/Job;', 'cancel'), 0x0000,
      0x1072, mIdx('Lkotlinx/coroutines/Job;', 'isCompleted'), 0x0000,
      0x010a, // move-result v1
      0x0138, 0x0003, // if-eqz v1, +3 (throw)
      0x0012,
      0x0011,
      // throw block:
      0x0022, tIdx('Ljava/lang/RuntimeException;'),
      0x011a, sIdx('boom'),
      0x2070, mIdx('Ljava/lang/RuntimeException;', '<init>'), 0x0010,
      0x0027,
    ];
  } else {
    filterInsns = [...launchPrefix, 0x0012, 0x0011];
  }

  const srcMethods = [
    { idx: mIdx('Ltest/JobSource;', '<init>'), direct: true, access: 0x10001, code: srcInit },
    {
      idx: mIdx('Ltest/JobSource;', 'getBaseUrl'),
      direct: false,
      access: 0x1,
      code: { regs: 2, ins: 1, outs: 0, insns: [0x001a, sIdx('https://job.test'), 0x0011] },
    },
    {
      idx: mIdx('Ltest/JobSource;', 'getFilterList'),
      direct: false,
      access: 0x1,
      code: { regs: 7, ins: 1, outs: 6, insns: filterInsns },
    },
    {
      idx: mIdx('Ltest/JobSource;', 'getId'),
      direct: false,
      access: 0x1,
      code: { regs: 3, ins: 1, outs: 0, insns: [0x0016, 99, 0x0010] },
    },
    {
      idx: mIdx('Ltest/JobSource;', 'getLang'),
      direct: false,
      access: 0x1,
      code: { regs: 2, ins: 1, outs: 0, insns: [0x001a, sIdx('en'), 0x0011] },
    },
    {
      idx: mIdx('Ltest/JobSource;', 'getName'),
      direct: false,
      access: 0x1,
      // return this.flag (p0 is v1)
      code: { regs: 2, ins: 1, outs: 0, insns: [0x1054, fIdx('Ltest/JobSource;', 'flag'), 0x0011] },
    },
    {
      idx: mIdx('Ltest/JobSource;', 'getSupportsLatest'),
      direct: false,
      access: 0x1,
      code: { regs: 2, ins: 1, outs: 0, insns: [0x0012, 0x000f] },
    },
  ];

  const blockMethods = [
    { idx: mIdx('Ltest/JobBlock;', '<init>'), direct: true, access: 0x10001, code: blockInit },
    { idx: mIdx('Ltest/JobBlock;', 'invoke'), direct: false, access: 0x1, code: blockInvoke },
  ];

  // Layout
  const headerSize = 0x70;
  const stringIdsOff = headerSize;
  const typeIdsOff = stringIdsOff + strings.length * 4;
  const protoIdsOff = typeIdsOff + types.length * 4;
  const fieldIdsOff = protoIdsOff + protos.length * 12;
  const methodIdsOff = fieldIdsOff + fields.length * 8;
  const classDefsOff = methodIdsOff + methods.length * 8;
  const dataOff = classDefsOff + 2 * 32; // 2 class_defs

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

  // Interface type_list for JobBlock: [Lkotlin/jvm/functions/Function2;]
  align4();
  const blockIfacesBuf = Buffer.alloc(6);
  blockIfacesBuf.writeUInt32LE(1, 0);
  blockIfacesBuf.writeUInt16LE(tIdx('Lkotlin/jvm/functions/Function2;'), 4);
  const blockIfacesOff = pushBytes(blockIfacesBuf);

  const stringDataOffs = strings.map((s) => {
    const utf8 = Buffer.from(s, 'utf8');
    return pushBytes([...uleb128(s.length), ...utf8, 0]);
  });

  const emitCode = (c) => {
    align4();
    const buf = Buffer.alloc(16 + c.insns.length * 2);
    buf.writeUInt16LE(c.regs, 0);
    buf.writeUInt16LE(c.ins, 2);
    buf.writeUInt16LE(c.outs, 4);
    buf.writeUInt16LE(0, 6);
    buf.writeUInt32LE(0, 8);
    buf.writeUInt32LE(c.insns.length, 12);
    c.insns.forEach((w, idx) => buf.writeUInt16LE(w, 16 + idx * 2));
    return pushBytes(buf);
  };

  const encodeMethodList = (list) => {
    const out = [];
    let prev = 0;
    for (const m of list) {
      out.push(...uleb128(m.idx - prev), ...uleb128(m.access), ...uleb128(m.codeOff));
      prev = m.idx;
    }
    return out;
  };

  const emitClassData = (instanceFields, methodList) => {
    const withOffs = methodList.map((m) => ({ ...m, codeOff: emitCode(m.code) }));
    const direct = withOffs.filter((m) => m.direct).sort((a, b) => a.idx - b.idx);
    const virtual = withOffs.filter((m) => !m.direct).sort((a, b) => a.idx - b.idx);
    const fBytes = [];
    let prevF = 0;
    for (const f of instanceFields) {
      fBytes.push(...uleb128(f.idx - prevF), ...uleb128(f.access));
      prevF = f.idx;
    }
    return pushBytes([
      ...uleb128(0),
      ...uleb128(instanceFields.length),
      ...uleb128(direct.length),
      ...uleb128(virtual.length),
      ...fBytes,
      ...encodeMethodList(direct),
      ...encodeMethodList(virtual),
    ]);
  };

  const blockClassDataOff = emitClassData(
    [{ idx: fIdx('Ltest/JobBlock;', 'owner'), access: 0x1 }],
    blockMethods
  );
  const srcClassDataOff = emitClassData(
    [{ idx: fIdx('Ltest/JobSource;', 'flag'), access: 0x1 }],
    srcMethods
  );
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
  dex.writeUInt32LE(fieldIdsOff, 84);
  dex.writeUInt32LE(methods.length, 88);
  dex.writeUInt32LE(methodIdsOff, 92);
  dex.writeUInt32LE(2, 96);
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
  methods.forEach(([cls, ret, params, name], i) => {
    const base = methodIdsOff + i * 8;
    dex.writeUInt16LE(tIdx(cls), base);
    dex.writeUInt16LE(pIdx(ret, params), base + 2);
    dex.writeUInt32LE(sIdx(name), base + 4);
  });

  // ClassDef 0: Ltest/JobBlock;
  dex.writeUInt32LE(tIdx('Ltest/JobBlock;'), classDefsOff);
  dex.writeUInt32LE(0x1, classDefsOff + 4);
  dex.writeUInt32LE(tIdx('Ljava/lang/Object;'), classDefsOff + 8);
  dex.writeUInt32LE(blockIfacesOff, classDefsOff + 12);
  dex.writeUInt32LE(0xffffffff, classDefsOff + 16);
  dex.writeUInt32LE(0, classDefsOff + 20);
  dex.writeUInt32LE(blockClassDataOff, classDefsOff + 24);
  dex.writeUInt32LE(0, classDefsOff + 28);

  // ClassDef 1: Ltest/JobSource;
  const cd1 = classDefsOff + 32;
  dex.writeUInt32LE(tIdx('Ltest/JobSource;'), cd1);
  dex.writeUInt32LE(0x1, cd1 + 4);
  dex.writeUInt32LE(tIdx('Leu/kanade/tachiyomi/source/online/HttpSource;'), cd1 + 8);
  dex.writeUInt32LE(0, cd1 + 12);
  dex.writeUInt32LE(0xffffffff, cd1 + 16);
  dex.writeUInt32LE(0, cd1 + 20);
  dex.writeUInt32LE(srcClassDataOff, cd1 + 24);
  dex.writeUInt32LE(0, cd1 + 28);

  let pos = dataOff;
  for (const c of chunks) {
    c.copy(dex, pos);
    pos += c.length;
  }
  crypto.createHash('sha1').update(dex.subarray(32)).digest().copy(dex, 12);
  dex.writeUInt32LE(adler32(dex.subarray(12)), 8);
  return dex;
}

// ---------------------------------------------------------------------------
// Tests (a) - (d)
// ---------------------------------------------------------------------------
test('(a) manhuagui v1.6.2 mangaUpdate sends 1 request; runPending truly suspends on delay(1000) then sends both ajax requests', async () => {
  const sleepBuf = new Int32Array(new SharedArrayBuffer(4));
  const sleepCalls = [];
  const requests = [];
  const vm = await createDexvm({
    wasmBytes,
    sleep: (ms) => {
      sleepCalls.push(ms);
      if (ms > 0) Atomics.wait(sleepBuf, 0, 0, ms);
    },
    http: (reqJson) => {
      const req = JSON.parse(reqJson);
      requests.push(req.url);
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

  // Main op: only 1 HTTP request (main page), no sleep, no ajax yet.
  const upd = vm.call('mangaUpdate', { handle, sourceId, manga: { url: '/comic/123/' } });
  assert.equal(upd.manga.title, 'Test Comic');
  assert.equal(upd.chapters.length, 1);
  assert.deepEqual(requests, ['https://www.manhuagui.com/comic/123/']);
  assert.equal(sleepCalls.length, 0);

  // First runPending: starts GlobalScope.launch job, hits delay(1000L), suspends cleanly with nextDueMs ≈ 1000.
  const r1 = vm.call('runPending', { handle });
  assert.equal(r1.ran, 1);
  assert.equal(r1.remaining, 1);
  assert.ok(
    typeof r1.nextDueMs === 'number' && r1.nextDueMs >= 800 && r1.nextDueMs <= 1100,
    `expected nextDueMs ≈ 1000, got ${JSON.stringify(r1)}`
  );
  assert.equal(requests.length, 1, 'ajax must not fire before delay(1000) expires');
  assert.equal(sleepCalls.length, 0, 'true suspension should not block worker with sleep()');

  // Wait for nextDueMs, then drain remaining pending jobs.
  Atomics.wait(sleepBuf, 0, 0, r1.nextDueMs + 20);
  const r2 = vm.call('runPending', { handle });
  assert.equal(r2.ran, 1);
  assert.equal(r2.remaining, 0);
  assert.equal(r2.nextDueMs, undefined);

  assert.equal(requests.length, 3, `expected main + 2 ajax, got ${JSON.stringify(requests)}`);
  assert.ok(requests.some((u) => u.includes('user_check_login')), `missing user_check_login: ${requests}`);
  assert.ok(requests.some((u) => u.includes('vote.ashx')), `missing vote.ashx: ${requests}`);

  vm.call('close', { handle });
});

test('(b) throwing pending job is caught, logged via host.log, and does not break subsequent ops', async () => {
  const logs = [];
  const vm = await createDexvm({
    wasmBytes,
    log: (lvl, msg) => logs.push({ lvl, msg }),
    http: () => JSON.stringify({ error: 'unused' }),
  });

  const dex = buildJobDex('throw');
  const { handle } = vm.call('open', { apkBase64: dex.toString('base64'), logLevel: 3 });
  const sources = vm.call('sources', { handle });
  assert.equal(sources[0].name, 'init');

  // getFilterList launches the throwing job (queued, not yet run).
  try {
    vm.call('filters', { handle, sourceId: sources[0].id });
  } catch {}

  const r = vm.call('runPending', { handle });
  assert.equal(r.ran, 1);
  assert.equal(r.remaining, 0);
  assert.equal(vm.trapped, false);
  assert.ok(
    logs.some((l) => l.msg.includes('boom') || l.msg.includes('RuntimeException')),
    `expected error logged via host.log, got ${JSON.stringify(logs)}`
  );

  // Subsequent op succeeds normally.
  const sourcesAfter = vm.call('sources', { handle });
  assert.equal(sourcesAfter[0].name, 'init');
  vm.call('close', { handle });
});

test('(c) job.join() inside main op runs the launched job inline immediately', async () => {
  const vm = await createDexvm({
    wasmBytes,
    http: () => JSON.stringify({ error: 'unused' }),
  });

  const dex = buildJobDex('join');
  const { handle } = vm.call('open', { apkBase64: dex.toString('base64') });
  const sources = vm.call('sources', { handle });
  assert.equal(sources[0].name, 'init');

  try {
    vm.call('filters', { handle, sourceId: sources[0].id });
  } catch {}

  // Job already ran inline during join(), mutating `flag` to "joined".
  const sourcesAfter = vm.call('sources', { handle });
  assert.equal(sourcesAfter[0].name, 'joined');

  // Queue is empty since join() already executed it.
  const r = vm.call('runPending', { handle });
  assert.equal(r.ran, 0);
  assert.equal(r.remaining, 0);
  vm.call('close', { handle });
});

test('(d) job.cancel() removes an unstarted job so runPending never executes it', async () => {
  const vm = await createDexvm({
    wasmBytes,
    http: () => JSON.stringify({ error: 'unused' }),
  });

  const dex = buildJobDex('cancel');
  const { handle } = vm.call('open', { apkBase64: dex.toString('base64') });
  const sources = vm.call('sources', { handle });
  assert.equal(sources[0].name, 'init');

  // getFilterList asserts job.isActive() === true, calls job.cancel(), asserts job.isCompleted() === true.
  try {
    vm.call('filters', { handle, sourceId: sources[0].id });
  } catch (e) {
    assert.ok(!e.message.includes('boom'), `Job state check failed: ${e.message}`);
  }

  const r = vm.call('runPending', { handle });
  assert.equal(r.ran, 0);
  assert.equal(r.remaining, 0);

  // Cancelled job must NOT have mutated `flag`.
  const sourcesAfter = vm.call('sources', { handle });
  assert.equal(sourcesAfter[0].name, 'init');
  vm.call('close', { handle });
});
