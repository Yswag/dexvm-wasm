// Unit tests for host-provided synchronous `sleep(ms)` in dexvm-host.js,
// WASI poll_oneoff semantics (earliest deadline, ABSTIME, clock consistency,
// truncation caps), Thread.sleep(3000), and manhuagui v1.6.2 rate limiting.
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
// Minimal valid DEX 035 builder: `class test.SleepSource extends HttpSource`
// whose `popularMangaRequest(int)` calls `Thread.sleep(sleepMs)`.
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

function buildSleepSourceDex(sleepMs) {
  // Strings MUST be sorted in UTF-8 / MUTF-8 code-unit order.
  const strings = [
    '<init>',
    'J',
    'L',
    'Leu/kanade/tachiyomi/source/model/FilterList;',
    'Leu/kanade/tachiyomi/source/online/HttpSource;',
    'Ljava/lang/String;',
    'Ljava/lang/Thread;',
    'Ltest/SleepSource;',
    'SleepSource',
    'V',
    'VJ',
    'Z',
    'en',
    'getBaseUrl',
    'getFilterList',
    'getId',
    'getLang',
    'getName',
    'getSupportsLatest',
    'https://sleep.test',
    'sleep',
  ];
  const sIdx = (s) => {
    const i = strings.indexOf(s);
    if (i < 0) throw new Error(`missing string: ${s}`);
    return i;
  };

  // Type IDs (sorted by string index)
  const types = [
    'J',
    'Leu/kanade/tachiyomi/source/model/FilterList;',
    'Leu/kanade/tachiyomi/source/online/HttpSource;',
    'Ljava/lang/String;',
    'Ljava/lang/Thread;',
    'Ltest/SleepSource;',
    'V',
    'Z',
  ];
  const tIdx = (t) => {
    const i = types.indexOf(t);
    if (i < 0) throw new Error(`missing type: ${t}`);
    return i;
  };

  // Proto IDs: [shorty, retType, params[]] sorted by (retType, params)
  const protos = [
    ['J', 'J', []],                                             // 0: ()J
    ['L', 'Leu/kanade/tachiyomi/source/model/FilterList;', []], // 1: ()FilterList
    ['L', 'Ljava/lang/String;', []],                            // 2: ()String
    ['V', 'V', []],                                             // 3: ()V
    ['VJ', 'V', ['J']],                                         // 4: (J)V
    ['Z', 'Z', []],                                             // 5: ()Z
  ];

  // Method IDs: [classType, protoIdx, nameStr] sorted by (classIdx, nameIdx, protoIdx)
  const methods = [
    ['Leu/kanade/tachiyomi/source/online/HttpSource;', 3, '<init>'], // 0
    ['Ljava/lang/Thread;', 4, 'sleep'],                              // 1
    ['Ltest/SleepSource;', 3, '<init>'],                             // 2
    ['Ltest/SleepSource;', 2, 'getBaseUrl'],                         // 3
    ['Ltest/SleepSource;', 1, 'getFilterList'],                      // 4
    ['Ltest/SleepSource;', 0, 'getId'],                              // 5
    ['Ltest/SleepSource;', 2, 'getLang'],                            // 6
    ['Ltest/SleepSource;', 2, 'getName'],                            // 7
    ['Ltest/SleepSource;', 5, 'getSupportsLatest'],                  // 8
  ];

  // Code items for each Ltest/SleepSource; method (register counts + 16-bit insns)
  const lo = sleepMs & 0xffff;
  const hi = (sleepMs >>> 16) & 0xffff;
  const codeItems = [
    // 2: <init>()V -> invoke-direct {p0}, HttpSource.<init>(); return-void
    { regs: 1, ins: 1, outs: 1, insns: [0x1070, 0x0000, 0x0000, 0x000e] },
    // 3: getBaseUrl() -> const-string v0, "https://sleep.test"; return-object v0
    { regs: 2, ins: 1, outs: 0, insns: [0x001a, sIdx('https://sleep.test'), 0x0011] },
    // 4: getFilterList() ->
    //   const-wide/32 v0, sleepMs  (opcode 0x17, reg 0, 32-bit imm lo/hi)
    //   invoke-static {v0, v1}, Thread.sleep(J)V  (opcode 0x71, count=2, method=1, regs=0x0010)
    //   const/4 v0, 0; return-object v0
    { regs: 3, ins: 1, outs: 2, insns: [0x0017, lo, hi, 0x2071, 0x0001, 0x0010, 0x0012, 0x0011] },
    // 5: getId() -> const-wide/16 v0, 42; return-wide v0
    { regs: 3, ins: 1, outs: 0, insns: [0x0016, 42, 0x0010] },
    // 6: getLang() -> const-string v0, "en"; return-object v0
    { regs: 2, ins: 1, outs: 0, insns: [0x001a, sIdx('en'), 0x0011] },
    // 7: getName() -> const-string v0, "SleepSource"; return-object v0
    { regs: 2, ins: 1, outs: 0, insns: [0x001a, sIdx('SleepSource'), 0x0011] },
    // 8: getSupportsLatest() -> const/4 v0, 0; return v0
    { regs: 2, ins: 1, outs: 0, insns: [0x0012, 0x000f] },
  ];

  // Layout offsets
  const headerSize = 0x70;
  const stringIdsOff = headerSize;
  const typeIdsOff = stringIdsOff + strings.length * 4;
  const protoIdsOff = typeIdsOff + types.length * 4;
  const methodIdsOff = protoIdsOff + protos.length * 12;
  const classDefsOff = methodIdsOff + methods.length * 8;
  const dataOff = classDefsOff + 32; // 1 class_def

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

  // Type lists for protos that have params
  const protoParamOffs = protos.map(([, , params]) => {
    if (!params.length) return 0;
    align4();
    const buf = Buffer.alloc(4 + params.length * 2);
    buf.writeUInt32LE(params.length, 0);
    params.forEach((p, idx) => buf.writeUInt16LE(tIdx(p), 4 + idx * 2));
    return pushBytes(buf);
  });

  // String data items
  const stringDataOffs = strings.map((s) => {
    const utf8 = Buffer.from(s, 'utf8');
    return pushBytes([...uleb128(s.length), ...utf8, 0]);
  });

  // Code items (4-byte aligned)
  const codeOffs = codeItems.map((c) => {
    align4();
    const buf = Buffer.alloc(16 + c.insns.length * 2);
    buf.writeUInt16LE(c.regs, 0);
    buf.writeUInt16LE(c.ins, 2);
    buf.writeUInt16LE(c.outs, 4);
    buf.writeUInt16LE(0, 6); // tries_size
    buf.writeUInt32LE(0, 8); // debug_info_off
    buf.writeUInt32LE(c.insns.length, 12);
    c.insns.forEach((w, idx) => buf.writeUInt16LE(w, 16 + idx * 2));
    return pushBytes(buf);
  });

  // class_data_item: 0 static fields, 0 instance fields, 1 direct method (<init>), 6 virtual methods
  const classData = [
    ...uleb128(0),
    ...uleb128(0),
    ...uleb128(1),
    ...uleb128(6),
    // direct method: method 2 (<init>), ACC_PUBLIC|ACC_CONSTRUCTOR (0x10001)
    ...uleb128(2),
    ...uleb128(0x10001),
    ...uleb128(codeOffs[0]),
    // virtual methods: 3..8 (deltas: 3, 1, 1, 1, 1, 1)
    ...uleb128(3), ...uleb128(0x1), ...uleb128(codeOffs[1]),
    ...uleb128(1), ...uleb128(0x1), ...uleb128(codeOffs[2]),
    ...uleb128(1), ...uleb128(0x1), ...uleb128(codeOffs[3]),
    ...uleb128(1), ...uleb128(0x1), ...uleb128(codeOffs[4]),
    ...uleb128(1), ...uleb128(0x1), ...uleb128(codeOffs[5]),
    ...uleb128(1), ...uleb128(0x1), ...uleb128(codeOffs[6]),
  ];
  const classDataOff = pushBytes(classData);
  align4();

  // Minimal map_list (required by dexvm parser at header offset 0x34)
  const mapOff = cursor;
  const mapBuf = Buffer.alloc(4 + 12);
  mapBuf.writeUInt32LE(1, 0); // 1 entry
  mapBuf.writeUInt16LE(0x1000, 4); // TYPE_MAP_LIST
  mapBuf.writeUInt32LE(1, 8);
  mapBuf.writeUInt32LE(mapOff, 12);
  pushBytes(mapBuf);

  const fileSize = cursor;
  const dex = Buffer.alloc(fileSize);

  // Header
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
  dex.writeUInt32LE(methods.length, 88);
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
  methods.forEach(([cls, proto, name], i) => {
    const base = methodIdsOff + i * 8;
    dex.writeUInt16LE(tIdx(cls), base);
    dex.writeUInt16LE(proto, base + 2);
    dex.writeUInt32LE(sIdx(name), base + 4);
  });
  // class_def_item
  dex.writeUInt32LE(tIdx('Ltest/SleepSource;'), classDefsOff);
  dex.writeUInt32LE(0x1, classDefsOff + 4);
  dex.writeUInt32LE(tIdx('Leu/kanade/tachiyomi/source/online/HttpSource;'), classDefsOff + 8);
  dex.writeUInt32LE(0, classDefsOff + 12);
  dex.writeUInt32LE(0xffffffff, classDefsOff + 16);
  dex.writeUInt32LE(0, classDefsOff + 20);
  dex.writeUInt32LE(classDataOff, classDefsOff + 24);
  dex.writeUInt32LE(0, classDefsOff + 28);

  // Copy data section
  let pos = dataOff;
  for (const c of chunks) {
    c.copy(dex, pos);
    pos += c.length;
  }

  // SHA-1 signature (bytes 12..32) + Adler-32 checksum (bytes 8..12)
  crypto.createHash('sha1').update(dex.subarray(32)).digest().copy(dex, 12);
  dex.writeUInt32LE(adler32(dex.subarray(12)), 8);
  return dex;
}

// ---------------------------------------------------------------------------
// Minimal inline Wasm module exposing wasi_snapshot_preview1.poll_oneoff and
// clock_time_get directly so we can unit-test multi-subscription & ABSTIME.
// ---------------------------------------------------------------------------
function buildWasiProbeWasm() {
  const bytes = [];
  const push = (...a) => bytes.push(...a);
  const str = (s) => {
    const b = [...Buffer.from(s, 'utf8')];
    return [b.length, ...b];
  };
  const sec = (id, body) => [id, ...uleb128(body.length), ...body];

  // Header
  push(0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00);

  // Type section:
  // 0: (i32, i32, i32, i32) -> i32   (poll_oneoff)
  // 1: (i32, i64, i32) -> i32        (clock_time_get)
  push(...sec(1, [
    2,
    0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f,
    0x60, 3, 0x7f, 0x7e, 0x7f, 1, 0x7f,
  ]));

  // Import section: poll_oneoff (func 0), clock_time_get (func 1)
  push(...sec(2, [
    2,
    ...str('wasi_snapshot_preview1'), ...str('poll_oneoff'), 0x00, 0,
    ...str('wasi_snapshot_preview1'), ...str('clock_time_get'), 0x00, 1,
  ]));

  // Memory section: 1 page
  push(...sec(5, [1, 0x00, 1]));

  // Export section: memory, poll_oneoff, clock_time_get
  push(...sec(7, [
    3,
    ...str('memory'), 0x02, 0,
    ...str('poll_oneoff'), 0x00, 0,
    ...str('clock_time_get'), 0x00, 1,
  ]));

  return new Uint8Array(bytes);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
test('Thread.sleep(3000) with host sleep calls sleep(≈3000) once without truncation', async () => {
  const calls = [];
  const warnings = [];
  const vm = await createDexvm({
    wasmBytes,
    http: () => JSON.stringify({ error: 'unused' }),
    log: (lvl, msg) => { if (lvl === 3) warnings.push(msg); },
    sleep: (ms) => calls.push(ms),
  });
  const dex = buildSleepSourceDex(3000);
  const { handle } = vm.call('open', { apkBase64: dex.toString('base64') });
  const sources = vm.call('sources', { handle });
  assert.equal(sources[0].name, 'SleepSource');
  try {
    vm.call('filters', { handle, sourceId: sources[0].id });
  } catch {
    // getFilterList returns null after sleeping; we only verify the sleep call.
  }
  vm.call('close', { handle });
  assert.equal(calls.length, 1, `expected 1 sleep call, got ${JSON.stringify(calls)}`);
  assert.ok(calls[0] >= 2990 && calls[0] <= 3010, `expected sleep(≈3000), got ${calls[0]}`);
  assert.equal(warnings.length, 0, `unexpected warnings: ${JSON.stringify(warnings)}`);
});

test('Thread.sleep(3000) without host sleep truncates at 2000ms and warns', async () => {
  const warnings = [];
  const vm = await createDexvm({
    wasmBytes,
    http: () => JSON.stringify({ error: 'unused' }),
    log: (lvl, msg) => { if (lvl === 3) warnings.push(msg); },
  });
  const dex = buildSleepSourceDex(3000);
  const { handle } = vm.call('open', { apkBase64: dex.toString('base64') });
  const sources = vm.call('sources', { handle });
  const t0 = performance.now();
  try {
    vm.call('filters', { handle, sourceId: sources[0].id });
  } catch {}
  const elapsed = performance.now() - t0;
  vm.call('close', { handle });
  assert.ok(
    warnings.some((w) => w.includes('truncated to 2000ms')),
    `expected 2000ms truncation warning, got ${JSON.stringify(warnings)}`
  );
  assert.ok(elapsed < 2800, `expected busy-wait capped near 2000ms, got ${elapsed}ms`);
});

test('Thread.sleep(70000) with host sleep truncates at 60000ms safety cap and warns', async () => {
  const calls = [];
  const warnings = [];
  const vm = await createDexvm({
    wasmBytes,
    http: () => JSON.stringify({ error: 'unused' }),
    log: (lvl, msg) => { if (lvl === 3) warnings.push(msg); },
    sleep: (ms) => calls.push(ms),
  });
  const dex = buildSleepSourceDex(70_000);
  const { handle } = vm.call('open', { apkBase64: dex.toString('base64') });
  const sources = vm.call('sources', { handle });
  try {
    vm.call('filters', { handle, sourceId: sources[0].id });
  } catch {}
  vm.call('close', { handle });
  assert.equal(calls.length, 1);
  assert.equal(calls[0], 60_000);
  assert.ok(
    warnings.some((w) => w.includes('truncated to 60000ms')),
    `expected 60000ms truncation warning, got ${JSON.stringify(warnings)}`
  );
});

test('poll_oneoff handles multiple clock subscriptions (earliest wins), ABSTIME, and clock consistency', async () => {
  const calls = [];
  const vm = await createDexvm({
    wasmBytes: buildWasiProbeWasm(),
    sleep: (ms) => calls.push(ms),
  });
  const { memory, poll_oneoff, clock_time_get } = vm.exports;
  const dv = () => new DataView(memory.buffer);

  const readClock = () => {
    assert.equal(clock_time_get(1, 0n, 0), 0);
    return dv().getBigUint64(0, true);
  };

  const nowNs = readClock();
  const inPtr = 64;
  const outPtr = 512;
  const neventsPtr = 1024;

  // Sub 0: relative 5000ms (userdata = 101)
  dv().setBigUint64(inPtr + 0, 101n, true);
  dv().setUint8(inPtr + 8, 0); // EVENTTYPE_CLOCK
  dv().setUint32(inPtr + 16, 1, true); // MONOTONIC
  dv().setBigUint64(inPtr + 24, 5_000_000_000n, true);
  dv().setUint16(inPtr + 40, 0, true); // relative

  // Sub 1: ABSTIME now + 1500ms (userdata = 202) — earliest!
  const targetAbsNs = nowNs + 1_500_000_000n;
  dv().setBigUint64(inPtr + 48 + 0, 202n, true);
  dv().setUint8(inPtr + 48 + 8, 0); // EVENTTYPE_CLOCK
  dv().setUint32(inPtr + 48 + 16, 1, true); // MONOTONIC
  dv().setBigUint64(inPtr + 48 + 24, targetAbsNs, true);
  dv().setUint16(inPtr + 48 + 40, 1, true); // SUBSCRIPTION_CLOCK_ABSTIME

  assert.equal(poll_oneoff(inPtr, outPtr, 2, neventsPtr), 0);
  const nevents = dv().getUint32(neventsPtr, true);
  assert.equal(nevents, 1, 'only the earliest clock subscription should fire');
  assert.equal(dv().getBigUint64(outPtr, true), 202n, 'earliest userdata=202 should fire');
  assert.equal(dv().getUint16(outPtr + 8, true), 0);
  assert.equal(calls.length, 1);
  assert.ok(calls[0] >= 1490 && calls[0] <= 1510, `expected sleep(≈1500), got ${calls[0]}`);

  // Clock read immediately after wakeup must NOT be earlier than targetAbsNs.
  const afterNs = readClock();
  assert.ok(afterNs >= targetAbsNs, `clock_time_get (${afterNs}) < targetAbsNs (${targetAbsNs})`);
});

test('manhuagui v1.6.2 15 consecutive popular calls respect 10 req / 10s rate limit with host sleep', async () => {
  const sleepBuf = new Int32Array(new SharedArrayBuffer(4));
  const sleepCalls = [];
  const timestamps = [];
  const t0 = performance.now();

  const vm = await createDexvm({
    wasmBytes,
    sleep: (ms) => {
      sleepCalls.push(ms);
      if (ms > 0) Atomics.wait(sleepBuf, 0, 0, ms);
    },
    http: (reqJson) => {
      const req = JSON.parse(reqJson);
      timestamps.push(Math.round(performance.now() - t0));
      return JSON.stringify({
        status: 200,
        headers: [['content-type', 'text/html; charset=utf-8']],
        bodyBase64: Buffer.from(
          '<html><body><ul id="contList"><li><a class="bcover" href="/comic/1/" title="T"><img src="https://i.hamreus.com/1.jpg"></a></li></ul></body></html>'
        ).toString('base64'),
        finalUrl: req.url,
      });
    },
  });

  const apkBase64 = fs
    .readFileSync(path.join(FIXTURES, 'tachiyomi-zh.manhuagui-v1.6.2.apk'))
    .toString('base64');
  const { handle } = vm.call('open', { apkBase64 });
  const sources = vm.call('sources', { handle });
  for (let i = 1; i <= 15; i++) {
    const page = vm.call('popular', { handle, sourceId: sources[0].id, page: i });
    assert.equal(page.mangas.length, 1);
  }
  const totalMs = Math.round(performance.now() - t0);
  vm.call('close', { handle });

  assert.equal(timestamps.length, 15);
  assert.ok(sleepCalls.length >= 1, `expected host sleep to be called, got ${JSON.stringify(sleepCalls)}`);
  assert.ok(totalMs >= 9900, `expected >= 10s total for 15 calls (10/10s), got ${totalMs}ms`);
  // Requests 11..15 (index 10..14) must not fire earlier than 10s after requests 1..5 (index 0..4).
  for (let i = 10; i < 15; i++) {
    const gap = timestamps[i] - timestamps[i - 10];
    assert.ok(
      gap >= 9900,
      `request #${i + 1} fired too early: t[${i}]=${timestamps[i]}ms vs t[${i - 10}]=${timestamps[i - 10]}ms (gap=${gap}ms)`
    );
  }
});
