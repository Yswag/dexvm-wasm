// Offline unit & reproduction tests for v0.2.8 (zh.bilibilimanga P-256 EC/ECDH + AES/CTR + AES-128-GCM + okio + HttpUrl):
// 1. RFC 5903 Section 8.1 (Group 19 / P-256) ECDH test vector via AlgorithmParameters,
//    ECGenParameterSpec, ECParameterSpec, BigInteger(1, bytes), KeyFactory("EC"),
//    ECPrivateKeySpec, ECPublicKeySpec, and KeyAgreement("ECDH").
// 2. KeyPairGenerator("EC") + ECGenParameterSpec("secp256r1") generates a valid on-curve
//    P-256 key pair (y^2 == x^3 + ax + b mod p) via EllipticCurve / ECFieldFp / ECPoint.
// 3. AES/CTR/NoPadding (256-bit key, 16-byte IV) matches Node crypto aes-256-ctr and round-trips.
// 4. AES/GCM/NoPadding (128-bit key, 12-byte IV, GCMParameterSpec) matches Node crypto aes-128-gcm.
// 5. Mac("HmacSHA256") getMacLength() + update([B) + update(B) + doFinal() matches Node crypto.
// 6. okio.Buffer.copyTo(Buffer, offset, count), BufferedSource.readAll(Sink), and
//    HttpUrl.queryParameter() percent-decoding (+ -> space, %2F/%2B/%3D).
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createDexvm } from '../dexvm-host.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const WASM = process.env.DEXVM_WASM || path.join(ROOT, 'dist', 'dexvm_bridge.wasm');
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
  customGetName,
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
  const autoStrings = [
    ...extraStrings,
    ...extraTypes,
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
  out.writeUInt32LE(1, 96);
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

  out.writeUInt32LE(tIdx('Ltest/ProbeSource;'), classDefsOff);
  out.writeUInt32LE(0x1, classDefsOff + 4);
  out.writeUInt32LE(tIdx('Leu/kanade/tachiyomi/source/online/HttpSource;'), classDefsOff + 8);
  out.writeUInt32LE(0, classDefsOff + 12);
  out.writeUInt32LE(0xffffffff, classDefsOff + 16);
  out.writeUInt32LE(0, classDefsOff + 20);
  out.writeUInt32LE(classDataOff, classDefsOff + 24);
  out.writeUInt32LE(0, classDefsOff + 28);

  let pos = dataOff;
  for (const c of chunks) {
    c.copy(out, pos);
    pos += c.length;
  }
  crypto.createHash('sha1').update(out.subarray(32)).digest().copy(out, 12);
  out.writeUInt32LE(adler32(out.subarray(12)), 8);
  return out;
}

function zipSingle(name, data) {
  const nameBuf = Buffer.from(name, 'utf8');
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i];
    for (let j = 0; j < 8; j++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  crc = (crc ^ 0xffffffff) >>> 0;

  const lfh = Buffer.alloc(30);
  lfh.writeUInt32LE(0x04034b50, 0);
  lfh.writeUInt16LE(20, 4);
  lfh.writeUInt32LE(crc, 14);
  lfh.writeUInt32LE(data.length, 18);
  lfh.writeUInt32LE(data.length, 22);
  lfh.writeUInt16LE(nameBuf.length, 26);

  const cdOff = lfh.length + nameBuf.length + data.length;
  const cdh = Buffer.alloc(46);
  cdh.writeUInt32LE(0x02014b50, 0);
  cdh.writeUInt16LE(20, 4);
  cdh.writeUInt16LE(20, 6);
  cdh.writeUInt32LE(crc, 16);
  cdh.writeUInt32LE(data.length, 20);
  cdh.writeUInt32LE(data.length, 24);
  cdh.writeUInt16LE(nameBuf.length, 28);

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(cdh.length + nameBuf.length, 12);
  eocd.writeUInt32LE(cdOff, 16);

  return Buffer.concat([lfh, nameBuf, data, cdh, nameBuf, eocd]);
}

async function runProbe(dexSpec) {
  const dex = buildTestDex(dexSpec);
  const apkBase64 = zipSingle('classes.dex', dex).toString('base64');
  const vm = await createDexvm({ wasmBytes, http: () => { throw new Error('unexpected http'); } });
  const { handle } = vm.call('open', { apkBase64 });
  const [src] = vm.call('sources', { handle });
  vm.call('close', { handle });
  return src.name;
}

// Helper to emit invoke-* (35c) with up to 5 registers
function inv(op, methodIdx, regs) {
  const n = regs.length;
  const r = [0, 0, 0, 0, 0];
  for (let i = 0; i < n; i++) r[i] = regs[i];
  const w0 = (n << 12) | (r[4] << 8) | op;
  const w2 = (r[3] << 12) | (r[2] << 8) | (r[1] << 4) | r[0];
  return [w0, methodIdx, w2];
}
const invStatic = (m, regs) => inv(0x71, m, regs);
const invVirtual = (m, regs) => inv(0x6e, m, regs);
const invDirect = (m, regs) => inv(0x70, m, regs);
const invInterface = (m, regs) => inv(0x72, m, regs);
const moveResObj = (reg) => (reg << 8) | 0x0c;
const moveRes = (reg) => (reg << 8) | 0x0a;
const constStr = (reg, sIdx) => [(reg << 8) | 0x1a, sIdx];
const constClass = (reg, tIdx) => [(reg << 8) | 0x1c, tIdx];
const newInst = (reg, tIdx) => [(reg << 8) | 0x22, tIdx];
const const4 = (reg, val) => ((val & 0xf) << 12) | (reg << 8) | 0x12;
const const16 = (reg, val) => [(reg << 8) | 0x13, val & 0xffff];
const constWide16 = (reg, val) => [(reg << 8) | 0x16, val & 0xffff];
const retObj = (reg) => (reg << 8) | 0x11;

test('1. RFC 5903 Group 19 (P-256) ECDH test vector via AlgorithmParameters + KeyFactory + KeyAgreement', async () => {
  // RFC 5903 Section 8.1:
  const dI = Buffer.from('C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433', 'hex').toString('base64');
  const gXr = Buffer.from('D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63', 'hex').toString('base64');
  const gYr = Buffer.from('56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB', 'hex').toString('base64');
  const expectedZ = Buffer.from('D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE', 'hex').toString('base64');

  const result = await runProbe({
    extraStrings: [
      'EC', 'ECDH', 'secp256r1', dI, gXr, gYr,
      'I', '[B', 'LL', 'LI', 'LIL', 'VL', 'VLL', 'VLI', 'VLZ', 'LLZ', 'L',
      'Landroid/util/Base64;', 'decode', 'encodeToString',
      'Ljava/math/BigInteger;',
      'Ljava/security/AlgorithmParameters;', 'getInstance', 'init', 'getParameterSpec',
      'Ljava/security/KeyFactory;', 'generatePublic', 'generatePrivate',
      'Ljava/security/PublicKey;', 'Ljava/security/PrivateKey;', 'Ljava/security/Key;',
      'Ljava/security/spec/AlgorithmParameterSpec;', 'Ljava/security/spec/ECGenParameterSpec;',
      'Ljava/security/spec/ECParameterSpec;', 'Ljava/security/spec/ECPoint;',
      'Ljava/security/spec/ECPublicKeySpec;', 'Ljava/security/spec/ECPrivateKeySpec;',
      'Ljava/security/spec/KeySpec;', 'Ljava/lang/Class;',
      'Ljavax/crypto/KeyAgreement;', 'doPhase', 'generateSecret',
    ],
    extraTypes: [
      'I', '[B', 'Landroid/util/Base64;', 'Ljava/math/BigInteger;',
      'Ljava/security/AlgorithmParameters;', 'Ljava/security/KeyFactory;',
      'Ljava/security/PublicKey;', 'Ljava/security/PrivateKey;', 'Ljava/security/Key;',
      'Ljava/security/spec/AlgorithmParameterSpec;', 'Ljava/security/spec/ECGenParameterSpec;',
      'Ljava/security/spec/ECParameterSpec;', 'Ljava/security/spec/ECPoint;',
      'Ljava/security/spec/ECPublicKeySpec;', 'Ljava/security/spec/ECPrivateKeySpec;',
      'Ljava/security/spec/KeySpec;', 'Ljava/lang/Class;', 'Ljavax/crypto/KeyAgreement;',
    ],
    extraProtos: [
      ['LLI', '[B', ['Ljava/lang/String;', 'I']],
      ['LLI', 'Ljava/lang/String;', ['[B', 'I']],
      ['VIL', 'V', ['I', '[B']],
      ['LL', 'Ljava/security/AlgorithmParameters;', ['Ljava/lang/String;']],
      ['VL', 'V', ['Ljava/lang/String;']],
      ['VL', 'V', ['Ljava/security/spec/AlgorithmParameterSpec;']],
      ['LL', 'Ljava/security/spec/AlgorithmParameterSpec;', ['Ljava/lang/Class;']],
      ['LL', 'Ljava/security/KeyFactory;', ['Ljava/lang/String;']],
      ['VLL', 'V', ['Ljava/math/BigInteger;', 'Ljava/math/BigInteger;']],
      ['VLL', 'V', ['Ljava/security/spec/ECPoint;', 'Ljava/security/spec/ECParameterSpec;']],
      ['VLL', 'V', ['Ljava/math/BigInteger;', 'Ljava/security/spec/ECParameterSpec;']],
      ['LL', 'Ljava/security/PublicKey;', ['Ljava/security/spec/KeySpec;']],
      ['LL', 'Ljava/security/PrivateKey;', ['Ljava/security/spec/KeySpec;']],
      ['LL', 'Ljavax/crypto/KeyAgreement;', ['Ljava/lang/String;']],
      ['VL', 'V', ['Ljava/security/Key;']],
      ['LLZ', 'Ljava/security/Key;', ['Ljava/security/Key;', 'Z']],
      ['L', '[B', []],
    ],
    extraMethods: [
      ['Landroid/util/Base64;', '[B', ['Ljava/lang/String;', 'I'], 'decode'],
      ['Landroid/util/Base64;', 'Ljava/lang/String;', ['[B', 'I'], 'encodeToString'],
      ['Ljava/math/BigInteger;', 'V', ['I', '[B'], '<init>'],
      ['Ljava/security/AlgorithmParameters;', 'Ljava/security/AlgorithmParameters;', ['Ljava/lang/String;'], 'getInstance'],
      ['Ljava/security/spec/ECGenParameterSpec;', 'V', ['Ljava/lang/String;'], '<init>'],
      ['Ljava/security/AlgorithmParameters;', 'V', ['Ljava/security/spec/AlgorithmParameterSpec;'], 'init'],
      ['Ljava/security/AlgorithmParameters;', 'Ljava/security/spec/AlgorithmParameterSpec;', ['Ljava/lang/Class;'], 'getParameterSpec'],
      ['Ljava/security/KeyFactory;', 'Ljava/security/KeyFactory;', ['Ljava/lang/String;'], 'getInstance'],
      ['Ljava/security/spec/ECPoint;', 'V', ['Ljava/math/BigInteger;', 'Ljava/math/BigInteger;'], '<init>'],
      ['Ljava/security/spec/ECPublicKeySpec;', 'V', ['Ljava/security/spec/ECPoint;', 'Ljava/security/spec/ECParameterSpec;'], '<init>'],
      ['Ljava/security/spec/ECPrivateKeySpec;', 'V', ['Ljava/math/BigInteger;', 'Ljava/security/spec/ECParameterSpec;'], '<init>'],
      ['Ljava/security/KeyFactory;', 'Ljava/security/PublicKey;', ['Ljava/security/spec/KeySpec;'], 'generatePublic'],
      ['Ljava/security/KeyFactory;', 'Ljava/security/PrivateKey;', ['Ljava/security/spec/KeySpec;'], 'generatePrivate'],
      ['Ljavax/crypto/KeyAgreement;', 'Ljavax/crypto/KeyAgreement;', ['Ljava/lang/String;'], 'getInstance'],
      ['Ljavax/crypto/KeyAgreement;', 'V', ['Ljava/security/Key;'], 'init'],
      ['Ljavax/crypto/KeyAgreement;', 'Ljava/security/Key;', ['Ljava/security/Key;', 'Z'], 'doPhase'],
      ['Ljavax/crypto/KeyAgreement;', '[B', [], 'generateSecret'],
    ],
    customGetName: ({ sIdx, tIdx, mIdx }) => {
      const mDecode = mIdx('Landroid/util/Base64;', 'decode');
      const mEncode = mIdx('Landroid/util/Base64;', 'encodeToString');
      const mBigInit = mIdx('Ljava/math/BigInteger;', '<init>');
      const mApInst = mIdx('Ljava/security/AlgorithmParameters;', 'getInstance');
      const mGenInit = mIdx('Ljava/security/spec/ECGenParameterSpec;', '<init>');
      const mApInit = mIdx('Ljava/security/AlgorithmParameters;', 'init');
      const mApSpec = mIdx('Ljava/security/AlgorithmParameters;', 'getParameterSpec');
      const mKfInst = mIdx('Ljava/security/KeyFactory;', 'getInstance');
      const mPtInit = mIdx('Ljava/security/spec/ECPoint;', '<init>');
      const mPubSpec = mIdx('Ljava/security/spec/ECPublicKeySpec;', '<init>');
      const mPrivSpec = mIdx('Ljava/security/spec/ECPrivateKeySpec;', '<init>');
      const mGenPub = mIdx('Ljava/security/KeyFactory;', 'generatePublic');
      const mGenPriv = mIdx('Ljava/security/KeyFactory;', 'generatePrivate');
      const mKaInst = mIdx('Ljavax/crypto/KeyAgreement;', 'getInstance');
      const mKaInit = mIdx('Ljavax/crypto/KeyAgreement;', 'init');
      const mKaPhase = mIdx('Ljavax/crypto/KeyAgreement;', 'doPhase');
      const mKaSec = mIdx('Ljavax/crypto/KeyAgreement;', 'generateSecret');

      // v0 = 0 (Base64.DEFAULT), v1 = 1 (signum / true), v2 = 2 (Base64.NO_WRAP)
      // v3 = params (ECParameterSpec), v4 = kf, v5 = privKey, v6 = pubKey, v7..v10 = scratch
      const insns = [
        const4(0, 0),
        const4(1, 1),
        const4(2, 2),
        // AlgorithmParameters.getInstance("EC") -> v7
        ...constStr(7, sIdx('EC')),
        ...invStatic(mApInst, [7]),
        moveResObj(7),
        // ECGenParameterSpec("secp256r1") -> v8
        ...newInst(8, tIdx('Ljava/security/spec/ECGenParameterSpec;')),
        ...constStr(9, sIdx('secp256r1')),
        ...invDirect(mGenInit, [8, 9]),
        ...invVirtual(mApInit, [7, 8]),
        ...constClass(8, tIdx('Ljava/security/spec/ECParameterSpec;')),
        ...invVirtual(mApSpec, [7, 8]),
        moveResObj(3), // v3 = ECParameterSpec
        // KeyFactory.getInstance("EC") -> v4
        ...constStr(7, sIdx('EC')),
        ...invStatic(mKfInst, [7]),
        moveResObj(4),
        // privKey: BigInteger(1, decode(dI, 0)) -> v8
        ...constStr(7, sIdx(dI)),
        ...invStatic(mDecode, [7, 0]),
        moveResObj(7),
        ...newInst(8, tIdx('Ljava/math/BigInteger;')),
        ...invDirect(mBigInit, [8, 1, 7]),
        ...newInst(9, tIdx('Ljava/security/spec/ECPrivateKeySpec;')),
        ...invDirect(mPrivSpec, [9, 8, 3]),
        ...invVirtual(mGenPriv, [4, 9]),
        moveResObj(5), // v5 = privKey
        // pubKey: ECPoint(BigInteger(1, decode(gXr)), BigInteger(1, decode(gYr)))
        ...constStr(7, sIdx(gXr)),
        ...invStatic(mDecode, [7, 0]),
        moveResObj(7),
        ...newInst(8, tIdx('Ljava/math/BigInteger;')),
        ...invDirect(mBigInit, [8, 1, 7]), // v8 = x
        ...constStr(7, sIdx(gYr)),
        ...invStatic(mDecode, [7, 0]),
        moveResObj(7),
        ...newInst(9, tIdx('Ljava/math/BigInteger;')),
        ...invDirect(mBigInit, [9, 1, 7]), // v9 = y
        ...newInst(10, tIdx('Ljava/security/spec/ECPoint;')),
        ...invDirect(mPtInit, [10, 8, 9]),
        ...newInst(8, tIdx('Ljava/security/spec/ECPublicKeySpec;')),
        ...invDirect(mPubSpec, [8, 10, 3]),
        ...invVirtual(mGenPub, [4, 8]),
        moveResObj(6), // v6 = pubKey
        // KeyAgreement.getInstance("ECDH")
        ...constStr(7, sIdx('ECDH')),
        ...invStatic(mKaInst, [7]),
        moveResObj(7),
        ...invVirtual(mKaInit, [7, 5]),
        ...invVirtual(mKaPhase, [7, 6, 1]),
        ...invVirtual(mKaSec, [7]),
        moveResObj(8),
        ...invStatic(mEncode, [8, 2]),
        moveResObj(9),
        retObj(9),
      ];
      return { regs: 12, ins: 1, outs: 3, insns };
    },
  });

  assert.equal(result, expectedZ);
});

test('2. KeyPairGenerator("EC") generates on-curve P-256 keypair verified via EllipticCurve/ECFieldFp', async () => {
  const result = await runProbe({
    extraStrings: [
      'EC', 'secp256r1', 'L', 'LL', 'VL', 'ZL',
      'Ljava/lang/Object;', 'Ljava/math/BigInteger;', 'multiply', 'add', 'mod', 'equals',
      'Ljava/security/KeyPairGenerator;', 'getInstance', 'initialize', 'generateKeyPair',
      'Ljava/security/KeyPair;', 'getPublic',
      'Ljava/security/PublicKey;', 'Ljava/security/interfaces/ECPublicKey;', 'getW', 'getParams',
      'Ljava/security/spec/AlgorithmParameterSpec;', 'Ljava/security/spec/ECGenParameterSpec;',
      'Ljava/security/spec/ECParameterSpec;', 'getCurve',
      'Ljava/security/spec/EllipticCurve;', 'getField', 'getA', 'getB',
      'Ljava/security/spec/ECField;', 'Ljava/security/spec/ECFieldFp;', 'getP',
      'Ljava/security/spec/ECPoint;', 'getAffineX', 'getAffineY',
      'Ljava/lang/String;', 'valueOf',
    ],
    extraTypes: [
      'Ljava/lang/Object;', 'Ljava/math/BigInteger;',
      'Ljava/security/KeyPairGenerator;', 'Ljava/security/KeyPair;',
      'Ljava/security/PublicKey;', 'Ljava/security/interfaces/ECPublicKey;',
      'Ljava/security/spec/AlgorithmParameterSpec;', 'Ljava/security/spec/ECGenParameterSpec;',
      'Ljava/security/spec/ECParameterSpec;', 'Ljava/security/spec/EllipticCurve;',
      'Ljava/security/spec/ECField;', 'Ljava/security/spec/ECFieldFp;',
      'Ljava/security/spec/ECPoint;',
    ],
    extraProtos: [
      ['LL', 'Ljava/security/KeyPairGenerator;', ['Ljava/lang/String;']],
      ['VL', 'V', ['Ljava/lang/String;']],
      ['VL', 'V', ['Ljava/security/spec/AlgorithmParameterSpec;']],
      ['L', 'Ljava/security/KeyPair;', []],
      ['L', 'Ljava/security/PublicKey;', []],
      ['L', 'Ljava/security/spec/ECPoint;', []],
      ['L', 'Ljava/security/spec/ECParameterSpec;', []],
      ['L', 'Ljava/security/spec/EllipticCurve;', []],
      ['L', 'Ljava/security/spec/ECField;', []],
      ['L', 'Ljava/math/BigInteger;', []],
      ['LL', 'Ljava/math/BigInteger;', ['Ljava/math/BigInteger;']],
      ['ZL', 'Z', ['Ljava/lang/Object;']],
      ['LZ', 'Ljava/lang/String;', ['Z']],
    ],
    extraMethods: [
      ['Ljava/security/KeyPairGenerator;', 'Ljava/security/KeyPairGenerator;', ['Ljava/lang/String;'], 'getInstance'],
      ['Ljava/security/spec/ECGenParameterSpec;', 'V', ['Ljava/lang/String;'], '<init>'],
      ['Ljava/security/KeyPairGenerator;', 'V', ['Ljava/security/spec/AlgorithmParameterSpec;'], 'initialize'],
      ['Ljava/security/KeyPairGenerator;', 'Ljava/security/KeyPair;', [], 'generateKeyPair'],
      ['Ljava/security/KeyPair;', 'Ljava/security/PublicKey;', [], 'getPublic'],
      ['Ljava/security/interfaces/ECPublicKey;', 'Ljava/security/spec/ECPoint;', [], 'getW'],
      ['Ljava/security/interfaces/ECPublicKey;', 'Ljava/security/spec/ECParameterSpec;', [], 'getParams'],
      ['Ljava/security/spec/ECParameterSpec;', 'Ljava/security/spec/EllipticCurve;', [], 'getCurve'],
      ['Ljava/security/spec/EllipticCurve;', 'Ljava/security/spec/ECField;', [], 'getField'],
      ['Ljava/security/spec/EllipticCurve;', 'Ljava/math/BigInteger;', [], 'getA'],
      ['Ljava/security/spec/EllipticCurve;', 'Ljava/math/BigInteger;', [], 'getB'],
      ['Ljava/security/spec/ECFieldFp;', 'Ljava/math/BigInteger;', [], 'getP'],
      ['Ljava/security/spec/ECPoint;', 'Ljava/math/BigInteger;', [], 'getAffineX'],
      ['Ljava/security/spec/ECPoint;', 'Ljava/math/BigInteger;', [], 'getAffineY'],
      ['Ljava/math/BigInteger;', 'Ljava/math/BigInteger;', ['Ljava/math/BigInteger;'], 'multiply'],
      ['Ljava/math/BigInteger;', 'Ljava/math/BigInteger;', ['Ljava/math/BigInteger;'], 'add'],
      ['Ljava/math/BigInteger;', 'Ljava/math/BigInteger;', ['Ljava/math/BigInteger;'], 'mod'],
      ['Ljava/math/BigInteger;', 'Z', ['Ljava/lang/Object;'], 'equals'],
      ['Ljava/lang/String;', 'Ljava/lang/String;', ['Z'], 'valueOf'],
    ],
    customGetName: ({ sIdx, tIdx, mIdx }) => {
      const insns = [
        ...constStr(0, sIdx('EC')),
        ...invStatic(mIdx('Ljava/security/KeyPairGenerator;', 'getInstance'), [0]),
        moveResObj(0),
        ...newInst(1, tIdx('Ljava/security/spec/ECGenParameterSpec;')),
        ...constStr(2, sIdx('secp256r1')),
        ...invDirect(mIdx('Ljava/security/spec/ECGenParameterSpec;', '<init>'), [1, 2]),
        ...invVirtual(mIdx('Ljava/security/KeyPairGenerator;', 'initialize'), [0, 1]),
        ...invVirtual(mIdx('Ljava/security/KeyPairGenerator;', 'generateKeyPair'), [0]),
        moveResObj(0),
        ...invVirtual(mIdx('Ljava/security/KeyPair;', 'getPublic'), [0]),
        moveResObj(0), // v0 = ECPublicKey
        ...invInterface(mIdx('Ljava/security/interfaces/ECPublicKey;', 'getW'), [0]),
        moveResObj(1), // v1 = ECPoint
        ...invVirtual(mIdx('Ljava/security/spec/ECPoint;', 'getAffineX'), [1]),
        moveResObj(2), // v2 = x
        ...invVirtual(mIdx('Ljava/security/spec/ECPoint;', 'getAffineY'), [1]),
        moveResObj(3), // v3 = y
        ...invInterface(mIdx('Ljava/security/interfaces/ECPublicKey;', 'getParams'), [0]),
        moveResObj(4),
        ...invVirtual(mIdx('Ljava/security/spec/ECParameterSpec;', 'getCurve'), [4]),
        moveResObj(4), // v4 = curve
        ...invVirtual(mIdx('Ljava/security/spec/EllipticCurve;', 'getField'), [4]),
        moveResObj(5),
        ...invVirtual(mIdx('Ljava/security/spec/ECFieldFp;', 'getP'), [5]),
        moveResObj(5), // v5 = p
        ...invVirtual(mIdx('Ljava/security/spec/EllipticCurve;', 'getA'), [4]),
        moveResObj(6), // v6 = a
        ...invVirtual(mIdx('Ljava/security/spec/EllipticCurve;', 'getB'), [4]),
        moveResObj(7), // v7 = b
        // lhs = (y * y).mod(p) -> v8
        ...invVirtual(mIdx('Ljava/math/BigInteger;', 'multiply'), [3, 3]),
        moveResObj(8),
        ...invVirtual(mIdx('Ljava/math/BigInteger;', 'mod'), [8, 5]),
        moveResObj(8),
        // rhs = (x*x*x + a*x + b).mod(p) -> v9
        ...invVirtual(mIdx('Ljava/math/BigInteger;', 'multiply'), [2, 2]),
        moveResObj(9),
        ...invVirtual(mIdx('Ljava/math/BigInteger;', 'multiply'), [9, 2]),
        moveResObj(9),
        ...invVirtual(mIdx('Ljava/math/BigInteger;', 'multiply'), [6, 2]),
        moveResObj(10),
        ...invVirtual(mIdx('Ljava/math/BigInteger;', 'add'), [9, 10]),
        moveResObj(9),
        ...invVirtual(mIdx('Ljava/math/BigInteger;', 'add'), [9, 7]),
        moveResObj(9),
        ...invVirtual(mIdx('Ljava/math/BigInteger;', 'mod'), [9, 5]),
        moveResObj(9),
        // lhs.equals(rhs) -> String.valueOf
        ...invVirtual(mIdx('Ljava/math/BigInteger;', 'equals'), [8, 9]),
        moveRes(0),
        ...invStatic(mIdx('Ljava/lang/String;', 'valueOf'), [0]),
        moveResObj(0),
        retObj(0),
      ];
      return { regs: 12, ins: 1, outs: 2, insns };
    },
  });

  assert.equal(result, 'true');
});

test('3. AES/CTR/NoPadding (256-bit key) matches Node crypto aes-256-ctr', async () => {
  const key = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');
  const iv = Buffer.from('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff', 'hex');
  const pt = Buffer.from('Hello BilibiliManga AES-CTR 256-bit non-block-aligned payload!', 'utf8');
  const expectedCt = crypto.createCipheriv('aes-256-ctr', key, iv).update(pt);

  const result = await runProbe({
    extraStrings: [
      'AES', 'AES/CTR/NoPadding', key.toString('base64'), iv.toString('base64'), pt.toString('base64'),
      'I', '[B', 'LL', 'LLI', 'VLL', 'VL', 'VILL',
      'Landroid/util/Base64;', 'decode', 'encodeToString',
      'Ljavax/crypto/Cipher;', 'getInstance', 'init', 'doFinal',
      'Ljavax/crypto/spec/SecretKeySpec;', 'Ljavax/crypto/spec/IvParameterSpec;',
      'Ljava/security/Key;', 'Ljava/security/spec/AlgorithmParameterSpec;',
    ],
    extraTypes: [
      'I', '[B', 'Landroid/util/Base64;', 'Ljavax/crypto/Cipher;',
      'Ljavax/crypto/spec/SecretKeySpec;', 'Ljavax/crypto/spec/IvParameterSpec;',
      'Ljava/security/Key;', 'Ljava/security/spec/AlgorithmParameterSpec;',
    ],
    extraProtos: [
      ['LLI', '[B', ['Ljava/lang/String;', 'I']],
      ['LLI', 'Ljava/lang/String;', ['[B', 'I']],
      ['LL', 'Ljavax/crypto/Cipher;', ['Ljava/lang/String;']],
      ['VLL', 'V', ['[B', 'Ljava/lang/String;']],
      ['VL', 'V', ['[B']],
      ['VILL', 'V', ['I', 'Ljava/security/Key;', 'Ljava/security/spec/AlgorithmParameterSpec;']],
      ['LL', '[B', ['[B']],
    ],
    extraMethods: [
      ['Landroid/util/Base64;', '[B', ['Ljava/lang/String;', 'I'], 'decode'],
      ['Landroid/util/Base64;', 'Ljava/lang/String;', ['[B', 'I'], 'encodeToString'],
      ['Ljavax/crypto/Cipher;', 'Ljavax/crypto/Cipher;', ['Ljava/lang/String;'], 'getInstance'],
      ['Ljavax/crypto/spec/SecretKeySpec;', 'V', ['[B', 'Ljava/lang/String;'], '<init>'],
      ['Ljavax/crypto/spec/IvParameterSpec;', 'V', ['[B'], '<init>'],
      ['Ljavax/crypto/Cipher;', 'V', ['I', 'Ljava/security/Key;', 'Ljava/security/spec/AlgorithmParameterSpec;'], 'init'],
      ['Ljavax/crypto/Cipher;', '[B', ['[B'], 'doFinal'],
    ],
    customGetName: ({ sIdx, tIdx, mIdx }) => {
      const mDec = mIdx('Landroid/util/Base64;', 'decode');
      const mEnc = mIdx('Landroid/util/Base64;', 'encodeToString');
      const insns = [
        const4(0, 0),
        const4(1, 1), // ENCRYPT_MODE
        const4(2, 2), // NO_WRAP
        ...constStr(3, sIdx(key.toString('base64'))),
        ...invStatic(mDec, [3, 0]),
        moveResObj(3),
        ...newInst(4, tIdx('Ljavax/crypto/spec/SecretKeySpec;')),
        ...constStr(5, sIdx('AES')),
        ...invDirect(mIdx('Ljavax/crypto/spec/SecretKeySpec;', '<init>'), [4, 3, 5]),
        ...constStr(3, sIdx(iv.toString('base64'))),
        ...invStatic(mDec, [3, 0]),
        moveResObj(3),
        ...newInst(5, tIdx('Ljavax/crypto/spec/IvParameterSpec;')),
        ...invDirect(mIdx('Ljavax/crypto/spec/IvParameterSpec;', '<init>'), [5, 3]),
        ...constStr(3, sIdx('AES/CTR/NoPadding')),
        ...invStatic(mIdx('Ljavax/crypto/Cipher;', 'getInstance'), [3]),
        moveResObj(6),
        ...invVirtual(mIdx('Ljavax/crypto/Cipher;', 'init'), [6, 1, 4, 5]),
        ...constStr(3, sIdx(pt.toString('base64'))),
        ...invStatic(mDec, [3, 0]),
        moveResObj(3),
        ...invVirtual(mIdx('Ljavax/crypto/Cipher;', 'doFinal'), [6, 3]),
        moveResObj(7),
        ...invStatic(mEnc, [7, 2]),
        moveResObj(8),
        retObj(8),
      ];
      return { regs: 10, ins: 1, outs: 4, insns };
    },
  });

  assert.equal(result, expectedCt.toString('base64'));
});

test('4. AES/GCM/NoPadding (128-bit key) matches Node crypto aes-128-gcm', async () => {
  const key = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
  const iv = Buffer.from('0102030405060708090a0b0c', 'hex');
  const pt = Buffer.from('RFC 8188 ECE aes128gcm record test', 'utf8');
  const c = crypto.createCipheriv('aes-128-gcm', key, iv);
  const ctWithTag = Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);

  const result = await runProbe({
    extraStrings: [
      'AES', 'AES/GCM/NoPadding', key.toString('base64'), iv.toString('base64'), ctWithTag.toString('base64'),
      'I', '[B', 'LL', 'LLI', 'VLL', 'VIL', 'VILL', 'VL',
      'Landroid/util/Base64;', 'decode',
      'Ljavax/crypto/Cipher;', 'getInstance', 'init', 'doFinal',
      'Ljavax/crypto/spec/SecretKeySpec;', 'Ljavax/crypto/spec/GCMParameterSpec;',
      'Ljava/security/Key;', 'Ljava/security/spec/AlgorithmParameterSpec;',
    ],
    extraTypes: [
      'I', '[B', 'Landroid/util/Base64;', 'Ljavax/crypto/Cipher;',
      'Ljavax/crypto/spec/SecretKeySpec;', 'Ljavax/crypto/spec/GCMParameterSpec;',
      'Ljava/security/Key;', 'Ljava/security/spec/AlgorithmParameterSpec;',
    ],
    extraProtos: [
      ['LLI', '[B', ['Ljava/lang/String;', 'I']],
      ['LL', 'Ljavax/crypto/Cipher;', ['Ljava/lang/String;']],
      ['VLL', 'V', ['[B', 'Ljava/lang/String;']],
      ['VIL', 'V', ['I', '[B']],
      ['VILL', 'V', ['I', 'Ljava/security/Key;', 'Ljava/security/spec/AlgorithmParameterSpec;']],
      ['LL', '[B', ['[B']],
      ['VL', 'V', ['[B']],
    ],
    extraMethods: [
      ['Landroid/util/Base64;', '[B', ['Ljava/lang/String;', 'I'], 'decode'],
      ['Ljavax/crypto/Cipher;', 'Ljavax/crypto/Cipher;', ['Ljava/lang/String;'], 'getInstance'],
      ['Ljavax/crypto/spec/SecretKeySpec;', 'V', ['[B', 'Ljava/lang/String;'], '<init>'],
      ['Ljavax/crypto/spec/GCMParameterSpec;', 'V', ['I', '[B'], '<init>'],
      ['Ljavax/crypto/Cipher;', 'V', ['I', 'Ljava/security/Key;', 'Ljava/security/spec/AlgorithmParameterSpec;'], 'init'],
      ['Ljavax/crypto/Cipher;', '[B', ['[B'], 'doFinal'],
      ['Ljava/lang/String;', 'V', ['[B'], '<init>'],
    ],
    customGetName: ({ sIdx, tIdx, mIdx }) => {
      const mDec = mIdx('Landroid/util/Base64;', 'decode');
      const insns = [
        const4(0, 0),
        const4(1, 2), // DECRYPT_MODE
        ...const16(2, 128), // tag bits
        ...constStr(3, sIdx(key.toString('base64'))),
        ...invStatic(mDec, [3, 0]),
        moveResObj(3),
        ...newInst(4, tIdx('Ljavax/crypto/spec/SecretKeySpec;')),
        ...constStr(5, sIdx('AES')),
        ...invDirect(mIdx('Ljavax/crypto/spec/SecretKeySpec;', '<init>'), [4, 3, 5]),
        ...constStr(3, sIdx(iv.toString('base64'))),
        ...invStatic(mDec, [3, 0]),
        moveResObj(3),
        ...newInst(5, tIdx('Ljavax/crypto/spec/GCMParameterSpec;')),
        ...invDirect(mIdx('Ljavax/crypto/spec/GCMParameterSpec;', '<init>'), [5, 2, 3]),
        ...constStr(3, sIdx('AES/GCM/NoPadding')),
        ...invStatic(mIdx('Ljavax/crypto/Cipher;', 'getInstance'), [3]),
        moveResObj(6),
        ...invVirtual(mIdx('Ljavax/crypto/Cipher;', 'init'), [6, 1, 4, 5]),
        ...constStr(3, sIdx(ctWithTag.toString('base64'))),
        ...invStatic(mDec, [3, 0]),
        moveResObj(3),
        ...invVirtual(mIdx('Ljavax/crypto/Cipher;', 'doFinal'), [6, 3]),
        moveResObj(7),
        ...newInst(8, tIdx('Ljava/lang/String;')),
        ...invDirect(mIdx('Ljava/lang/String;', '<init>'), [8, 7]),
        retObj(8),
      ];
      return { regs: 10, ins: 1, outs: 4, insns };
    },
  });

  assert.equal(result, pt.toString('utf8'));
});

test('5. Mac("HmacSHA256") update([B) + update(B) + doFinal() + getMacLength() matches Node crypto', async () => {
  const key = Buffer.from('super-secret-hkdf-key', 'utf8');
  const info = Buffer.from('Content-Encoding: aes128gcm\0', 'utf8');
  const expected = crypto.createHmac('sha256', key).update(info).update(Buffer.from([1])).digest('base64');

  const result = await runProbe({
    extraStrings: [
      'HmacSHA256', key.toString('base64'), info.toString('base64'),
      'B', 'I', '[B', 'L', 'LL', 'LLI', 'VLL', 'VL', 'VB',
      'Landroid/util/Base64;', 'decode', 'encodeToString',
      'Ljavax/crypto/Mac;', 'getInstance', 'init', 'update', 'doFinal', 'getMacLength',
      'Ljavax/crypto/spec/SecretKeySpec;', 'Ljava/security/Key;',
    ],
    extraTypes: [
      'B', 'I', '[B', 'Landroid/util/Base64;', 'Ljavax/crypto/Mac;',
      'Ljavax/crypto/spec/SecretKeySpec;', 'Ljava/security/Key;',
    ],
    extraProtos: [
      ['LLI', '[B', ['Ljava/lang/String;', 'I']],
      ['LLI', 'Ljava/lang/String;', ['[B', 'I']],
      ['LL', 'Ljavax/crypto/Mac;', ['Ljava/lang/String;']],
      ['VLL', 'V', ['[B', 'Ljava/lang/String;']],
      ['VL', 'V', ['Ljava/security/Key;']],
      ['VL', 'V', ['[B']],
      ['VB', 'V', ['B']],
      ['L', '[B', []],
      ['I', 'I', []],
    ],
    extraMethods: [
      ['Landroid/util/Base64;', '[B', ['Ljava/lang/String;', 'I'], 'decode'],
      ['Landroid/util/Base64;', 'Ljava/lang/String;', ['[B', 'I'], 'encodeToString'],
      ['Ljavax/crypto/Mac;', 'Ljavax/crypto/Mac;', ['Ljava/lang/String;'], 'getInstance'],
      ['Ljavax/crypto/spec/SecretKeySpec;', 'V', ['[B', 'Ljava/lang/String;'], '<init>'],
      ['Ljavax/crypto/Mac;', 'V', ['Ljava/security/Key;'], 'init'],
      ['Ljavax/crypto/Mac;', 'V', ['[B'], 'update'],
      ['Ljavax/crypto/Mac;', 'V', ['B'], 'update'],
      ['Ljavax/crypto/Mac;', '[B', [], 'doFinal'],
      ['Ljavax/crypto/Mac;', 'I', [], 'getMacLength'],
    ],
    customGetName: ({ sIdx, tIdx, mIdx }) => {
      const mDec = mIdx('Landroid/util/Base64;', 'decode');
      const mEnc = mIdx('Landroid/util/Base64;', 'encodeToString');
      const insns = [
        const4(0, 0),
        const4(1, 1),
        const4(2, 2),
        ...constStr(3, sIdx('HmacSHA256')),
        ...invStatic(mIdx('Ljavax/crypto/Mac;', 'getInstance'), [3]),
        moveResObj(4),
        ...constStr(5, sIdx(key.toString('base64'))),
        ...invStatic(mDec, [5, 0]),
        moveResObj(5),
        ...newInst(6, tIdx('Ljavax/crypto/spec/SecretKeySpec;')),
        ...invDirect(mIdx('Ljavax/crypto/spec/SecretKeySpec;', '<init>'), [6, 5, 3]),
        ...invVirtual(mIdx('Ljavax/crypto/Mac;', 'init'), [4, 6]),
        ...constStr(5, sIdx(info.toString('base64'))),
        ...invStatic(mDec, [5, 0]),
        moveResObj(5),
        ...invVirtual(mIdx('Ljavax/crypto/Mac;', 'update', 'V', ['[B']), [4, 5]),
        ...invVirtual(mIdx('Ljavax/crypto/Mac;', 'update', 'V', ['B']), [4, 1]),
        ...invVirtual(mIdx('Ljavax/crypto/Mac;', 'doFinal'), [4]),
        moveResObj(7),
        ...invStatic(mEnc, [7, 2]),
        moveResObj(8),
        retObj(8),
      ];
      return { regs: 10, ins: 1, outs: 3, insns };
    },
  });

  assert.equal(result, expected);
});

test('6. okio.Buffer.copyTo(Buffer, offset, count) + readAll(Sink) + HttpUrl.queryParameter percent-decode', async () => {
  const result = await runProbe({
    extraStrings: [
      '0123456789', 'https://img.example/a?cpx=AB%2FCD%2BEF%3D&ts=1#frag', 'cpx', '|',
      'L', 'LL', 'LLJJ', 'JL',
      'Lokio/Buffer;', 'Lokio/Sink;', 'writeUtf8', 'copyTo', 'readAll', 'readUtf8',
      'Lokhttp3/HttpUrl;', 'Lokhttp3/HttpUrl$Companion;', 'parse', 'queryParameter',
      'Ljava/lang/StringBuilder;', 'append', 'toString',
    ],
    extraTypes: [
      'Lokio/Buffer;', 'Lokio/Sink;', 'Lokhttp3/HttpUrl;', 'Lokhttp3/HttpUrl$Companion;', 'Ljava/lang/StringBuilder;',
    ],
    extraProtos: [
      ['LL', 'Lokio/Buffer;', ['Ljava/lang/String;']],
      ['LLJJ', 'Lokio/Buffer;', ['Lokio/Buffer;', 'J', 'J']],
      ['JL', 'J', ['Lokio/Sink;']],
      ['LL', 'Lokhttp3/HttpUrl;', ['Ljava/lang/String;']],
      ['LL', 'Ljava/lang/String;', ['Ljava/lang/String;']],
      ['LL', 'Ljava/lang/StringBuilder;', ['Ljava/lang/String;']],
    ],
    extraMethods: [
      ['Lokio/Buffer;', 'V', [], '<init>'],
      ['Lokio/Buffer;', 'Lokio/Buffer;', ['Ljava/lang/String;'], 'writeUtf8'],
      ['Lokio/Buffer;', 'Lokio/Buffer;', ['Lokio/Buffer;', 'J', 'J'], 'copyTo'],
      ['Lokio/Buffer;', 'J', ['Lokio/Sink;'], 'readAll'],
      ['Lokio/Buffer;', 'Ljava/lang/String;', [], 'readUtf8'],
      ['Lokhttp3/HttpUrl$Companion;', 'Lokhttp3/HttpUrl;', ['Ljava/lang/String;'], 'parse'],
      ['Lokhttp3/HttpUrl;', 'Ljava/lang/String;', ['Ljava/lang/String;'], 'queryParameter'],
      ['Ljava/lang/StringBuilder;', 'V', [], '<init>'],
      ['Ljava/lang/StringBuilder;', 'Ljava/lang/StringBuilder;', ['Ljava/lang/String;'], 'append'],
      ['Ljava/lang/StringBuilder;', 'Ljava/lang/String;', [], 'toString'],
    ],
    customGetName: ({ sIdx, tIdx, mIdx }) => {
      const mBufInit = mIdx('Lokio/Buffer;', '<init>');
      const mWrite = mIdx('Lokio/Buffer;', 'writeUtf8');
      const mCopyTo = mIdx('Lokio/Buffer;', 'copyTo');
      const mReadAll = mIdx('Lokio/Buffer;', 'readAll');
      const mReadUtf8 = mIdx('Lokio/Buffer;', 'readUtf8');
      const mSbApp = mIdx('Ljava/lang/StringBuilder;', 'append');

      // Note: copyTo takes (this, dst, J, J) -> 6 registers, so use invoke-virtual/range (0x74)
      // v0=src, v1=dst1, v2..v3=offset(2L), v4..v5=count(4L)
      const insns = [
        ...newInst(0, tIdx('Lokio/Buffer;')),
        ...invDirect(mBufInit, [0]),
        ...constStr(6, sIdx('0123456789')),
        ...invVirtual(mWrite, [0, 6]),
        ...newInst(1, tIdx('Lokio/Buffer;')),
        ...invDirect(mBufInit, [1]),
        ...constWide16(2, 2),
        ...constWide16(4, 4),
        // invoke-virtual/range {v0..v5}, copyTo
        0x0674, mCopyTo, 0x0000,
        // dst2 = Buffer(); src.readAll(dst2) -> proves src was NOT consumed by copyTo!
        ...newInst(6, tIdx('Lokio/Buffer;')),
        ...invDirect(mBufInit, [6]),
        ...invVirtual(mReadAll, [0, 6]),
        // HttpUrl.Companion.parse(...).queryParameter("cpx") -> v7
        ...newInst(8, tIdx('Lokhttp3/HttpUrl$Companion;')),
        ...constStr(7, sIdx('https://img.example/a?cpx=AB%2FCD%2BEF%3D&ts=1#frag')),
        ...invVirtual(mIdx('Lokhttp3/HttpUrl$Companion;', 'parse'), [8, 7]),
        moveResObj(7),
        ...constStr(8, sIdx('cpx')),
        ...invVirtual(mIdx('Lokhttp3/HttpUrl;', 'queryParameter'), [7, 8]),
        moveResObj(7),
        // sb = dst1.readUtf8() + "|" + dst2.readUtf8() + "|" + cpx
        ...newInst(8, tIdx('Ljava/lang/StringBuilder;')),
        ...invDirect(mIdx('Ljava/lang/StringBuilder;', '<init>'), [8]),
        ...invVirtual(mReadUtf8, [1]),
        moveResObj(9),
        ...invVirtual(mSbApp, [8, 9]),
        ...constStr(9, sIdx('|')),
        ...invVirtual(mSbApp, [8, 9]),
        ...invVirtual(mReadUtf8, [6]),
        moveResObj(9),
        ...invVirtual(mSbApp, [8, 9]),
        ...constStr(9, sIdx('|')),
        ...invVirtual(mSbApp, [8, 9]),
        ...invVirtual(mSbApp, [8, 7]),
        ...invVirtual(mIdx('Ljava/lang/StringBuilder;', 'toString'), [8]),
        moveResObj(9),
        retObj(9),
      ];
      return { regs: 11, ins: 1, outs: 6, insns };
    },
  });

  assert.equal(result, '2345|0123456789|AB/CD+EF=');
});
