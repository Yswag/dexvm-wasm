// dexvm-host.js — zero-dependency WASI (preview1) + `host` import shim for
// dist/dexvm_bridge.wasm. Works in a Web Worker (no SharedArrayBuffer, no
// Atomics) and in Node 18+.
//
//   import { createDexvm } from './dexvm-host.js';
//   const vm = await createDexvm({
//     wasmBytes,                       // ArrayBuffer | Uint8Array | WebAssembly.Module
//     http: (req) => respJsonString,   // SYNC: {url,method,headers,bodyBase64?}
//                                      //   -> {status,headers,bodyBase64,finalUrl} | {error}
//     log: (level, msg) => {},         // optional
//     evalJs: (src) => jsonString,     // optional, for app.cash.quickjs
//   });
//   const value = vm.call('open', { apkBase64 });   // throws DexvmError on ok:false

const ERRNO = {
  SUCCESS: 0,
  BADF: 8,
  INVAL: 28,
  IO: 29,
  NOSYS: 52,
  NOTSUP: 58,
};

const POLL_CAP_MS = 2000;

export class DexvmError extends Error {
  constructor(err) {
    super(err && err.message ? err.message : String(err));
    this.name = 'DexvmError';
    this.kind = (err && err.kind) || 'internal';
    this.javaStack = err && err.javaStack;
    this.raw = err;
  }
}

function encoder() {
  return new TextEncoder();
}
let _decoder = null;
function decoder() {
  if (!_decoder) _decoder = new TextDecoder('utf-8');
  return _decoder;
}

export async function createDexvm({ wasmBytes, http, log, evalJs } = {}) {
  if (!wasmBytes) throw new Error('createDexvm: wasmBytes is required');
  let instance = null;
  let cryptoObj = globalThis.crypto;
  if (!cryptoObj) {
    try {
      cryptoObj = (await import('node:crypto')).webcrypto;
    } catch {
      cryptoObj = null;
    }
  }
  const warn = (msg) => {
    if (typeof log === 'function') log(3, msg);
    else if (typeof console !== 'undefined') console.warn('[dexvm] ' + msg);
  };
  const mem = () => new Uint8Array(instance.exports.memory.buffer);
  const dv = () => new DataView(instance.exports.memory.buffer);

  function readStr(ptr, len) {
    if (!ptr || !len) return '';
    return decoder().decode(mem().subarray(ptr, ptr + len));
  }

  // The host writes its reply into wasm memory: allocate through the module's
  // own `alloc` export, copy the bytes in, hand back (ptr<<32)|len.
  function writeToWasm(str) {
    const bytes = encoder().encode(str);
    if (bytes.length === 0) return 0n;
    const ptr = instance.exports.alloc(bytes.length);
    if (!ptr) return 0n;
    mem().set(bytes, ptr); // re-reads the (possibly grown) buffer each time
    return (BigInt(ptr) << 32n) | BigInt(bytes.length);
  }

  function errno(code) {
    return code;
  }

  const wasi = {
    clock_time_get(_id, _precision, out) {
      // Date.now() has ms resolution; ns precision is good enough for the VM.
      dv().setBigUint64(out, BigInt(Date.now()) * 1000000n, true);
      return 0;
    },
    random_get(ptr, len) {
      const buf = mem().subarray(ptr, ptr + len);
      if (cryptoObj && cryptoObj.getRandomValues) {
        for (let off = 0; off < buf.length; off += 65536) {
          cryptoObj.getRandomValues(buf.subarray(off, Math.min(off + 65536, buf.length)));
        }
      } else {
        warn('crypto.getRandomValues unavailable, falling back to Math.random');
        for (let i = 0; i < buf.length; i++) buf[i] = (Math.random() * 256) | 0;
      }
      return 0;
    },
    fd_write(fd, iovs, iovsLen, nwritten) {
      const view = dv();
      let total = 0;
      let text = '';
      for (let i = 0; i < iovsLen; i++) {
        const base = iovs + i * 8;
        const ptr = view.getUint32(base, true);
        const len = view.getUint32(base + 4, true);
        text += readStr(ptr, len);
        total += len;
      }
      if (fd === 1) console.log(text.replace(/\n$/, ''));
      else if (fd === 2) console.error(text.replace(/\n$/, ''));
      else return ERRNO.BADF;
      view.setUint32(nwritten, total, true);
      return 0;
    },
    environ_sizes_get(countPtr, sizePtr) {
      dv().setUint32(countPtr, 0, true);
      dv().setUint32(sizePtr, 0, true);
      return 0;
    },
    environ_get() {
      return 0;
    },
    args_sizes_get(countPtr, sizePtr) {
      dv().setUint32(countPtr, 0, true);
      dv().setUint32(sizePtr, 0, true);
      return 0;
    },
    args_get() {
      return 0;
    },
    proc_exit(code) {
      throw new Error('dexvm: wasm called proc_exit(' + code + ')');
    },
    sched_yield() {
      return 0;
    },
    // Only single absolute/relative clock subscriptions are supported.
    // No Atomics.wait in a worker without SharedArrayBuffer => busy wait,
    // capped at POLL_CAP_MS.
    poll_oneoff(inPtr, outPtr, nsubs, neventsPtr) {
      const view = dv();
      let written = 0;
      for (let i = 0; i < nsubs; i++) {
        const sub = inPtr + i * 48;
        const userdata = view.getBigUint64(sub, true);
        const type = view.getUint8(sub + 8);
        const ev = outPtr + written * 32;
        view.setBigUint64(ev, userdata, true);
        if (type === 0) {
          const clockId = view.getUint32(sub + 16, true);
          const timeout = view.getBigUint64(sub + 24, true); // ns
          const flags = view.getUint16(sub + 40, true);
          const nowNs = BigInt(Date.now()) * 1000000n;
          let target = flags & 1 ? timeout : nowNs + timeout;
          // subscriptions with id 0 (realtime) or 1 (monotonic) both use Date.now here
          if (clockId > 1) {
            view.setUint16(ev + 8, ERRNO.INVAL, true);
            view.setUint8(ev + 10, 2);
            written++;
            continue;
          }
          const capNs = BigInt(POLL_CAP_MS) * 1000000n;
          if (target - nowNs > capNs) {
            warn('poll_oneoff clock wait truncated to ' + POLL_CAP_MS + 'ms (was ' +
              Number((target - nowNs) / 1000000n) + 'ms)');
            target = nowNs + capNs;
          }
          // busy wait; Date.now() may not advance fast enough on some hosts,
          // so also bound the loop by iterations.
          let guard = 0;
          while (Date.now() < Number(target / 1000000n) && guard++ < 4_000_000) {}
          view.setUint16(ev + 8, 0, true);
          view.setUint8(ev + 10, 0);
        } else {
          view.setUint16(ev + 8, ERRNO.NOSYS, true);
          view.setUint8(ev + 10, type);
        }
        written++;
      }
      view.setUint32(neventsPtr, written, true);
      return 0;
    },
    fd_close: () => errno(ERRNO.BADF),
    fd_read: () => errno(ERRNO.BADF),
    fd_seek: () => errno(ERRNO.BADF),
    fd_sync: () => errno(ERRNO.BADF),
    fd_fdstat_get: () => errno(ERRNO.BADF),
    fd_filestat_get: () => errno(ERRNO.BADF),
    fd_prestat_get: () => errno(ERRNO.BADF),
    fd_prestat_dir_name: () => errno(ERRNO.BADF),
    fd_readdir: () => errno(ERRNO.BADF),
    path_open: () => errno(ERRNO.NOSYS),
    path_create_directory: () => errno(ERRNO.NOSYS),
    path_filestat_get: () => errno(ERRNO.NOSYS),
    path_readlink: () => errno(ERRNO.NOSYS),
    path_remove_directory: () => errno(ERRNO.NOSYS),
    path_rename: () => errno(ERRNO.NOSYS),
    path_unlink_file: () => errno(ERRNO.NOSYS),
  };

  const imports = {
    host: {
      http(reqPtr, reqLen) {
        let reply;
        try {
          const reqJson = readStr(reqPtr, reqLen);
          reply = http ? http(reqJson) : JSON.stringify({ error: 'no http handler' });
        } catch (e) {
          reply = JSON.stringify({ error: 'host http threw: ' + (e && e.message ? e.message : e) });
        }
        return writeToWasm(String(reply));
      },
      log(level, ptr, len) {
        const msg = readStr(ptr, len);
        if (typeof log === 'function') log(level, msg);
        else if (level >= 4) console.error('[dexvm] ' + msg);
        else if (level === 3) console.warn('[dexvm] ' + msg);
      },
      eval_js(ptr, len) {
        let reply;
        try {
          const src = readStr(ptr, len);
          if (typeof evalJs !== 'function') {
            reply = JSON.stringify({ ok: false, error: 'evalJs not provided by loader' });
          } else {
            const out = evalJs(src); // must return a JSON string
            reply = typeof out === 'string' ? out : JSON.stringify({ ok: true, value: out });
          }
        } catch (e) {
          reply = JSON.stringify({ ok: false, error: String((e && e.message) || e) });
        }
        return writeToWasm(String(reply));
      },
    },
    wasi_snapshot_preview1: wasi,
  };

  // Accept ArrayBuffer / TypedArray / Module
  let moduleOrBytes = wasmBytes;
  if (wasmBytes instanceof Uint8Array || wasmBytes instanceof ArrayBuffer) {
    moduleOrBytes = wasmBytes;
  }
  const result = await WebAssembly.instantiate(moduleOrBytes, imports);
  instance = result.instance || result;

  let trapped = false;
  function call(op, args = {}) {
    if (trapped) throw new DexvmError({ kind: 'trap', message: 'instance already trapped' });
    const payload = JSON.stringify({ op, ...args });
    const bytes = encoder().encode(payload);
    const ptr = instance.exports.alloc(bytes.length);
    if (!ptr && bytes.length) throw new Error('dexvm: alloc failed');
    mem().set(bytes, ptr);
    let packed;
    try {
      packed = instance.exports.call(ptr, bytes.length);
    } catch (e) {
      // wasm32-wasip1 has no unwinding: a Rust panic aborts the instance.
      // Surface it as a regular error instead of letting it escape silently.
      trapped = true;
      throw new DexvmError({
        kind: 'trap',
        message: 'wasm trapped (' + (e && e.message ? e.message : e) + '); the instance is unusable',
      });
    }
    instance.exports.dealloc(ptr, bytes.length);
    const outPtr = Number(packed >> 32n);
    const outLen = Number(packed & 0xffffffffn);
    let text = '';
    if (outPtr && outLen) {
      text = decoder().decode(mem().subarray(outPtr, outPtr + outLen));
      instance.exports.dealloc(outPtr, outLen);
    }
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new DexvmError({ kind: 'protocol', message: 'bad reply from wasm: ' + text.slice(0, 200) });
    }
    if (!parsed.ok) throw new DexvmError(parsed.error);
    return parsed.value;
  }

  return { call, instance, exports: instance.exports, get trapped() { return trapped; } };
}

export default createDexvm;
