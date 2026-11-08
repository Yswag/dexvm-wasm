import fs from 'node:fs';
import { createDexvm } from '../dexvm-host.js';

const WASM = process.env.WASM || '../dist/dexvm_bridge.wasm';
const APK = process.argv[2] || new URL('../test/fixtures/tachiyomi-en.mangapill-v1.4.9.apk', import.meta.url).pathname;

const wasmBytes = fs.readFileSync(new URL(WASM, import.meta.url));
const t0 = performance.now();
const vm = await createDexvm({
  wasmBytes,
  http: () => JSON.stringify({ error: 'network disabled in smoke test' }),
  log: (l, m) => { if (l >= 3) console.error(`[wasm ${l}] ${m}`); },
});
console.log('instantiate ms', (performance.now() - t0).toFixed(1));

const b64 = fs.readFileSync(APK).toString('base64');
let t = performance.now();
const opened = vm.call('open', { apkBase64: b64 });
console.log('open ms', (performance.now() - t).toFixed(1), JSON.stringify(opened.value ?? opened));

t = performance.now();
const sources = vm.call('sources', { handle: opened.handle });
console.log('sources ms', (performance.now() - t).toFixed(1));
console.log(JSON.stringify(sources, null, 2));

const src = sources[0];
t = performance.now();
const filters = vm.call('filters', { handle: opened.handle, sourceId: src.id });
console.log('filters ms', (performance.now() - t).toFixed(1), JSON.stringify(filters));

const prefs = vm.call('preferences', { handle: opened.handle, sourceId: src.id });
console.log('preferences', JSON.stringify(prefs));
console.log('exportPrefs', JSON.stringify(vm.call('exportPrefs', { handle: opened.handle })));
vm.call('close', { handle: opened.handle });
console.log('total ms', (performance.now() - t0).toFixed(1));
