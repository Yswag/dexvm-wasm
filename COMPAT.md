# Compatibility

Update this table on every release. "Passing" means
`popular → details → chapters → pages → fetchImage`, not just `open`.

## Verified

| Date | Release | dexvm | ext-lib (Mihon) | Corpus | Result |
|---|---|---|---|---|---|
| 2026-11-08 | v0.1.0 | 0.2.0 + patch | 1.4.x, 1.6.3–1.6.8 | `test/fixtures/` (5 APKs) | 5/5 open + sources; MangaPill 1.4.9 and Comic Fury 1.4.8 complete the full flow including images |
| 2026-11-12 | unreleased | 0.2.0 + patch | 1.6.1–1.6.11 | `test/fixtures/` (14 APKs in `run.mjs`) | 14/14 open + sources; 4/5 Chinese 1.6 sources complete the full flow with images (`node test/run.mjs 1.6`) |

Raw output: `test/results/all.log` (1.4 baseline); run `node test/run.mjs 1.6`
for the current 1.6 gate.

## Unsupported

| Generation | State | Missing |
|---|---|---|
| ext-lib **1.6.x** (current repo builds) | ⚠️ partial — see below | RSA/X509 crypto (manhuaren), site-side gatekeepers (baozimanhua), a few source-specific DOM/JSON edge cases |
| ext-lib 1.4.x | ✅ works | — (Mihon 0.21 is the last major release supporting 1.4, and the repo stopped publishing it in 2026-10) |
| ext-lib 1.5.x | untested | no APKs on hand |

The remaining 1.6 failures are source/site-specific rather than VM-generation
wide; the VM-level gaps found so far are listed under "VM/bridge fixes".

## Corpus policy

The guarantee is **"every APK in the corpus passes"**, not "every extension
works".

* Corpus = `test/fixtures/*.apk` plus an optional `test/corpus.json` for remote APKs.
* Record a SHA-256 per APK. Upstream rebuilds change versions; re-pinning is a
  deliberate act, not a daily chore.
* Target size: 10–30 sources actually in use. Steady-state cost ≈ 1–2 h/month.
* No work is required between releases; upstream churn does not affect pinned
  artifacts.

### 1.6.x progress (2026-11-12)

Each row is `popular → details → chapters → pages → fetchImage`.

| Source | Result | Notes |
|---|---|---|
| 动漫屋 dm5 v1.6.4 (zh) | ✅ 70 / 227 / 69 | image 175,427 B `image/jpeg` |
| Komiic v1.6.11 (zh) | ✅ 30 / 203 / 12 | image 141,880 B `image/jpeg` |
| 漫画柜 manhuagui v1.6.1 (zh) | ✅ 42 / 235 / 230 | image 178,932 B `image/webp` |
| 拷貝漫畫 kaobeimanhua v1.6.1 (zh) | ✅ 30 / 235 / 21 | image 862,825 B `image/jpeg` (new fixture) |
| 包子漫画 baozimanhua v1.6.33 (zh) | ❌ | site gatekeeper: `/__gatekeeper_challenge/start` → HTTP 403 before any parse |
| 漫画人 manhuaren v1.6.2 (zh) | ❌ probe | `X509EncodedKeySpec.<init>([B)` / RSA public-key encryption missing |
| Mangabz v1.6.3 (zh) | ❌ probe | `popular` returns 0 entries; site DOM/API change, not a shim error |

`manhuaren` and `mangabz` were probed from the current keiyoushi repo but are
not part of the corpus; only `test/fixtures/*.apk` is gated.

### VM/bridge fixes behind the 1.6 results

All vendor edits are marked `// wasm:`.

* `instance-of` (22c) kept only the low 8 bits of the type index → resolved
  obfuscated classes to primitive descriptors like `I`.
* `const/high16` / `const-wide/high16` shifted an already-shifted literal,
  turning every such constant into 0 (broke LZString base64 decoding).
* Float/double literals loaded as `Int`/`Long` bit patterns now coerce when the
  other binop operand is already `Float`/`Double`.
* Shims: `RoundingMode`, `Instant.Companion`, `Random.Default` + `nextBytes/
  nextLong/nextFloat/nextBoolean/nextInt`, predefined `DateTimeFormatter`
  constants (`ISO_LOCAL_DATE`, `BASIC_ISO_DATE`, …), `JsonElementSerializer`
  Object-returning bridge methods, null/default `HexFormat`, `joinToString`
  null/`Char` elements, `Headers$Builder.get`.
* Source enumeration falls back to single-source discovery when a
  `SourceFactory.createSources()` call throws (one bad factory no longer hides
  the extension).
* Bridge: `QuickJs.evaluate` translates JS arrays/objects to typed Java arrays
  and `HashMap` (Suwayomi's `translateType` shape) and `compile`/`execute`
  round-trip source; image fetches go through the extension's
  `getImageRequest`/`imageRequest`; `Jsoup.parse(InputStream, charset, baseUri)`
  honours the base URI argument.
* Cookie jar shared between `host.http` and `android.webkit.CookieManager`;
  the host can seed/read it through the `cookies` op (WebView challenge flow).

### Old 1.6 notes (2026-11-09, kept for history)

Initial shims before the VM fixes: `Json.Default` singleton + inheritance,
`JsonElementSerializer` (+`INSTANCE`), `EnumSerializer.serialize`,
`IntRange.iterator`, `DateTimeFormatter.parseCaseInsensitive`,
`Jsoup.parse(InputStream,…)`, relative selectors (`"> ul"`),
`:contains/:containsData`, non-panicking `payload_of`/`str_of_jvalue`,
primitive-safe `Intrinsics.areEqual`, and native-dispatch diagnostics.
