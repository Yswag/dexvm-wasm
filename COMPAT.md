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

### SAFE zh sweep (2026-11-12)

`node test/run.mjs apks <dir>` over the 23 `CONTENT_WARNING_SAFE` zh
extensions in the keiyoushi index (`zh` sources only). 8 pass end to end:

| Source | Result |
|---|---|
| MangaToon (Limited) 1.6.2 | ✅ 18 / 276 / 1, image 70,349 B |
| xkcd 1.6.2 | ✅ 1 / 676 / 2, image 47,080 B PNG |
| ACGN 1.6.0 | ✅ 36 / 137 / 16, image 155,663 B |
| 崩坏3 IP站 bh3 1.6.1 | ✅ 23 / 7 / 21, image 189,809 B |
| Bika Manhua (unoriginal) 1.6.3 | ✅ 30 / 225 / 21, image 563,084 B |
| 漫画1234 mh1234 1.6.6 | ✅ 21 / 554 / 11, image 104,424 B webp |
| 漫画160 mh160 1.6.2 | ✅ 50 / 786 / 26, image 234,603 B |
| 如漫 Rumanhua (unoriginal) 1.6.1 | ✅ 20 / 352 / 8, image 102,046 B webp |

Failures, by cause:
* Cloudflare/JS challenge (host-side WebView): baozimanhua, manhuawu,
  dumanwu, rumanhua.
* Dead or blocked hosts: guazimanhua (connect timeout), zazhimi (API body
  empty), mangabz (popular 0), comicabc (popular 0).
* Site markup changes: GoDa (detail links resolve to a broken host), manben /
  Terra Historicus (detail NPE after a non-matching `selectFirst`),
  zaimanhua (empty chapter list + canvas comment interceptor).
* Needs Android graphics: Dragon Ball Multiverse (draws balloons onto images).

VM/bridge fixes from this sweep:
* `java.net.URLEncoder.encode` / `URLDecoder.decode` read the *charset*
  argument instead of the string (every call returned `"UTF-8"`). This broke
  every path-encoding helper.
* `getImageUrl(page)` (suspend and plain shapes) is now consulted when the
  page list carries no image URL.
* Shims: `java.time.ZoneOffset.UTC`, `java.time.ZoneId`,
  `StringCompanionObject.INSTANCE`, `okhttp3.Headers.Companion`,
  `okhttp3.Response` implements `java.io.Closeable`,
  `javax.net.ssl.HostnameVerifier`, `DateTimeFormatter.getZone`,
  `BooleanSerializer.INSTANCE`, `decodeFloat/DoubleElement`,
  `StringsKt.toList(CharSequence)`.
* `async {}` no longer swallows the body's exception into a null Deferred.
* The test harness follows redirects (OkHttp semantics) and resets the wasm
  instance after a trap.

### MIXED/NSFW zh sweep (2026-11-12)

Same harness over the 35 `CONTENT_WARNING_MIXED` + 39 `CONTENT_WARNING_NSFW`
zh extensions: **32 of 74 pass** the full flow. Notable passes:

| Source | Result |
|---|---|
| Akuma 1.6.11 | 60 / 1 / 86, 331 KB JPEG |
| AsmHentai 1.6.15 | 20 / 1 / 198, 62 KB |
| Cin.blue 1.6.1 | 25 / 1 / 79, 403 KB webp |
| Comic Fury 1.6.1 (zh) | 20 / 68 / 1, 441 KB PNG |
| HentaiFox 1.6.22 | 20 / 1 / 203, 163 KB |
| NHentai.to 1.6.12 / NHentai.xxx 1.6.13 | 24–25 / 1 / 85–162, 238–283 KB |
| 3Hentai 1.6.7 | 25 / 1 / 236, 347 KB |
| 92漫画 1.6.1 | 36 / 96 / 49, 199 KB |
| 米卡漫画 1.6.1 | 25 / 1 / 3, 595 KB JPEG |
| CManhua 1.6.1 | 12 / 48 / 1, 134 KB webp |
| HANMAN18 / Manga Xiao Si | 20 / 326–336 / 156, 61–62 KB |
| dm5, Komiic, manhuagui, kaobeimanhua, 极速漫画, 比卡漫画 … | unchanged |

Failure buckets:
* Cloudflare/anti-bot: MyReadingManga, MyComic, 18漫画, 90漫画, 优酷漫画,
  绅士会所 (451), 禁漫天堂.
* Dead/blocked hosts: HentaiHand, nHentai.com, Luscious, 漫蛙 (connect fail).
* Site markup/API changes: Ahri Gallery, Manga Ball, Swarm, 米卡漫画,
  Hanime1 (0 mangas), BaKa/巴卡.
* VM gaps still open: Kotlin reflection beyond `KFunction` (property access,
  `Class.getClassifier`), continuation casts (`Pixiv`, 嬉皮漫畫),
  `okio`/`Class.getClassifier`, `SupportLibReflectionUtil` (HDoujin), the
  bundled `ca.mpreg.imagedecoder.ImageDecoder` (ToonLook), and three sources
  that trap the wasm instance (Kagane, 漫?漫画, zero…) — needs a panic message
  from the host before they can be diagnosed.
* `NHentai.website` and one more reach the reader but fail
  `pageListParse` (`NumberFormatException: ""`).

RSA is now implemented (`X509EncodedKeySpec`, `KeyFactory.generatePublic`,
`Cipher` `RSA/ECB/PKCS1Padding`). 漫画人 gets through key parsing and the
encrypted anonymous-user call and stops at the site's own "please log in"
error, not a VM gap. Kotlin function references now satisfy `KFunction` and
carry their captured `receiver`, so `::method` callables type-check.

Shims added for this sweep: `Cookie.Companion`, `okhttp3.Protocol`,
`java.time.temporal.ChronoField` constants, `Locale.CHINESE`,
`Build.VERSION.SDK_INT/RELEASE/CODENAME`, `JsonPrimitiveSerializer.INSTANCE`,
`Instant.ofEpochSecond` (+nanos), `kotlin.time.Instant.Companion.DISTANT_PAST`,
`Instant.epochSeconds`, `ArrayDeque.size/addAll`, `ListIterator.hasPrevious/
previous`, `DateTimeFormatter.withZone`, `DateTimeFormatterBuilder.
parseCaseInsensitive`, `okio.BufferedSource/Buffer.readByteArray(J)`,
jsoup `Element : Node` and `Element.isBlock`, `CompletableDeferred(value)` /
`await` / `complete`, `MatchGroupCollection`/`MatchGroup` (allocated as the
declared collection class), `SharedPreferences.getAll`,
`WebView.getWebViewClassLoader`, `Class.getClassifier`, and
`kotlin.time.Instant` compareTo/minus/toString.

Later shims: RSA (`java.security.spec.X509EncodedKeySpec`,
`KeyFactory`, `javax.crypto.Cipher` PKCS#1 v1.5), `okio.Buffer()` init,
`ByteString` companion/digests (`md5`, `sha1`), `LocalDateTime.now`,
FormBody `writeTo` form-encoding, and `KFunction`/receiver on
`FunctionReferenceImpl`.

### Inverse gap scan (2026-11-12)

Instead of copying Suwayomi's `AndroidCompat` class list, the corpus was
scanned directly: every dex in the 97 zh APKs was parsed for its type table,
defined classes were subtracted, and the result was diffed against the shims
already in the VM. 592 external classes, 162 not referenced by any shim.

Only a handful have non-trivial reference counts, and none are "missing
Android support" — they are small surface classes: `kotlin.enums.EnumEntries`,
`okhttp3.Connection`, `android.os.LocaleList`, `java.util.Locale$Builder`,
`kotlinx.serialization.Serializable`, `CoroutineStart`, the
`Float/Double/IntArray/JsonArray/JsonObject` serializers, `Layout$Alignment`,
`MultipartBody`, and WebView preference/callback interfaces. These are now
shimmed (with real `LocaleList` / `Locale.Builder` / multipart media types /
serializer behavior); the rest are annotations or unused platform internals.

Suwayomi's compat layer is JVM Java over AWT/JCE/JCEF and cannot be dropped
into a wasm DEX engine; it is useful only as a behavior reference.

### Old 1.6 notes (2026-11-09, kept for history)

Initial shims before the VM fixes: `Json.Default` singleton + inheritance,
`JsonElementSerializer` (+`INSTANCE`), `EnumSerializer.serialize`,
`IntRange.iterator`, `DateTimeFormatter.parseCaseInsensitive`,
`Jsoup.parse(InputStream,…)`, relative selectors (`"> ul"`),
`:contains/:containsData`, non-panicking `payload_of`/`str_of_jvalue`,
primitive-safe `Intrinsics.areEqual`, and native-dispatch diagnostics.
