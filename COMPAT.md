# Compatibility

Update this table on every release. "Passing" means
`popular → details → chapters → pages → fetchImage`, not just `open`.

## Verified

| Date | Release | dexvm | ext-lib (Mihon) | Corpus | Result |
|---|---|---|---|---|---|
| 2026-11-08 | v0.1.0 | 0.2.0 + patch | 1.4.x, 1.6.3–1.6.8 | `test/fixtures/` (5 APKs) | 5/5 open + sources; MangaPill 1.4.9 and Comic Fury 1.4.8 complete the full flow including images |
| 2026-11-12 | v0.2.0-beta.1 | 0.2.0 + patch | 1.6.1–1.6.72 | 14 fixtures + 97 zh sweep | 14/14 open; 1.6 gate 5/11 full flow (dm5, Komiic, manhuagui, kaobeimanhua, CuuTruyen); zh full-flow 45/97; EN spot check 0/12 but MangaDex reaches pages |
| 2026-11-25 | v0.2.0 | 0.2.0 + patch | 1.6.1–1.6.72 | 24 fixtures (`test/fixtures/`, 21 ext-lib 1.6) | 24/24 open; 1.6 gate **16/21** full flow (+Weeb Central, MangaDex, MangaFire, Mangahere, Kun Manga Online, Mangakakalot, **MANGA Plus by SHUEISHA**, **Shonen Jump+**, **Webtoons.com**, **MangaBuddy/MangaK**, **Rawkuma**); all 5 remaining failures are site-side (403/522/UA), zero VM errors |
| 2026-11-25 | v0.2.1 | 0.2.0 + patch | 1.6.1–1.6.72 | 25 fixtures (`test/fixtures/`, 22 ext-lib 1.6) | 25/25 open; 1.6 gate **17/22** full flow (+**manhuagui v1.6.2** via `HttpSource.getHeaders()` → `headersBuilder()` / `configureHeaders()`, `AppInfo.INSTANCE`, and optional `open.defaultUserAgent`); 6/6 offline header unit tests pass |
| 2026-11-25 | v0.2.2 | 0.2.0 + patch | 1.6.1–1.6.72 | 25 fixtures (`test/fixtures/`, 22 ext-lib 1.6) | 25/25 open; 1.6 gate **17/22** full flow; optional host `sleep(ms)` in `dexvm-host.js`, timed wait shims (`Object.wait`, `Condition.awaitNanos`/`await`, `CountDownLatch.await`) routed via WASI `poll_oneoff`, `DurationUnit` fix; 11/11 unit tests pass |
| 2026-11-26 | v0.2.3 | 0.2.0 + patch | 1.6.1–1.6.72 | 25 fixtures (`test/fixtures/`, 22 ext-lib 1.6) | 25/25 open; 1.6 gate **17/22** full flow; single-request 1.6 `details`/`chapters` + combined `mangaUpdate` op, non-blocking `GlobalScope.launch` + `DelayKt.delay` → host `sleep`, `StringsKt.lineSequence`/`Sequence.iterator`, `MatchResult.getDestructured`, `BooleanSerializer` boxing, `JsonNull.INSTANCE`; 17/17 unit tests pass |
| 2026-11-26 | v0.2.4 | 0.2.0 + patch | 1.6.1–1.6.72 | 25 fixtures (`test/fixtures/`, 22 ext-lib 1.6) | 25/25 open; detached `GlobalScope.launch`/`CoroutineScope(...).launch` queued per VM instance and drained via `runPending` op with true `COROUTINE_SUSPENDED` `delay()` suspension (`nextDueMs`), `Job.isActive`/`isCompleted`/`cancel`/`join`, and exception isolation; 21/21 unit tests pass |
| 2026-11-26 | v0.2.5 | 0.2.0 + patch | 1.6.1–1.6.72 | 25 fixtures (`test/fixtures/`, 22 ext-lib 1.6) | 25/25 open; direct coroutine dispatch for 1.6 `pages`/`popular`/`latest`/`search` (no spurious legacy `pageListRequest`/`*Request` calls), `ZonedDateTime.toLocalDate()` / `toLocalDateTime()` / `OffsetDateTime.toLocalDate()` / `LocalDateTime.toLocalDate()`; 25/25 unit tests pass |
| 2026-11-26 | v0.2.6 | 0.2.0 + patch | 1.6.1–1.6.72 | 25 fixtures (`test/fixtures/`, 22 ext-lib 1.6) | 25/25 open; new `headers` op, `imageRequest` header consistency & 0-fetch when `page.imageUrl` is set, `System.getProperty("http.agent")` Dalvik default, Jsoup `Element.children()` element-only + `MapsKt.getValue(JsonObject)` (GoDa `mangaUpdate` live), `Integer`/`Long` bit helpers, `fetchImage` 1-request fast path when `page.imageUrl` is set, `TimeZone.getID()`/`getRawOffset()`/`getOffset(long)`; 31/31 unit tests pass |
| 2026-11-26 | v0.2.7 | 0.2.0 + patch | 1.6.1–1.6.72 | 25 fixtures (`test/fixtures/`, 22 ext-lib 1.6) | 25/25 open; OkHttp `Request.Builder.tag(...)` / `Request.tag(...)` (`Class`, `KClass`, `Object`) preserved across `build()`/`newBuilder()`/interceptors so keiyoushi `BrowserHeaders` injects `Referer`/`Accept`/`Sec-Fetch-*`, plus `fetchImage` throws `HttpException: HTTP <code>` on non-2xx responses; 34/34 unit tests pass |

Raw output: `test/results/all.log` (1.4 baseline); run `node test/run.mjs 1.6`
for the current 1.6 gate.

## Unsupported

| Generation | State | Missing |
|---|---|---|
| ext-lib **1.6.x** (current repo builds) | ✅ supported (17/22 gated fixtures pass full flow; 0 VM errors) | RSA/X509 crypto (manhuaren), site-side Cloudflare/gatekeepers (baozimanhua, Asura Scans, MoeTruyen) |
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
zh extensions: **36 of 74 pass** the full flow (site flakiness moves one or
two either way; every remaining failure is a site/credentials issue or a
missing bundled library, not a VM trap). Notable passes:

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
| Pixiv 1.6.1 | 50 / 2 / 14, 4.8 MB JPEG |
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
  bundled `ca.mpreg.imagedecoder.ImageDecoder` (ToonLook), and login-gated
  sites (漫画人, PICACG, 177漫画). No source traps the wasm instance any more.
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

Trap fixes (all three former hard traps): `removeAll { }` read the boxed
Boolean result as an int (now `bool_of`); `CharRange` materialized elements
as raw ints in generic collections (now boxed `Character`, so R8's
`getClass()` null-check works); a virtual invoke with a non-object receiver
now throws a catchable NPE and logs the method instead of panicking.
`MatchResult.getRange()` was added. `JValue::as_*` panics now report the
call site via `#[track_caller]`.

Next VM-semantics fixes (Pixiv and 90漫画 now pass): `new-instance` fills
object fields with JVM defaults instead of null (`Ref$IntRef.element` read as
null before its first write); shim `alloc` does the same for host-allocated
objects; `SuspendLambda`/`RestrictedSuspendLambda` extend `ContinuationImpl`
so suspend lambdas satisfy `Continuation` casts; `android.util.LruCache` is a
real map (`put/get/remove/size/evictAll`); `BigInteger` gained
`and/or/xor` and `ZERO/ONE/TWO/TEN`. Safe-zh now 9/23 (包子漫画 closed its
gatekeeper).

### EN spot check (2026-11-12)

Twelve popular EN extensions from the current index, `DEXVM_LANGS=en`,
`DEXVM_UA=okhttp/4.12.0` (MangaDex rejects browser UAs): **0 full passes**,
but the failures are mostly site-side:

| Source | Result |
|---|---|
| MangaDex 1.6.4 | popular/details/chapters/pages OK; imageUrl is a relative `/data/...` path, rejected as an invalid URL |
| MangaFire 1.6.38 | NPE in popular after the lock fix |
| Asura Scans 1.6.72 | site 403 |
| ComicK Fanmade 1.6.4 | HTTP 522 |
| Kun Manga / Toonily | NPE in popular |
| Mangakakalot 1.6.28 | NPE in details |
| Mangahere 1.6.3 | `StringIndexOutOfBoundsException` in pageListParse |
| Manganato 1.6.25 | site 403 |
| MangaPill 1.6.1 | popular returns 0 (site changed) |
| MangaReader.site 1.6.41 | NPE |
| Weeb Central 1.6.27 | 403 with a non-browser UA, no chapters with a desktop UA |

Harness changes that came out of this: curl runs with `-g` (bracket URLs like
MangaDex's `contentRating[]` no longer trip globbing — this also made
CuuTruyen 1.6 pass) and `DEXVM_LANGS=en` selects languages for `apks` mode.

Shims added for EN: `ZonedDateTime/LocalDateTime/LocalDate.format(formatter)`,
`java.util.concurrent.locks.ReentrantReadWriteLock` (+Read/WriteLock).

### 1.6.x EN & VM follow-up (2026-11-25)

Five VM/bridge fixes targeting the remaining 1.6.x EN and cross-source gaps:

* **Jsoup `[attr~=regex]`**: Jsoup treats `~=` as a regex `find` rather than
  CSS whitespace-word matching. Plain literals now rewrite to `[attr*="..."]`
  and regex patterns split/filter with `fancy_regex` (including ancestor
  segments like `section[x-data~=scroll] > img`). Fixes **Weeb Central 1.6.27**
  (32 mangas / 1,199 chapters / 13 pages / 161 KB PNG) — 1.6 fixture gate is
  now **6/11**.
* **Bridge `image_response` fallback**: when `getImageRequest(Page)` is not
  overridden, fall back unconditionally to `imageRequest(Page)` (previously
  discarded when headers were empty) and seed the resolved `imageUrl` onto the
  `Page` object. Fixes **MangaDex 1.6.5** (20 mangas / 4 chapters / 26 pages /
  7.0 MB JPEG with `DEXVM_UA=okhttp/4.12.0`).
* **DEX `const/4 0` null references (`is_null_ref`)**: `HttpUrl$Builder.query`
  / `encodedQuery` / `fragment` / `addQueryParameter` / `setQueryParameter` and
  `StringBuilder.append(String)` / `append(CharSequence)` / `insert(int, String)`
  now treat DEX `Int(0)` null refs as `null` (`StringBuilder` appends `"null"`,
  `HttpUrl$Builder.query(null)` clears the query). Fixes **MangaFire 1.6.40**
  end-to-end (50 mangas / 475 chapters / 34 pages / 144 KB JPEG, including its
  VRF interceptor).
* **`Regex$Companion.escape(String)`**: read `args[1]` instead of `args[0]`
  (the Companion receiver). Unblocks Madara-based 1.6 sources like
  **Kun Manga Online 1.6.63** through `popular` (12 mangas).
* **Kotlin `Function5`–`Function22` + `FunctionN`**: registered in the VM
  interface table. Unblocks **MangaReader.site 1.6.41** through `sources` and
  its GraphQL `popular` request.
* **Bridge `QuickJs.evaluate`/`compile`/`execute`**: fixed instance-method
  argument indexing (`args[1]` instead of `args[0]`, which was `this` and
  silently evaluated `""`), and updated the Node test harness `evalJs` to run
  full JS programs via `node:vm`.
* **`StringsKt.indexOf` / `lastIndexOf` UTF-16 offsets**: converted start/result
  indices between JVM UTF-16 code units and Rust UTF-8 byte offsets (preventing
  shifted substrings and potential non-boundary panics on multi-byte pages).
  Together with the QuickJS fix, **Mangahere 1.6.3** passes end-to-end
  (70 mangas / 422 chapters / 16 pages / 176 KB JPEG).
* **`CloseableKt.closeFinally` / `ArrayDeque.<init>` / `runnable_post`**:
  switched remaining `args[i].is_null()` checks to `is_null_ref()` for DEX
  `const/4 0` null references.
* **ext-lib 1.6 `SManga.memo` / `SChapter.memo` round-tripping**: `Manga` and
  `Chapter` now carry optional JSON-encoded `memo` across `keiyoushi.rs` and
  `dexvm-bridge/src/engine.rs` (`popular`/`chapters` -> `details`/`chapters`/
  `pages`), and `SManga.getMemo()` / `SChapter.getMemo()` lazily return an
  empty non-null `JsonObject` by default. Unblocks **Kun Manga Online 1.6.63**
  end-to-end (12 mangas / 2,160 chapters / 9 pages / 115 KB WebP), removes
  `Asura Scans 1.6.72`'s `details` NPE (now reaches the site's 403), and
  unblocks **Mangakakalot 1.6.30** through `popular`/`details`/`chapters`.
* **`SequencesKt.mapIndexed` boxed index**: `Function2<Int, T, R>` erases to
  `invoke(Object, Object)Object` with a boxed `java.lang.Integer`, not
  `(ILjava/lang/Object;)Ljava/lang/Object;`. Fixes **Mangakakalot 1.6.30**
  `pages` — now passes end-to-end (24 mangas / 3,877 chapters / 96 pages /
  4.6 KB WebP).

### Expanded 1.6.x corpus & multi-region sweep (2026-11-25)

Added 10 newly passing 1.6.x APKs into `test/fixtures/` (24 total fixtures, 21
on ext-lib 1.6; `node test/run.mjs fixtures` is **24/24 ok**, and
`node test/run.mjs 1.6` is **16/21 full flow** with zero VM/bridge errors —
the 5 remaining failures are 3× HTTP 403, 1× HTTP 522, and 1× `MangaPill`
desktop-UA empty list):

* **MANGA Plus by SHUEISHA 1.6.69 (all/en)** — ✅ 100 / 6 / 19, 457.7 KB
  XOR-decrypted JPEG:
  * Dalvik `shl-long`/`shr-long`/`ushr-long` now accept `Int` shift counts
    (2nd operand) in `interpret.rs`.
  * `kotlinx.serialization.descriptors` reflection (`SerialKind`, `StructureKind`,
    `PrimitiveKind`, `PluginGeneratedSerialDescriptor.{getKind, getElementAnnotations,
    getElementDescriptor, getElementIndex, isElementOptional, isNullable, isInline}`),
    `AbstractDecoder` / `AbstractEncoder` defaults, `AbstractCollectionSerializer.merge`,
    `ByteArraySerializer`, `SerializersModuleBuildersKt.EmptySerializersModule`,
    `ProtoIntegerType` real `Native::Enum` constants + `values()`, and
    `java.lang.annotation.Annotation`.
  * `okio.BufferedSource` primitive reads (`readByte`, `readInt*`, `readLong*`,
    `readUtf8(J)`, `skip`), `okio.Buffer$UnsafeCursor` (`readAndWriteUnsafe`,
    `seek`, `next`, `close` with in-place writeback), and `Okio.buffer(Source)`
    draining custom DEX `ForwardingSource.read` subclasses.
* **Shonen Jump+ 1.6.3 (ja)** — ✅ 96 / 22 / 24, 1.76 MB Canvas-descrambled PNG:
  * Fixed static arg indexing in `BitmapFactory.decodeStream` / `decodeByteArray`,
    `Bitmap.compress` stream argument (`args[3]`, not `args[2]` quality), PNG
    fallback encoding for non-PNG `CompressFormat` (instead of raw RGBA stub),
    `Bitmap$Config` / `Bitmap$CompressFormat` enum descriptors, and `Rect.<init>`
    attaching `Native::Rect` onto `new-instance` objects.
* **Webtoons.com 1.6.5 (all/en)** — ✅ 30 / 5 / 114, 174 KB JPEG:
  * Added `java.text.DecimalFormat.format(Ljava/lang/Object;)Ljava/lang/String;`.
* **MangaBuddy / MangaK 1.6.40 (en)** — ✅ 24 / 269 / 34, 112.5 KB WebP:
  * `JsonObject` implements `java.util.Map`, `JsonArray` implements `List` and
    is handled by `coll_elems`, `JsonArray.<init>(List)` attaches `Native::Json`
    onto `new-instance` objects, `PrimitiveSerializer` boxes primitives into
    `Integer`/`Long`/`Float`/`Double` objects for `Number.*Value()`, and added
    `java.util.function.*` + `Map.computeIfAbsent`.
* **Rawkuma 1.6.44 (ja)** — ✅ 24 / 191 / 11, 108 KB WebP:
  * Added `kotlinx.coroutines.sync.Mutex` `owner: Object?` overloads (`lock`,
    `tryLock`, `unlock`).
* **nHentai.com 1.6.3 (all: zh/en/ja)** — ✅ verified end-to-end across all 3
  languages (18 mangas / 1 ch / 71–231 pg / 102–348 KB JPEG).

Unit test `vm::tests::ext16_shims_null_ref_regex_escape_and_jsoup_attr_regex`
locks in these behaviors without requiring an external APK.

### ext-lib 1.6 `configureHeaders()` & `defaultUserAgent` (2026-11-25, v0.2.1)

* **`HttpSource.getHeaders()` → `headersBuilder().build()`**: previously
  returned an empty `Headers` object without invoking `headersBuilder()`, so
  `KeiSource.headersBuilder()` (which sets `Referer: "$baseUrl/"` and calls
  `configureHeaders()`) and classic `HttpSource.headersBuilder()` overrides
  were silently skipped. Default `*Request()` helpers (`mangaDetailsRequest`,
  `chapterListRequest`, `pageListRequest`, `imageUrlRequest`, `imageRequest`)
  now also attach `source.getHeaders()` to match upstream Mihon `HttpSource.kt`.
* **Optional `open.defaultUserAgent`**: mirrors Mihon's
  `NetworkHelper.defaultUserAgentProvider()` and `UserAgentInterceptor` —
  seeds `HttpSource.headersBuilder()` and fills missing/empty `User-Agent`
  headers without overriding any `User-Agent` declared by the extension. When
  omitted, behavior stays no-UA by default.
* **`eu.kanade.tachiyomi.AppInfo.INSTANCE` + `getVersionCode()`**: exposed the
  Kotlin `object` singleton so `MangaDex` v1.6.5's `headersBuilder()` runs and
  emits its own `Tachiyomi` UA + `Extra` header instead of a browser UA.
* **New pinned fixture**: `tachiyomi-zh.manhuagui-v1.6.2.apk` (keiyoushi
  release `582615a`, SHA-256
  `d346f335b3211d26edb00d7b09ace3ed59758f2c1a16926fbf61fb57f2543728`) passes the
  full flow (42 mangas / 235 chapters / 230 pages / 178,932 B `image/webp`).
* **Offline unit test**: `test/headers.test.mjs` (`node --test test/headers.test.mjs`)
  verifies the SHA-256 pin, `configureHeaders()` propagation, `defaultUserAgent`
  precedence, classic `HttpSource` default behavior, and MangaDex's non-browser UA.

### Host synchronous `sleep(ms)` & timed wait shims (2026-11-25, v0.2.2)

* **`createDexvm({ sleep })` in `dexvm-host.js`**: optional synchronous
  `sleep(ms)` callback replaces busy-waiting in WASI `poll_oneoff` with a
  60 s safety cap (truncating and warning above 60 s). Supports multiple clock
  subscriptions (earliest deadline wins), both relative and `ABSTIME` flags,
  and a monotonic clock floor so `clock_time_get` never reads earlier than a
  scheduled `poll_oneoff` wakeup. Omitting `sleep` preserves the existing 2 s
  busy-wait behavior.
* **Timed wait shims routed through `std::thread::sleep` (→ WASI `poll_oneoff`)**:
  `Condition.awaitNanos(J)J`, `Condition.await(J, TimeUnit)Z`,
  `Object.wait(J)V`/`wait(JI)V`, and `CountDownLatch.await(J, TimeUnit)Z`
  (alongside existing `Thread.sleep`).
* **`kotlin.time.DurationUnit` enum variants**: fixed `DurationUnit` singletons
  so `MILLISECONDS` (1 ms), `SECONDS` (1,000 ms), `MINUTES` (60,000 ms),
  `HOURS` (3,600,000 ms), and `DAYS` (86,400,000 ms) no longer all scale by
  1,000 ms (which previously caused `RateLimitInterceptor`'s 10 s sliding
  window to expire in 10 ms).
* **Rate-limiting limitation without `sleep`**: both keiyoushi's
  `RateLimitInterceptor` (`core/src/main/kotlin/keiyoushi/network/RateLimit.kt`)
  and Mihon's legacy `RateLimitInterceptor`
  (`core/common/src/main/kotlin/eu/kanade/tachiyomi/network/interceptor/RateLimitInterceptor.kt`)
  loop and re-check `SystemClock.elapsedRealtime()` after waking, so a 2 s cap
  does not dispatch rate-limited requests early — however, extensions that call
  a one-shot `Thread.sleep(>2s)` without re-checking the clock will wake early
  (and busy-waiting burns 100% of one CPU core) when `sleep` is omitted.
* **Unit tests**: `test/sleep.test.mjs` verifies `Thread.sleep(3000)` with and
  without host `sleep`, the 60 s safety cap, multi-subscription `poll_oneoff` +
  `ABSTIME` + `clock_time_get` consistency, and `manhuagui` v1.6.2 15-call
  rate limiting (10 req / 10 s). `test/run.mjs` now supplies an `Atomics.wait`
  `sleep` implementation in Node.

### ext-lib 1.6 dedup, `mangaUpdate`, coroutines & shims (2026-11-26, v0.2.3)

1. **No duplicate HTTP requests in `details`/`chapters` + combined `mangaUpdate` op**:
   sources implementing `getMangaUpdate`/`fetchMangaUpdate` now go directly to
   the coroutine path (1 HTTP request instead of 3); legacy sources skip the
   `HttpSource` native `fetch*` stub unless overridden in DEX bytecode (1 HTTP
   request instead of 2). Added `mangaUpdate` op returning `{ manga, chapters }`
   in a single `getMangaUpdate` call.
2. **Non-blocking `GlobalScope.launch` + `DelayKt.delay` → host `sleep`**:
   detached `GlobalScope.launch` fire-and-forget jobs are dropped (returning an
   opaque `Job` without blocking the main op, eliminating Manhuagui's ~0.9 s
   background ajax overhead), while structured `coroutineScope { launch {} }`
   still runs inline; `DelayKt.delay` now delegates positive durations to
   `std::thread::sleep` (→ WASI `poll_oneoff` → `createDexvm({ sleep })`).
3. **`StringsKt.lineSequence(CharSequence)` + `Sequence.iterator()` + `JsonNull.INSTANCE`**:
   unblocks **WaManga v1.6.3** `popular` (24 mangas).
4. **`MatchResult.getDestructured()` + `MatchResult$Destructured.component1..10`**:
   unblocks **Desu v1.6.37** `popular` (24 mangas).
5. **`kotlinx.serialization` `BooleanSerializer` boxing**:
   `run_serializer` and `primitive_serializer_deserialize` now box booleans as
   `java.lang.Boolean` (`Native::BoolBox`) instead of `java.lang.Integer`, fixing
   `ClassCastException` on nullable `Boolean?` DTO fields (e.g. **XCOMIC v1.6.11**).
* **Offline repro tests**: `test/v023.test.mjs` covers all 5 fixes (6/6 passing;
  17/17 total unit tests).

### Background coroutine jobs & `runPending` (2026-11-26, v0.2.4)

* **Detached vs. structured concurrency**:
  * Detached launches (`GlobalScope.launch`, `CoroutineScope(...).launch`) are
    enqueued on the VM instance's pending queue rather than dropped or run
    synchronously during the main op. Because they execute later in the **same
    VM instance**, they share the cookie jar, `SharedPreferences`, and source
    instance fields just like `Dispatchers.IO` on Android.
  * Structured concurrency (`coroutineScope { launch {} }`, `supervisorScope`,
    `withContext`, `async`/`await`) continues to run inline.
* **`Job` lifecycle**: returned `Job` handles reflect `isActive` / `isCompleted`
  / `isCancelled`. Calling `cancel()` removes unstarted or suspended jobs from
  the pending queue; calling `join()` inside a main op runs the job inline to
  completion immediately.
* **`runPending` op & true `delay()` suspension**:
  * `call('runPending', { handle, maxJobs? })` returns
    `{ ran, remaining, nextDueMs? }`, running up to `maxJobs` currently due jobs
    (at least one when due).
  * Inside `runPending`, `DelayKt.delay(ms, cont)` returns a singleton
    `COROUTINE_SUSPENDED` token and stores the continuation + due timestamp
    (`BaseContinuationImpl` completion links are tracked across
    `SuspendLambda`/`ContinuationImpl`), allowing the worker to yield without
    blocking and resume from the continuation after `nextDueMs`.
  * Uncaught exceptions inside pending jobs are caught, logged via `host.log`,
    and never trap the VM instance or affect subsequent ops.
* **Tests**: `test/pending.test.mjs` covers (a) `manhuagui` v1.6.2 `mangaUpdate`
  + `runPending` true `delay(1000)` suspension → both ajax calls, (b) throwing
  job isolation, (c) `Job.join()` inline execution, and (d) `Job.cancel()`
  removal (4/4 passing; 21/21 total unit tests).

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
