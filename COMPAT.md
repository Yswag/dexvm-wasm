# Compatibility

Update this table on every release. "Passing" means
`popular → details → chapters → pages → fetchImage`, not just `open`.

## Verified

| Date | Release | dexvm | ext-lib (Mihon) | Corpus | Result |
|---|---|---|---|---|---|
| 2026-11-08 | v0.1.0 | 0.2.0 + patch | 1.4.x, 1.6.3–1.6.8 | `test/fixtures/` (5 APKs) | 5/5 open + sources; MangaPill 1.4.9 and Comic Fury 1.4.8 complete the full flow including images |

Raw output: `test/results/all.log`.

## Unsupported

| Generation | State | Missing |
|---|---|---|
| ext-lib **1.6.x** (current repo builds) | ⚠️ partial — see below | kotlinx.serialization coverage, jsoup/DOM edge cases, site-side challenges |
| ext-lib 1.4.x | ✅ works | — (Mihon 0.21 is the last major release supporting 1.4, and the repo stopped publishing it in 2026-10) |
| ext-lib 1.5.x | untested | no APKs on hand |

The 1.6 failures are not wasm-specific: the same APKs behave identically on
native dexvm 0.2.0, except that native builds turn panics into exceptions.

## Corpus policy

The guarantee is **"every APK in the corpus passes"**, not "every extension
works".

* Corpus = `test/fixtures/*.apk` plus an optional `test/corpus.json` for remote APKs.
* Record a SHA-256 per APK. Upstream rebuilds change versions; re-pinning is a
  deliberate act, not a daily chore.
* Target size: 10–30 sources actually in use. Steady-state cost ≈ 1–2 h/month.
* No work is required between releases; upstream churn does not affect pinned
  artifacts.

### 1.6.x progress (2026-11-09)

Work in progress; each row is `popular → details → chapters → pages`.

| Source | popular | details | chapters | pages | Blocked by |
|---|---|---|---|---|---|
| 动漫屋 dm5 (zh) | ✅ 70 | ✅ | ✅ 227 | ✅ 69 | — |
| Komiic (zh) | ✅ 30 | ❌ | — | — | `class not found: I` inside details deserialization |
| 漫画柜 manhuagui (zh) | ✅ 42 | ✅ | ✅ 235 | ❌ | the extension's JS-packer unpacker emits a malformed JSON string (VM string-op bug) |
| 包子漫画 baozimanhua (zh) | ❌ | — | — | — | site gatekeeper returns 403 before any parse |

Vendor shims added for 1.6 (see `vendor/dexvm`, marked `// wasm:`):
`Json.Default` singleton + inheritance, `JsonElementSerializer` (+`INSTANCE`),
`EnumSerializer.serialize`, `IntRange.iterator`, `DateTimeFormatter.parseCaseInsensitive`,
`Jsoup.parse(InputStream,…)`, relative selectors (`"> ul"`), `:contains/​:containsData`,
non-panicking `payload_of`/`str_of_jvalue`, primitive-safe `Intrinsics.areEqual`,
and native-dispatch diagnostics.
