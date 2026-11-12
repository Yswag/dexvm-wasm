//! Resolved classes, methods, and the shim-class registry.
//!
//! Shim classes supply the host-provided JVM surface (`java.lang.*`,
//! `java.util.*`, ...) that keiyoushi APKs reference but do not bundle.
//! A shim class has no bytecode: every method resolves to a native function.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use crate::dex::insn::Decoded;
use crate::dex::CodeItem;
use crate::vm::native;
use crate::vm::value::JValue;

pub const ACC_PUBLIC: u32 = 0x0001;
pub const ACC_PRIVATE: u32 = 0x0002;
pub const ACC_PROTECTED: u32 = 0x0004;
pub const ACC_STATIC: u32 = 0x0008;
pub const ACC_FINAL: u32 = 0x0010;
pub const ACC_SYNCHRONIZED: u32 = 0x0020;
pub const ACC_VOLATILE: u32 = 0x0040;
pub const ACC_TRANSIENT: u32 = 0x0080;
pub const ACC_NATIVE: u32 = 0x0100;
pub const ACC_INTERFACE: u32 = 0x0200;
pub const ACC_ABSTRACT: u32 = 0x0400;
pub const ACC_SYNTHETIC: u32 = 0x1000;
pub const ACC_ENUM: u32 = 0x4000;

#[derive(Debug, Clone)]
pub struct Method {
    /// Index into `Class::methods`.
    pub slot: u32,
    /// Owning class id.
    pub class: u32,
    /// Interned method name.
    pub name: u32,
    /// Interned full signature `(args)ret`, e.g. `(II)Ljava/lang/String;`.
    pub sig: u32,
    /// Interned return descriptor.
    pub ret: u32,
    /// Interned argument descriptors (excluding `this`).
    pub args: Vec<u32>,
    pub access_flags: u32,
    pub static_method: bool,
    /// Dex file (index into `Vm::dexes`) this method's bytecode/ids came from.
    pub dex_idx: u32,
    /// Present when this method is implemented natively.
    pub native_key: Option<(u32, u32, u32)>,
    /// Declared `native` in the dex (no code item, no JNI bridge).
    ///
    /// JNI is unsupported; invoking such a method raises a resolution error
    /// unless the host registered a shim for it first.
    pub native_decl: bool,
    pub code: Option<Arc<CodeItem>>,
    /// Decoded instructions (bytecode methods only).
    pub insns: OnceLock<Arc<Decoded>>,
}

impl Method {
    pub fn is_native(&self) -> bool {
        self.native_key.is_some()
    }
}

/// Lazily materialized static field value (e.g. `System.out`).
pub type ShimLazy = fn(&mut crate::vm::Vm) -> JValue;

#[derive(Debug, Clone, Copy)]
pub enum ShimValue {
    Const(JValue),
    Lazy(ShimLazy),
}

#[derive(Debug, Clone, Copy)]
pub struct ShimStaticDef {
    pub name: &'static str,
    pub ty: &'static str,
    pub value: ShimValue,
}

#[derive(Debug, Clone, Copy)]
pub struct ShimDef {
    pub desc: &'static str,
    pub super_desc: Option<&'static str>,
    pub interfaces: &'static [&'static str],
    pub flags: u32,
    pub statics: &'static [ShimStaticDef],
    /// Instance fields `(name, descriptor)` declared on the shim, so
    /// extension code can `iget`/`iput` them (e.g. Kotlin's
    /// `Ref$ObjectRef.element`). Offsets continue after the superclass's.
    pub instance_fields: &'static [(&'static str, &'static str)],
}

macro_rules! shim {
    ($desc:expr, $super_desc:expr, $interfaces:expr, $flags:expr) => {
        ShimDef {
            desc: $desc,
            super_desc: $super_desc,
            interfaces: $interfaces,
            flags: $flags,
            statics: &[],
            instance_fields: &[],
        }
    };
    ($desc:expr, $super_desc:expr, $interfaces:expr, $flags:expr, [$($s:expr),* $(,)?]) => {
        ShimDef {
            desc: $desc,
            super_desc: $super_desc,
            interfaces: $interfaces,
            flags: $flags,
            statics: &[$($s),*],
            instance_fields: &[],
        }
    };
    ($desc:expr, $super_desc:expr, $interfaces:expr, $flags:expr, [$($s:expr),* $(,)?], fields = [$(($fname:expr, $fty:expr)),* $(,)?]) => {
        ShimDef {
            desc: $desc,
            super_desc: $super_desc,
            interfaces: $interfaces,
            flags: $flags,
            statics: &[$($s),*],
            instance_fields: &[$(($fname, $fty)),*],
        }
    };
}

macro_rules! sdef {
    ($name:expr, $ty:expr, $value:expr) => {
        ShimStaticDef {
            name: $name,
            ty: $ty,
            value: $value,
        }
    };
}

/// Host-provided classes not present in extension dex files.
pub static SHIM_CLASSES: &[ShimDef] = &[
    shim!("Ljava/lang/Object;", None, &[], 0),
    shim!(
        "Ljava/io/Serializable;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/lang/Cloneable;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/lang/Comparable;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/lang/CharSequence;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/lang/Iterable;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/lang/reflect/AccessibleObject;",
        Some("Ljava/lang/Object;"),
        &[],
        ACC_PUBLIC | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/lang/reflect/Field;",
        Some("Ljava/lang/reflect/AccessibleObject;"),
        &[],
        ACC_PUBLIC
    ),
    // mihon extension host API (keiyoushi/Tachiyomi extension entry points)
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Leu/kanade/tachiyomi/source/SourceFactory;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Leu/kanade/tachiyomi/source/Source;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Leu/kanade/tachiyomi/source/ConfigurableSource;",
        Some("Leu/kanade/tachiyomi/source/Source;"),
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Leu/kanade/tachiyomi/source/online/HttpSource;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    // mihon extension network API (eu.kanade.tachiyomi.network.*)
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Leu/kanade/tachiyomi/network/NetworkHelper;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    // mihon source model classes (eu.kanade.tachiyomi.source.model.*)
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Leu/kanade/tachiyomi/source/model/SManga;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [sdef!(
            "Companion",
            "Leu/kanade/tachiyomi/source/model/SManga$Companion;",
            ShimValue::Lazy(native::lazy_smanga_companion)
        ),]
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Leu/kanade/tachiyomi/source/model/SManga$Companion;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Leu/kanade/tachiyomi/source/model/SChapter;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [sdef!(
            "Companion",
            "Leu/kanade/tachiyomi/source/model/SChapter$Companion;",
            ShimValue::Lazy(native::lazy_schapter_companion)
        ),]
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Leu/kanade/tachiyomi/source/model/SChapter$Companion;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Leu/kanade/tachiyomi/source/model/Page;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Leu/kanade/tachiyomi/source/model/MangasPage;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Leu/kanade/tachiyomi/source/model/FilterList;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Leu/kanade/tachiyomi/source/model/Filter;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Leu/kanade/tachiyomi/source/model/Filter$Header;",
        Some("Leu/kanade/tachiyomi/source/model/Filter;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Leu/kanade/tachiyomi/source/model/Filter$Separator;",
        Some("Leu/kanade/tachiyomi/source/model/Filter;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Leu/kanade/tachiyomi/source/model/Filter$Select;",
        Some("Leu/kanade/tachiyomi/source/model/Filter;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Leu/kanade/tachiyomi/source/model/Filter$CheckBox;",
        Some("Leu/kanade/tachiyomi/source/model/Filter;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Leu/kanade/tachiyomi/source/model/Filter$Sort;",
        Some("Leu/kanade/tachiyomi/source/model/Filter;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Leu/kanade/tachiyomi/source/model/Filter$Text;",
        Some("Leu/kanade/tachiyomi/source/model/Filter;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Leu/kanade/tachiyomi/source/model/Filter$TriState;",
        Some("Leu/kanade/tachiyomi/source/model/Filter;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Leu/kanade/tachiyomi/source/model/Filter$Group;",
        Some("Leu/kanade/tachiyomi/source/model/Filter;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Leu/kanade/tachiyomi/source/model/UpdateStrategy;",
        Some("Ljava/lang/Enum;"),
        &[],
        0,
        [sdef!(
            "ONLY_FETCH_ONCE",
            "Leu/kanade/tachiyomi/source/model/UpdateStrategy;",
            ShimValue::Lazy(native::lazy_update_strategy_once)
        ),]
    ),
    // org.jsoup host shims (parsed via dom_query)
    #[cfg(feature = "jsoup")]
    shim!(
        "Leu/kanade/tachiyomi/util/JsoupExtensionsKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    // Kotlin stdlib host shims (default-arg synthetic methods)
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/text/StringsKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/text/RegexOption;",
        Some("Ljava/lang/Enum;"),
        &[],
        ACC_PUBLIC | ACC_FINAL | ACC_ENUM,
        [
            sdef!(
                "UNIX_LINES",
                "Lkotlin/text/RegexOption;",
                ShimValue::Lazy(native::lazy_regex_option_unix_lines)
            ),
            sdef!(
                "COMMENTS",
                "Lkotlin/text/RegexOption;",
                ShimValue::Lazy(native::lazy_regex_option_comments)
            ),
            sdef!(
                "IGNORE_CASE",
                "Lkotlin/text/RegexOption;",
                ShimValue::Lazy(native::lazy_regex_option_ignore_case)
            ),
            sdef!(
                "MULTILINE",
                "Lkotlin/text/RegexOption;",
                ShimValue::Lazy(native::lazy_regex_option_multiline)
            ),
            sdef!(
                "DOT_MATCHES_ALL",
                "Lkotlin/text/RegexOption;",
                ShimValue::Lazy(native::lazy_regex_option_dot_matches_all)
            ),
            sdef!(
                "LITERAL",
                "Lkotlin/text/RegexOption;",
                ShimValue::Lazy(native::lazy_regex_option_literal)
            ),
        ]
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/text/Charsets;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [
            sdef!(
                "UTF_8",
                "Ljava/nio/charset/Charset;",
                ShimValue::Lazy(native::lazy_charset_utf8)
            ),
            sdef!(
                "ISO_8859_1",
                "Ljava/nio/charset/Charset;",
                ShimValue::Lazy(native::lazy_charset_iso)
            ),
            sdef!(
                "US_ASCII",
                "Ljava/nio/charset/Charset;",
                ShimValue::Lazy(native::lazy_charset_ascii)
            ),
        ]
    ),
    #[cfg(feature = "jsoup")]
    shim!("Lorg/jsoup/Jsoup;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "jsoup")]
    shim!(
        "Lorg/jsoup/nodes/Document;",
        Some("Lorg/jsoup/nodes/Element;"),
        &[],
        0
    ),
    #[cfg(feature = "jsoup")]
    shim!(
        "Lorg/jsoup/nodes/Element;",
        Some("Lorg/jsoup/nodes/Node;"),
        &[],
        0
    ),
    #[cfg(feature = "jsoup")]
    shim!(
        "Lorg/jsoup/select/Elements;",
        Some("Ljava/util/AbstractCollection;"),
        &[],
        0
    ),
    // okhttp host shims
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/Interceptor;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/Interceptor$Chain;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/OkHttpClient;",
        Some("Ljava/lang/Object;"),
        &["Ljava/io/Closeable;", "Ljava/lang/Cloneable;"],
        0
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/OkHttpClient$Builder;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Leu/kanade/tachiyomi/network/interceptor/UncaughtExceptionInterceptor;",
        Some("Lokhttp3/Interceptor;"),
        &[],
        0
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Leu/kanade/tachiyomi/network/interceptor/UserAgentInterceptor;",
        Some("Lokhttp3/Interceptor;"),
        &[],
        0
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Leu/kanade/tachiyomi/network/interceptor/CloudflareInterceptor;",
        Some("Lokhttp3/Interceptor;"),
        &[],
        0
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/CompressionInterceptor;",
        Some("Lokhttp3/Interceptor;"),
        &[],
        0
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/CompressionInterceptor$DecompressionAlgorithm;",
        None,
        &[],
        0
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/brotli/BrotliInterceptor;",
        Some("Lokhttp3/Interceptor;"),
        &[],
        0
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/brotli/Brotli;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [sdef!(
            "INSTANCE",
            "Lokhttp3/brotli/Brotli;",
            ShimValue::Lazy(native::lazy_brotli_inst)
        )]
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/Gzip;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [sdef!(
            "INSTANCE",
            "Lokhttp3/Gzip;",
            ShimValue::Lazy(native::lazy_gzip_inst)
        )]
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/zstd/Zstd;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [sdef!(
            "INSTANCE",
            "Lokhttp3/zstd/Zstd;",
            ShimValue::Lazy(native::lazy_zstd_inst)
        )]
    ),
    #[cfg(feature = "okhttp")]
    shim!("Lokhttp3/FormBody;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "okhttp")]
    shim!("Lokio/Okio;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokio/Source;",
        None,
        &["Ljava/io/Closeable;"],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokio/BufferedSource;",
        None,
        &["Lokio/Source;", "Ljava/io/Closeable;"],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokio/Buffer;",
        Some("Ljava/lang/Object;"),
        &["Lokio/BufferedSource;", "Ljava/io/Closeable;"],
        0
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokio/ByteString;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [sdef!(
            "Companion",
            "Lokio/ByteString$Companion;",
            ShimValue::Lazy(native::lazy_byte_string_companion)
        )]
    ),
    #[cfg(feature = "okhttp")]
    shim!("Lokio/ByteStreams;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "okhttp")]
    shim!("Lokio/ByteStreamsKt;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/FormBody$Builder;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/HttpUrl;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [sdef!(
            "Companion",
            "Lokhttp3/HttpUrl$Companion;",
            ShimValue::Lazy(native::lazy_http_url_companion)
        ),]
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/HttpUrl$Companion;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/HttpUrl$Builder;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/MediaType;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [sdef!(
            "Companion",
            "Lokhttp3/MediaType$Companion;",
            ShimValue::Lazy(native::lazy_media_type_companion)
        ),]
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/MediaType$Companion;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/Headers;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [sdef!(
            "Companion",
            "Lokhttp3/Headers$Companion;",
            ShimValue::Lazy(native::lazy_headers_companion)
        )]
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/RequestBody;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [sdef!(
            "Companion",
            "Lokhttp3/RequestBody$Companion;",
            ShimValue::Lazy(native::lazy_request_body_companion)
        )]
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/RequestBody$Companion;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/CacheControl;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [
            sdef!(
                "FORCE_NETWORK",
                "Lokhttp3/CacheControl;",
                ShimValue::Lazy(native::lazy_cache_control_force_network)
            ),
            sdef!(
                "FORCE_CACHE",
                "Lokhttp3/CacheControl;",
                ShimValue::Lazy(native::lazy_cache_control_force_cache)
            ),
        ]
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/Request$Builder;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "okhttp")]
    shim!("Lokhttp3/Request;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "okhttp")]
    shim!("Lokhttp3/Call;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/Response;",
        Some("Ljava/lang/Object;"),
        &["Ljava/io/Closeable;"],
        0
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/ResponseBody;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [sdef!(
            "Companion",
            "Lokhttp3/ResponseBody$Companion;",
            ShimValue::Lazy(native::lazy_response_body_companion)
        ),]
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Leu/kanade/tachiyomi/network/RequestsKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    // android framework shims
    #[cfg(feature = "android")]
    shim!(
        "Landroid/os/Build;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/os/Build$VERSION;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [
            sdef!("SDK_INT", "I", ShimValue::Const(JValue::Int(34))),
            sdef!(
                "RELEASE",
                "Ljava/lang/String;",
                ShimValue::Lazy(native::android::lazy_build_release)
            ),
            sdef!(
                "CODENAME",
                "Ljava/lang/String;",
                ShimValue::Lazy(native::android::lazy_build_codename)
            ),
        ]
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/content/Context;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/content/ContextWrapper;",
        Some("Landroid/content/Context;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/app/Activity;",
        Some("Landroid/content/ContextWrapper;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/app/Application;",
        Some("Landroid/content/ContextWrapper;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/content/ActivityNotFoundException;",
        Some("Ljava/lang/RuntimeException;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/content/Intent;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/content/SharedPreferences;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "android")]
    shim!("Landroid/net/Uri;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "android")]
    shim!("Landroid/os/Bundle;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/os/SystemClock;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!("Landroid/util/Log;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/webkit/CookieManager;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroidx/preference/Preference;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroidx/preference/PreferenceScreen;",
        Some("Landroidx/preference/Preference;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroidx/preference/SwitchPreferenceCompat;",
        Some("Landroidx/preference/Preference;"),
        &[],
        0
    ),
    shim!(
        "Ljava/lang/String;",
        Some("Ljava/lang/Object;"),
        &[
            "Ljava/io/Serializable;",
            "Ljava/lang/Comparable;",
            "Ljava/lang/CharSequence;"
        ],
        0
    ),
    shim!(
        "Ljava/lang/StringBuilder;",
        Some("Ljava/lang/Object;"),
        &["Ljava/io/Serializable;", "Ljava/lang/CharSequence;"],
        0
    ),
    shim!(
        "Ljava/lang/Class;",
        Some("Ljava/lang/Object;"),
        &[
            "Ljava/io/Serializable;",
            "Ljava/lang/reflect/GenericDeclaration;",
            "Ljava/lang/reflect/Type;",
            "Ljava/lang/reflect/AnnotatedElement;"
        ],
        0
    ),
    shim!(
        "Ljava/lang/Throwable;",
        Some("Ljava/lang/Object;"),
        &["Ljava/io/Serializable;"],
        0
    ),
    shim!(
        "Ljava/lang/Exception;",
        Some("Ljava/lang/Throwable;"),
        &[],
        0
    ),
    shim!(
        "Ljava/lang/RuntimeException;",
        Some("Ljava/lang/Exception;"),
        &[],
        0
    ),
    shim!("Ljava/lang/Error;", Some("Ljava/lang/Throwable;"), &[], 0),
    shim!(
        "Ljava/lang/AssertionError;",
        Some("Ljava/lang/Error;"),
        &[],
        0
    ),
    shim!(
        "Ljava/lang/StackOverflowError;",
        Some("Ljava/lang/Error;"),
        &[],
        0
    ),
    shim!(
        "Ljava/lang/OutOfMemoryError;",
        Some("Ljava/lang/Error;"),
        &[],
        0
    ),
    shim!(
        "Ljava/lang/NullPointerException;",
        Some("Ljava/lang/RuntimeException;"),
        &[],
        0
    ),
    shim!(
        "Ljava/lang/ArithmeticException;",
        Some("Ljava/lang/RuntimeException;"),
        &[],
        0
    ),
    shim!(
        "Ljava/lang/IllegalArgumentException;",
        Some("Ljava/lang/RuntimeException;"),
        &[],
        0
    ),
    shim!(
        "Ljava/lang/IllegalStateException;",
        Some("Ljava/lang/RuntimeException;"),
        &[],
        0
    ),
    shim!(
        "Ljava/lang/NumberFormatException;",
        Some("Ljava/lang/IllegalArgumentException;"),
        &[],
        0
    ),
    shim!(
        "Ljava/lang/UnsupportedOperationException;",
        Some("Ljava/lang/RuntimeException;"),
        &[],
        0
    ),
    shim!(
        "Ljava/lang/IndexOutOfBoundsException;",
        Some("Ljava/lang/RuntimeException;"),
        &[],
        0
    ),
    shim!(
        "Ljava/lang/ArrayIndexOutOfBoundsException;",
        Some("Ljava/lang/IndexOutOfBoundsException;"),
        &[],
        0
    ),
    shim!(
        "Ljava/lang/StringIndexOutOfBoundsException;",
        Some("Ljava/lang/IndexOutOfBoundsException;"),
        &[],
        0
    ),
    shim!(
        "Ljava/lang/ClassCastException;",
        Some("Ljava/lang/RuntimeException;"),
        &[],
        0
    ),
    shim!(
        "Ljava/lang/NegativeArraySizeException;",
        Some("Ljava/lang/RuntimeException;"),
        &[],
        0
    ),
    shim!(
        "Ljava/util/NoSuchElementException;",
        Some("Ljava/lang/RuntimeException;"),
        &[],
        0
    ),
    shim!(
        "Ljava/lang/NoSuchMethodError;",
        Some("Ljava/lang/Error;"),
        &[],
        0
    ),
    shim!(
        "Ljava/lang/NoClassDefFoundError;",
        Some("Ljava/lang/Error;"),
        &[],
        0
    ),
    shim!(
        "Ljava/lang/ClassNotFoundException;",
        Some("Ljava/lang/Exception;"),
        &[],
        0
    ),
    shim!(
        "Ljava/io/IOException;",
        Some("Ljava/lang/Exception;"),
        &[],
        0
    ),
    shim!(
        "Ljava/net/MalformedURLException;",
        Some("Ljava/io/IOException;"),
        &[],
        0
    ),
    shim!(
        "Ljava/lang/InterruptedException;",
        Some("Ljava/lang/Exception;"),
        &[],
        0
    ),
    shim!(
        "Ljava/io/InputStream;",
        Some("Ljava/lang/Object;"),
        &["Ljava/io/Closeable;"],
        0
    ),
    shim!(
        "Ljava/io/ByteArrayInputStream;",
        Some("Ljava/io/InputStream;"),
        &[],
        0
    ),
    shim!(
        "Ljava/lang/SecurityException;",
        Some("Ljava/lang/RuntimeException;"),
        &[],
        0
    ),
    shim!(
        "Ljava/lang/Enum;",
        Some("Ljava/lang/Object;"),
        &["Ljava/lang/Comparable;", "Ljava/io/Serializable;"],
        0
    ),
    shim!(
        "Ljava/lang/System;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [
            sdef!(
                "out",
                "Ljava/io/PrintStream;",
                ShimValue::Lazy(native::lazy_print_stream)
            ),
            sdef!(
                "err",
                "Ljava/io/PrintStream;",
                ShimValue::Lazy(native::lazy_print_stream)
            ),
        ]
    ),
    shim!(
        "Ljava/io/PrintStream;",
        Some("Ljava/lang/Object;"),
        &["Ljava/lang/Appendable;", "Ljava/io/Closeable;"],
        0
    ),
    shim!("Ljava/lang/Math;", Some("Ljava/lang/Object;"), &[], 0),
    shim!(
        "Ljava/lang/Integer;",
        Some("Ljava/lang/Number;"),
        &["Ljava/lang/Comparable;"],
        0,
        [
            sdef!(
                "TYPE",
                "Ljava/lang/Class;",
                ShimValue::Lazy(native::lazy_int_type)
            ),
            sdef!("MIN_VALUE", "I", ShimValue::Const(JValue::Int(i32::MIN))),
            sdef!("MAX_VALUE", "I", ShimValue::Const(JValue::Int(i32::MAX))),
        ]
    ),
    shim!(
        "Ljava/lang/Long;",
        Some("Ljava/lang/Number;"),
        &["Ljava/lang/Comparable;"],
        0,
        [
            sdef!(
                "TYPE",
                "Ljava/lang/Class;",
                ShimValue::Lazy(native::lazy_long_type)
            ),
            sdef!("MIN_VALUE", "J", ShimValue::Const(JValue::Long(i64::MIN))),
            sdef!("MAX_VALUE", "J", ShimValue::Const(JValue::Long(i64::MAX))),
        ]
    ),
    shim!(
        "Ljava/lang/Short;",
        Some("Ljava/lang/Number;"),
        &["Ljava/lang/Comparable;"],
        0,
        [
            sdef!(
                "TYPE",
                "Ljava/lang/Class;",
                ShimValue::Lazy(native::lazy_short_type)
            ),
            sdef!(
                "MIN_VALUE",
                "S",
                ShimValue::Const(JValue::Int(i16::MIN as i32))
            ),
            sdef!(
                "MAX_VALUE",
                "S",
                ShimValue::Const(JValue::Int(i16::MAX as i32))
            ),
        ]
    ),
    shim!(
        "Ljava/lang/Byte;",
        Some("Ljava/lang/Number;"),
        &["Ljava/lang/Comparable;"],
        0,
        [
            sdef!(
                "TYPE",
                "Ljava/lang/Class;",
                ShimValue::Lazy(native::lazy_byte_type)
            ),
            sdef!(
                "MIN_VALUE",
                "B",
                ShimValue::Const(JValue::Int(i8::MIN as i32))
            ),
            sdef!(
                "MAX_VALUE",
                "B",
                ShimValue::Const(JValue::Int(i8::MAX as i32))
            ),
        ]
    ),
    shim!(
        "Ljava/lang/Character;",
        Some("Ljava/lang/Object;"),
        &["Ljava/lang/Comparable;"],
        0,
        [
            sdef!(
                "TYPE",
                "Ljava/lang/Class;",
                ShimValue::Lazy(native::lazy_char_type)
            ),
            sdef!("MIN_VALUE", "C", ShimValue::Const(JValue::Int(0))),
            sdef!("MAX_VALUE", "C", ShimValue::Const(JValue::Int(0xFFFF))),
        ]
    ),
    shim!(
        "Ljava/lang/Boolean;",
        Some("Ljava/lang/Object;"),
        &["Ljava/lang/Comparable;"],
        0,
        [
            sdef!(
                "TYPE",
                "Ljava/lang/Class;",
                ShimValue::Lazy(native::lazy_bool_type)
            ),
            sdef!(
                "TRUE",
                "Ljava/lang/Boolean;",
                ShimValue::Lazy(native::lazy_bool_true)
            ),
            sdef!(
                "FALSE",
                "Ljava/lang/Boolean;",
                ShimValue::Lazy(native::lazy_bool_false)
            ),
        ]
    ),
    shim!(
        "Ljava/lang/Float;",
        Some("Ljava/lang/Number;"),
        &["Ljava/lang/Comparable;"],
        0,
        [
            sdef!(
                "TYPE",
                "Ljava/lang/Class;",
                ShimValue::Lazy(native::lazy_float_type)
            ),
            sdef!(
                "MIN_VALUE",
                "F",
                ShimValue::Const(JValue::Float(f32::MIN_POSITIVE))
            ),
            sdef!("MAX_VALUE", "F", ShimValue::Const(JValue::Float(f32::MAX))),
            sdef!(
                "POSITIVE_INFINITY",
                "F",
                ShimValue::Const(JValue::Float(f32::INFINITY))
            ),
            sdef!(
                "NEGATIVE_INFINITY",
                "F",
                ShimValue::Const(JValue::Float(f32::NEG_INFINITY))
            ),
            sdef!("NaN", "F", ShimValue::Const(JValue::Float(f32::NAN))),
        ]
    ),
    shim!(
        "Ljava/lang/Double;",
        Some("Ljava/lang/Number;"),
        &["Ljava/lang/Comparable;"],
        0,
        [
            sdef!(
                "TYPE",
                "Ljava/lang/Class;",
                ShimValue::Lazy(native::lazy_double_type)
            ),
            sdef!(
                "MIN_VALUE",
                "D",
                ShimValue::Const(JValue::Double(f64::MIN_POSITIVE))
            ),
            sdef!("MAX_VALUE", "D", ShimValue::Const(JValue::Double(f64::MAX))),
            sdef!(
                "POSITIVE_INFINITY",
                "D",
                ShimValue::Const(JValue::Double(f64::INFINITY))
            ),
            sdef!(
                "NEGATIVE_INFINITY",
                "D",
                ShimValue::Const(JValue::Double(f64::NEG_INFINITY))
            ),
            sdef!("NaN", "D", ShimValue::Const(JValue::Double(f64::NAN))),
        ]
    ),
    shim!(
        "Ljava/lang/Number;",
        Some("Ljava/lang/Object;"),
        &["Ljava/io/Serializable;"],
        0
    ),
    shim!(
        "Ljava/lang/StackTraceElement;",
        Some("Ljava/lang/Object;"),
        &["Ljava/io/Serializable;"],
        0
    ),
    shim!("Ljava/lang/Thread;", Some("Ljava/lang/Object;"), &[], 0),
    shim!("Ljava/lang/Thread$State;", Some("Ljava/lang/Enum;"), &[], 0),
    shim!(
        "Ljava/security/MessageDigest;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/security/SecureRandom;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/security/Key;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/security/spec/AlgorithmParameterSpec;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!("Ljavax/crypto/Cipher;", Some("Ljava/lang/Object;"), &[], 0),
    shim!(
        "Ljavax/crypto/spec/SecretKeySpec;",
        Some("Ljava/lang/Object;"),
        &[
            "Ljava/security/Key;",
            "Ljava/security/spec/AlgorithmParameterSpec;"
        ],
        0
    ),
    shim!(
        "Ljavax/crypto/spec/GCMParameterSpec;",
        Some("Ljava/lang/Object;"),
        &["Ljava/security/spec/AlgorithmParameterSpec;"],
        0
    ),
    shim!(
        "Ljava/util/Collection;",
        Some("Ljava/lang/Iterable;"),
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/util/List;",
        Some("Ljava/util/Collection;"),
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/util/Set;",
        Some("Ljava/util/Collection;"),
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/util/SortedSet;",
        Some("Ljava/util/Set;"),
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/util/NavigableSet;",
        Some("Ljava/util/SortedSet;"),
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/util/Map;",
        Some("Ljava/lang/Object;"),
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/util/SortedMap;",
        Some("Ljava/util/Map;"),
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/util/NavigableMap;",
        Some("Ljava/util/SortedMap;"),
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/util/Map$Entry;",
        Some("Ljava/lang/Object;"),
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/util/Iterator;",
        Some("Ljava/lang/Object;"),
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/util/ListIterator;",
        Some("Ljava/util/Iterator;"),
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/util/Comparator;",
        Some("Ljava/lang/Object;"),
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/util/RandomAccess;",
        Some("Ljava/lang/Object;"),
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/util/ArrayList;",
        Some("Ljava/util/AbstractList;"),
        &[
            "Ljava/util/List;",
            "Ljava/util/RandomAccess;",
            "Ljava/lang/Cloneable;",
            "Ljava/io/Serializable;"
        ],
        0
    ),
    shim!(
        "Ljava/util/AbstractList;",
        Some("Ljava/util/AbstractCollection;"),
        &["Ljava/util/List;"],
        0
    ),
    shim!(
        "Ljava/util/AbstractCollection;",
        Some("Ljava/util/Collection;"),
        &[],
        0
    ),
    shim!("Ljava/util/AbstractMap;", Some("Ljava/util/Map;"), &[], 0),
    shim!(
        "Ljava/util/AbstractSet;",
        Some("Ljava/util/AbstractCollection;"),
        &["Ljava/util/Set;"],
        0
    ),
    shim!(
        "Ljava/util/HashMap;",
        Some("Ljava/util/AbstractMap;"),
        &[
            "Ljava/util/Map;",
            "Ljava/lang/Cloneable;",
            "Ljava/io/Serializable;"
        ],
        0
    ),
    shim!(
        "Ljava/util/LinkedHashMap;",
        Some("Ljava/util/HashMap;"),
        &["Ljava/util/Map;"],
        0
    ),
    shim!(
        "Ljava/util/HashSet;",
        Some("Ljava/util/AbstractSet;"),
        &[
            "Ljava/util/Set;",
            "Ljava/lang/Cloneable;",
            "Ljava/io/Serializable;"
        ],
        0
    ),
    shim!(
        "Ljava/util/LinkedHashSet;",
        Some("Ljava/util/HashSet;"),
        &[
            "Ljava/util/Set;",
            "Ljava/lang/Cloneable;",
            "Ljava/io/Serializable;"
        ],
        0
    ),
    shim!(
        "Ljava/util/Collections;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!("Ljava/util/Arrays;", Some("Ljava/lang/Object;"), &[], 0),
    shim!("Ljava/util/Objects;", Some("Ljava/lang/Object;"), &[], 0),
    shim!(
        "Ljava/util/Locale;",
        Some("Ljava/lang/Object;"),
        &["Ljava/io/Serializable;", "Ljava/lang/Cloneable;"],
        0,
        [
            sdef!(
                "ROOT",
                "Ljava/util/Locale;",
                ShimValue::Lazy(native::lazy_opaque_locale)
            ),
            sdef!(
                "ENGLISH",
                "Ljava/util/Locale;",
                ShimValue::Lazy(native::lazy_opaque_locale)
            ),
            sdef!(
                "US",
                "Ljava/util/Locale;",
                ShimValue::Lazy(native::lazy_locale_us)
            ),
            sdef!(
                "UK",
                "Ljava/util/Locale;",
                ShimValue::Lazy(native::lazy_locale_uk)
            ),
            sdef!(
                "CANADA",
                "Ljava/util/Locale;",
                ShimValue::Lazy(native::lazy_locale_canada)
            ),
            sdef!(
                "JAPAN",
                "Ljava/util/Locale;",
                ShimValue::Lazy(native::lazy_locale_japan)
            ),
            sdef!(
                "KOREA",
                "Ljava/util/Locale;",
                ShimValue::Lazy(native::lazy_locale_korea)
            ),
            sdef!(
                "CHINA",
                "Ljava/util/Locale;",
                ShimValue::Lazy(native::lazy_locale_china)
            ),
            sdef!(
                "CHINESE",
                "Ljava/util/Locale;",
                ShimValue::Lazy(native::lazy_locale_china)
            ),
            sdef!(
                "FRANCE",
                "Ljava/util/Locale;",
                ShimValue::Lazy(native::lazy_locale_france)
            ),
            sdef!(
                "GERMANY",
                "Ljava/util/Locale;",
                ShimValue::Lazy(native::lazy_locale_germany)
            ),
            sdef!(
                "ITALY",
                "Ljava/util/Locale;",
                ShimValue::Lazy(native::lazy_locale_italy)
            ),
        ]
    ),
    shim!(
        "Ljava/util/TimeZone;",
        Some("Ljava/lang/Object;"),
        &["Ljava/io/Serializable;", "Ljava/lang/Cloneable;"],
        0
    ),
    shim!(
        "Ljava/util/ArrayDeque;",
        Some("Ljava/util/AbstractCollection;"),
        &[
            "Ljava/util/Deque;",
            "Ljava/lang/Cloneable;",
            "Ljava/io/Serializable;"
        ],
        0
    ),
    shim!(
        "Ljava/util/Deque;",
        Some("Ljava/util/Collection;"),
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!("Ljava/text/DateFormat;", Some("Ljava/lang/Object;"), &[], 0),
    shim!(
        "Ljava/text/SimpleDateFormat;",
        Some("Ljava/text/DateFormat;"),
        &[],
        0
    ),
    shim!(
        "Ljava/text/ParsePosition;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/util/concurrent/locks/Lock;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/util/concurrent/locks/ReentrantLock;",
        Some("Ljava/lang/Object;"),
        &[
            "Ljava/util/concurrent/locks/Lock;",
            "Ljava/io/Serializable;"
        ],
        0
    ),
    shim!(
        "Ljava/util/concurrent/locks/Condition;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/nio/charset/Charset;",
        Some("Ljava/lang/Object;"),
        &["Ljava/io/Serializable;", "Ljava/lang/Comparable;"],
        0
    ),
    shim!(
        "Ljava/nio/charset/StandardCharsets;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [
            sdef!(
                "UTF_8",
                "Ljava/nio/charset/Charset;",
                ShimValue::Lazy(native::lazy_charset_utf8)
            ),
            sdef!(
                "ISO_8859_1",
                "Ljava/nio/charset/Charset;",
                ShimValue::Lazy(native::lazy_charset_iso)
            ),
            sdef!(
                "US_ASCII",
                "Ljava/nio/charset/Charset;",
                ShimValue::Lazy(native::lazy_charset_ascii)
            ),
        ]
    ),
    shim!(
        "Ljava/util/regex/Pattern;",
        Some("Ljava/lang/Object;"),
        &["Ljava/io/Serializable;"],
        0
    ),
    shim!(
        "Ljava/util/regex/Matcher;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/util/Random;",
        Some("Ljava/lang/Object;"),
        &["Ljava/io/Serializable;"],
        0
    ),
    shim!(
        "Ljava/util/Date;",
        Some("Ljava/lang/Object;"),
        &[
            "Ljava/io/Serializable;",
            "Ljava/lang/Cloneable;",
            "Ljava/lang/Comparable;"
        ],
        0
    ),
    shim!(
        "Ljava/lang/reflect/GenericDeclaration;",
        Some("Ljava/lang/Object;"),
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/lang/reflect/Type;",
        Some("Ljava/lang/Object;"),
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/lang/reflect/AnnotatedElement;",
        Some("Ljava/lang/Object;"),
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/lang/Appendable;",
        Some("Ljava/lang/Object;"),
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/io/Closeable;",
        Some("Ljava/lang/Object;"),
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/io/Flushable;",
        Some("Ljava/lang/Object;"),
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    // kotlin stdlib host shims
    shim!(
        "Lkotlin/Lazy;",
        None,
        &["Ljava/io/Serializable;"],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Lkotlin/SynchronizedLazyImpl;",
        Some("Ljava/lang/Object;"),
        &["Lkotlin/Lazy;", "Ljava/io/Serializable;"],
        0
    ),
    shim!(
        "Lkotlin/jvm/functions/Function0;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Lkotlin/jvm/functions/Function1;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!("Lkotlin/LazyKt;", Some("Ljava/lang/Object;"), &[], 0),
    shim!(
        "Lkotlin/LazyThreadSafetyMode;",
        Some("Ljava/lang/Enum;"),
        &[],
        ACC_PUBLIC | ACC_FINAL | ACC_ENUM,
        [
            sdef!(
                "SYNCHRONIZED",
                "Lkotlin/LazyThreadSafetyMode;",
                ShimValue::Lazy(native::lazy_lazy_mode_synchronized)
            ),
            sdef!(
                "PUBLICATION",
                "Lkotlin/LazyThreadSafetyMode;",
                ShimValue::Lazy(native::lazy_lazy_mode_publication)
            ),
            sdef!(
                "NONE",
                "Lkotlin/LazyThreadSafetyMode;",
                ShimValue::Lazy(native::lazy_lazy_mode_none)
            ),
        ]
    ),
    shim!(
        "Lkotlin/time/Duration;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [sdef!(
            "Companion",
            "Lkotlin/time/Duration$Companion;",
            ShimValue::Lazy(native::lazy_duration_companion)
        ),]
    ),
    shim!(
        "Lkotlin/time/Duration$Companion;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Lkotlin/time/DurationUnit;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [
            sdef!(
                "NANOSECONDS",
                "Lkotlin/time/DurationUnit;",
                ShimValue::Lazy(native::lazy_duration_unit_millis)
            ),
            sdef!(
                "MICROSECONDS",
                "Lkotlin/time/DurationUnit;",
                ShimValue::Lazy(native::lazy_duration_unit_millis)
            ),
            sdef!(
                "MILLISECONDS",
                "Lkotlin/time/DurationUnit;",
                ShimValue::Lazy(native::lazy_duration_unit_millis)
            ),
            sdef!(
                "SECONDS",
                "Lkotlin/time/DurationUnit;",
                ShimValue::Lazy(native::lazy_duration_unit_seconds)
            ),
            sdef!(
                "MINUTES",
                "Lkotlin/time/DurationUnit;",
                ShimValue::Lazy(native::lazy_duration_unit_millis)
            ),
            sdef!(
                "HOURS",
                "Lkotlin/time/DurationUnit;",
                ShimValue::Lazy(native::lazy_duration_unit_hours)
            ),
            sdef!(
                "DAYS",
                "Lkotlin/time/DurationUnit;",
                ShimValue::Lazy(native::lazy_duration_unit_days)
            ),
        ]
    ),
    shim!(
        "Lkotlin/time/DurationKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Lkotlin/text/Regex;",
        Some("Ljava/lang/Object;"),
        &["Ljava/io/Serializable;"],
        0,
        [sdef!(
            "Companion",
            "Lkotlin/text/Regex$Companion;",
            ShimValue::Lazy(native::lazy_regex_companion)
        )]
    ),
    shim!(
        "Lkotlin/collections/CollectionsKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Lkotlin/collections/IntIterator;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Lkotlin/ranges/IntRange;",
        Some("Lkotlin/ranges/IntProgression;"),
        &[],
        0
    ),
    shim!(
        "Lkotlin/comparisons/ComparisonsKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Lkotlin/jvm/internal/Intrinsics;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Lkotlin/Unit;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [sdef!(
            "INSTANCE",
            "Lkotlin/Unit;",
            ShimValue::Lazy(native::lazy_unit_instance)
        ),]
    ),
    shim!(
        "Lkotlinx/coroutines/GlobalScope;",
        Some("Ljava/lang/Object;"),
        &["Lkotlinx/coroutines/CoroutineScope;"],
        0,
        [sdef!(
            "INSTANCE",
            "Lkotlinx/coroutines/GlobalScope;",
            ShimValue::Lazy(native::lazy_global_scope)
        ),]
    ),
    shim!(
        "Lkotlinx/coroutines/CoroutineScope;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Lkotlin/coroutines/CoroutineContext;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Lkotlinx/coroutines/CoroutineDispatcher;",
        Some("Ljava/lang/Object;"),
        &["Lkotlin/coroutines/CoroutineContext;"],
        ACC_ABSTRACT
    ),
    shim!(
        "Lkotlinx/coroutines/Job;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Lkotlin/coroutines/jvm/internal/SuspendLambda;",
        Some("Lkotlin/coroutines/jvm/internal/ContinuationImpl;"),
        &[],
        0
    ),
    shim!(
        "Lkotlin/coroutines/jvm/internal/ContinuationImpl;",
        Some("Ljava/lang/Object;"),
        &["Lkotlin/coroutines/Continuation;"],
        0
    ),
    shim!(
        "Lkotlin/coroutines/Continuation;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Lkotlin/coroutines/intrinsics/IntrinsicsKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!("Lkotlin/ResultKt;", Some("Ljava/lang/Object;"), &[], 0),
    shim!(
        "Lkotlin/jvm/functions/Function2;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Lokhttp3/CacheControl$Builder;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Lkotlin/coroutines/CoroutineDispatcher;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Lkotlin/Pair;",
        Some("Ljava/lang/Object;"),
        &["Ljava/io/Serializable;"],
        0
    ),
    shim!(
        "Lkotlin/Result$Failure;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Lkotlin/Result;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [sdef!(
            "Companion",
            "Lkotlin/Result$Companion;",
            ShimValue::Lazy(native::lazy_result_companion)
        ),]
    ),
    shim!(
        "Lkotlin/Result$Companion;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Lkotlin/text/MatchResult;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Lkotlin/text/MatcherMatchResult;",
        Some("Ljava/lang/Object;"),
        &["Lkotlin/text/MatchResult;"],
        0
    ),
    shim!("Lkotlin/TuplesKt;", Some("Ljava/lang/Object;"), &[], 0),
    shim!(
        "Lkotlin/ranges/RangesKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Lkotlin/jvm/internal/DefaultConstructorMarker;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    // kotlinx.serialization JSON pipeline (cached filter lists, moetruyen)
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/json/Json;",
        Some("Ljava/lang/Object;"),
        &["Ljava/io/Serializable;"],
        0,
        // wasm: 1.6-era extensions reference `Json.Default` directly.
        [sdef!(
            "Default",
            "Lkotlinx/serialization/json/Json$Default;",
            ShimValue::Lazy(native::lazy_json_default)
        )]
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/json/JsonElement;",
        Some("Ljava/lang/Object;"),
        &["Ljava/io/Serializable;"],
        ACC_ABSTRACT,
        [sdef!(
            "Companion",
            "Lkotlinx/serialization/json/JsonElement$Companion;",
            ShimValue::Lazy(native::lazy_json_element_companion)
        )]
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/json/JsonElement$Companion;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/json/JsonObject;",
        Some("Lkotlinx/serialization/json/JsonElement;"),
        &[],
        0,
        [sdef!(
            "Companion",
            "Lkotlinx/serialization/json/JsonObject$Companion;",
            ShimValue::Lazy(native::lazy_json_object_companion)
        )]
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/json/JsonObject$Companion;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/json/JsonArray;",
        Some("Lkotlinx/serialization/json/JsonElement;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/json/JsonPrimitive;",
        Some("Lkotlinx/serialization/json/JsonElement;"),
        &[],
        ACC_ABSTRACT
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/json/JsonNull;",
        Some("Lkotlinx/serialization/json/JsonPrimitive;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/json/JsonLiteral;",
        Some("Lkotlinx/serialization/json/JsonPrimitive;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/SerializationStrategy;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/DeserializationStrategy;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/KSerializer;",
        None,
        &[
            "Lkotlinx/serialization/SerializationStrategy;",
            "Lkotlinx/serialization/DeserializationStrategy;",
        ],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/encoding/Decoder;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/encoding/CompositeDecoder;",
        None,
        &["Lkotlinx/serialization/encoding/Decoder;"],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/encoding/Encoder;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/encoding/CompositeEncoder;",
        None,
        &["Lkotlinx/serialization/encoding/Encoder;"],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/json/JsonDecoder;",
        None,
        &["Lkotlinx/serialization/encoding/Decoder;"],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/descriptors/SerialDescriptor;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/internal/GeneratedSerializer;",
        None,
        &["Lkotlinx/serialization/KSerializer;"],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/internal/PluginGeneratedSerialDescriptor;",
        Some("Ljava/lang/Object;"),
        &["Lkotlinx/serialization/descriptors/SerialDescriptor;"],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/internal/ArrayListSerializer;",
        Some("Ljava/lang/Object;"),
        &["Lkotlinx/serialization/KSerializer;"],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/json/okio/OkioStreamsKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/builtins/BuiltinSerializersKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/internal/PluginExceptionsKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/internal/StringSerializer;",
        Some("Ljava/lang/Object;"),
        &["Lkotlinx/serialization/KSerializer;"],
        0,
        [sdef!(
            "INSTANCE",
            "Lkotlinx/serialization/internal/StringSerializer;",
            ShimValue::Lazy(native::lazy_string_serializer)
        )]
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/internal/IntSerializer;",
        Some("Ljava/lang/Object;"),
        &["Lkotlinx/serialization/KSerializer;"],
        0,
        [sdef!(
            "INSTANCE",
            "Lkotlinx/serialization/internal/IntSerializer;",
            ShimValue::Lazy(native::lazy_int_serializer)
        )]
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/internal/LongSerializer;",
        Some("Ljava/lang/Object;"),
        &["Lkotlinx/serialization/KSerializer;"],
        0,
        [sdef!(
            "INSTANCE",
            "Lkotlinx/serialization/internal/LongSerializer;",
            ShimValue::Lazy(native::lazy_long_serializer)
        )]
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/internal/BooleanSerializer;",
        Some("Ljava/lang/Object;"),
        &["Lkotlinx/serialization/KSerializer;"],
        0,
        [sdef!(
            "INSTANCE",
            "Lkotlinx/serialization/internal/BooleanSerializer;",
            ShimValue::Lazy(native::lazy_boolean_serializer)
        )]
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lcom/squareup/zstd/okio/OkioZstd;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/json/internal/StreamingJsonDecoder;",
        Some("Ljava/lang/Object;"),
        &[
            "Lkotlinx/serialization/json/JsonDecoder;",
            "Lkotlinx/serialization/encoding/CompositeDecoder;",
        ],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/json/internal/StreamingJsonEncoder;",
        Some("Ljava/lang/Object;"),
        &[
            "Lkotlinx/serialization/encoding/Encoder;",
            "Lkotlinx/serialization/encoding/CompositeEncoder;"
        ],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/UnknownFieldException;",
        Some("Ljava/lang/IllegalArgumentException;"),
        &[],
        0
    ),
    // injekt DI
    shim!(
        "Luy/kohesive/injekt/InjektKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Luy/kohesive/injekt/api/InjektScope;",
        None,
        &["Luy/kohesive/injekt/api/InjektFactory;"],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Luy/kohesive/injekt/api/InjektFactory;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Luy/kohesive/injekt/api/InjektRegister;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Luy/kohesive/injekt/api/FullTypeReference;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    // audit gap shim classes (kotlin)
    #[cfg(feature = "kotlin")]
    shim!("Lkotlin/ExceptionsKt;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/NotImplementedError;",
        Some("Ljava/lang/RuntimeException;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!("Lkotlin/Triple;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "kotlin")]
    shim!("Lkotlin/UByteArray;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "kotlin")]
    shim!("Lkotlin/UIntArray;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "kotlin")]
    shim!("Lkotlin/ULong;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "kotlin")]
    shim!("Lkotlin/UnsignedKt;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/collections/ArrayDeque;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/collections/CharIterator;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/collections/GroupingKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/collections/IndexedValue;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/concurrent/ThreadsKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/coroutines/jvm/internal/DebugProbesKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/coroutines/jvm/internal/RestrictedSuspendLambda;",
        Some("Lkotlin/coroutines/jvm/internal/SuspendLambda;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/internal/ProgressionUtilKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/io/ByteStreamsKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/io/TextStreamsKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/jdk7/AutoCloseableKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/jvm/functions/Function3;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/jvm/functions/Function4;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/jvm/internal/CollectionToArray;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/jvm/internal/FunctionReferenceImpl;",
        Some("Ljava/lang/Object;"),
        &["Lkotlin/jvm/functions/Function1;", "Lkotlin/reflect/KFunction;"],
        0,
        [],
        fields = [("receiver", "Ljava/lang/Object;")]
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/jvm/internal/MutablePropertyReference1Impl;",
        Some("Ljava/lang/Object;"),
        &["Lkotlin/reflect/KProperty;"],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/jvm/internal/PropertyReference0Impl;",
        Some("Ljava/lang/Object;"),
        &["Lkotlin/reflect/KProperty;"],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/jvm/internal/PropertyReference1Impl;",
        Some("Ljava/lang/Object;"),
        &["Lkotlin/reflect/KProperty;"],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/jvm/internal/Ref$BooleanRef;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [],
        fields = [("element", "Z")]
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/jvm/internal/Ref$ByteRef;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [],
        fields = [("element", "B")]
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/jvm/internal/Ref$CharRef;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [],
        fields = [("element", "C")]
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/jvm/internal/Ref$DoubleRef;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [],
        fields = [("element", "D")]
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/jvm/internal/Ref$FloatRef;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [],
        fields = [("element", "F")]
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/jvm/internal/Ref$IntRef;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [],
        fields = [("element", "I")]
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/jvm/internal/Ref$LongRef;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [],
        fields = [("element", "J")]
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/jvm/internal/Ref$ObjectRef;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [],
        fields = [("element", "Ljava/lang/Object;")]
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/jvm/internal/Ref$ShortRef;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [],
        fields = [("element", "S")]
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/jvm/internal/Reflection;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/jvm/internal/SpreadBuilder;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!("Lkotlin/math/MathKt;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "kotlin")]
    shim!(
        // wasm: 1.6-era code reads `Random.Default` as a static field.
        "Lkotlin/random/Random;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [sdef!(
            "Default",
            "Lkotlin/random/Random$Default;",
            ShimValue::Lazy(native::lazy_random_default)
        )]
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/reflect/KCallable;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/reflect/KFunction;",
        None,
        &["Lkotlin/reflect/KCallable;"],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/text/MatchGroup;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/text/MatchGroupCollection;",
        Some("Ljava/lang/Object;"),
        &["Ljava/util/List;"],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/random/Random$Default;",
        Some("Lkotlin/random/Random;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/jvm/internal/StringCompanionObject;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [sdef!(
            "INSTANCE",
            "Lkotlin/jvm/internal/StringCompanionObject;",
            ShimValue::Lazy(native::lazy_string_companion_object)
        )]
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/random/RandomKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/random/URandomKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/ranges/CharRange;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/ranges/IntProgression;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/ranges/ClosedRange;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/ranges/LongRange;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/reflect/KClass;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/reflect/KClassifier;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/reflect/KProperty;",
        None,
        &["Lkotlin/reflect/KCallable;"],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/reflect/KType;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/reflect/KTypeProjection$Companion;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/sequences/Sequence;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/sequences/SequenceScope;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/sequences/SequencesKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/text/HexExtensionsKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/text/HexFormat;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [sdef!(
            "Companion",
            "Lkotlin/text/HexFormat$Companion;",
            ShimValue::Lazy(native::lazy_hex_format_companion)
        )]
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/text/HexFormat$BytesHexFormat;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/text/HexFormat$Builder;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/text/HexFormat$BytesHexFormat$Builder;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/text/HexFormat$Companion;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/text/MatchGroup;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/text/MatchGroupCollection;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/text/MatchResult$Destructured;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/text/Regex$Companion;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/text/UStringsKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/time/Clock$System;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [sdef!(
            "INSTANCE",
            "Lkotlin/time/Clock$System;",
            ShimValue::Lazy(native::lazy_clock_system_instance)
        ),]
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        // wasm: predefined formatter constants (1.6 sources read ISO_LOCAL_DATE
        // & co. as static fields instead of calling ofPattern).
        "Ljava/time/format/DateTimeFormatter;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [
            sdef!(
                "ISO_LOCAL_DATE",
                "Ljava/time/format/DateTimeFormatter;",
                ShimValue::Lazy(native::lazy_iso_local_date)
            ),
            sdef!(
                "ISO_LOCAL_TIME",
                "Ljava/time/format/DateTimeFormatter;",
                ShimValue::Lazy(native::lazy_iso_local_time)
            ),
            sdef!(
                "ISO_LOCAL_DATE_TIME",
                "Ljava/time/format/DateTimeFormatter;",
                ShimValue::Lazy(native::lazy_iso_local_date_time)
            ),
            sdef!(
                "ISO_OFFSET_DATE",
                "Ljava/time/format/DateTimeFormatter;",
                ShimValue::Lazy(native::lazy_iso_offset_date)
            ),
            sdef!(
                "ISO_OFFSET_TIME",
                "Ljava/time/format/DateTimeFormatter;",
                ShimValue::Lazy(native::lazy_iso_offset_time)
            ),
            sdef!(
                "ISO_OFFSET_DATE_TIME",
                "Ljava/time/format/DateTimeFormatter;",
                ShimValue::Lazy(native::lazy_iso_offset_date_time)
            ),
            sdef!(
                "ISO_ZONED_DATE_TIME",
                "Ljava/time/format/DateTimeFormatter;",
                ShimValue::Lazy(native::lazy_iso_zoned_date_time)
            ),
            sdef!(
                "ISO_INSTANT",
                "Ljava/time/format/DateTimeFormatter;",
                ShimValue::Lazy(native::lazy_iso_instant)
            ),
            sdef!(
                "BASIC_ISO_DATE",
                "Ljava/time/format/DateTimeFormatter;",
                ShimValue::Lazy(native::lazy_basic_iso_date)
            ),
            sdef!(
                "ISO_ORDINAL_DATE",
                "Ljava/time/format/DateTimeFormatter;",
                ShimValue::Lazy(native::lazy_iso_ordinal_date)
            ),
            sdef!(
                "ISO_WEEK_DATE",
                "Ljava/time/format/DateTimeFormatter;",
                ShimValue::Lazy(native::lazy_iso_week_date)
            ),
            sdef!(
                "RFC_1123_DATE_TIME",
                "Ljava/time/format/DateTimeFormatter;",
                ShimValue::Lazy(native::lazy_rfc_1123_date_time)
            ),
        ]
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/time/Instant$Companion;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        // wasm: 1.6-era code reads `Instant.Companion` as a static field
        // before calling parse()/parseOrNull().
        "Lkotlin/time/Instant;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [sdef!(
            "Companion",
            "Lkotlin/time/Instant$Companion;",
            ShimValue::Lazy(native::lazy_instant_companion)
        )]
    ),
    #[cfg(feature = "kotlin")]
    shim!(
        "Lkotlin/time/jdk8/InstantConversionsJDK8Kt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    // audit gap shim classes (android)
    #[cfg(feature = "android")]
    shim!(
        "Landroid/app/ActivityManager;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/app/ActivityManager$MemoryInfo;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/content/ComponentName;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/content/res/Resources;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/graphics/Bitmap;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/graphics/Bitmap$CompressFormat;",
        Some("Ljava/lang/Enum;"),
        &[],
        0,
        [
            sdef!("JPEG", "I", ShimValue::Const(JValue::Int(0))),
            sdef!("PNG", "I", ShimValue::Const(JValue::Int(1))),
            sdef!("WEBP", "I", ShimValue::Const(JValue::Int(2))),
            sdef!("WEBP_LOSSY", "I", ShimValue::Const(JValue::Int(3))),
            sdef!("WEBP_LOSSLESS", "I", ShimValue::Const(JValue::Int(4))),
        ]
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/graphics/Bitmap$Config;",
        Some("Ljava/lang/Enum;"),
        &[],
        0,
        [
            sdef!("ARGB_8888", "I", ShimValue::Const(JValue::Int(0))),
            sdef!("ALPHA_8", "I", ShimValue::Const(JValue::Int(1))),
            sdef!("RGB_565", "I", ShimValue::Const(JValue::Int(2))),
            sdef!("ARGB_4444", "I", ShimValue::Const(JValue::Int(3))),
            sdef!("HARDWARE", "I", ShimValue::Const(JValue::Int(4))),
        ]
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/graphics/BitmapFactory;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/graphics/BitmapFactory$Options;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/graphics/Canvas;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/graphics/ImageDecoder;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/graphics/Paint;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/graphics/Paint$Style;",
        Some("Ljava/lang/Enum;"),
        &[],
        0,
        [
            sdef!("FILL", "I", ShimValue::Const(JValue::Int(0))),
            sdef!("STROKE", "I", ShimValue::Const(JValue::Int(1))),
            sdef!("FILL_AND_STROKE", "I", ShimValue::Const(JValue::Int(2))),
        ]
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/graphics/Rect;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/graphics/Typeface;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/graphics/pdf/PdfRenderer;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/graphics/pdf/PdfRenderer$Page;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/icu/text/BreakIterator;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/icu/text/Collator;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/icu/text/Normalizer2;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/icu/text/RuleBasedCollator;",
        Some("Landroid/icu/text/Collator;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/icu/text/SearchIterator;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/icu/text/StringSearch;",
        Some("Landroid/icu/text/SearchIterator;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/net/Uri$Builder;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!("Landroid/os/Handler;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "android")]
    shim!("Landroid/os/Looper;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/os/ParcelFileDescriptor;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!("Landroid/text/Html;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/text/Editable;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "android")]
    shim!("Landroid/text/Layout;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/text/SpannableString;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/text/StaticLayout;",
        Some("Landroid/text/Layout;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/text/StaticLayout$Builder;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/text/TextPaint;",
        Some("Landroid/graphics/Paint;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/text/method/LinkMovementMethod;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/text/util/Linkify;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/util/Base64InputStream;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/util/JsonReader;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/util/LruCache;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/view/View$MeasureSpec;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!("Landroid/view/View;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/view/ViewGroup;",
        Some("Landroid/view/View;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/view/ViewGroup$LayoutParams;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/webkit/ConsoleMessage$MessageLevel;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/webkit/ConsoleMessage;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/webkit/RenderProcessGoneDetail;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/webkit/SslErrorHandler;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/webkit/URLUtil;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/webkit/WebChromeClient;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/webkit/WebResourceRequest;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/webkit/WebResourceResponse;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/webkit/WebSettings;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/webkit/WebView;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/webkit/WebViewClient;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/widget/EditText;",
        Some("Landroid/widget/TextView;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroid/widget/TextView;",
        Some("Landroid/view/View;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!("Landroid/widget/Toast;", Some("Ljava/lang/Object;"), &[], 0),
    // audit gap shim classes (androidx)
    #[cfg(feature = "android")]
    shim!(
        "Landroidx/preference/CheckBoxPreference;",
        Some("Landroidx/preference/Preference;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroidx/preference/EditTextPreference;",
        Some("Landroidx/preference/Preference;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroidx/preference/ListPreference;",
        Some("Landroidx/preference/Preference;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroidx/preference/MultiSelectListPreference;",
        Some("Landroidx/preference/Preference;"),
        &[],
        0
    ),
    #[cfg(feature = "android")]
    shim!(
        "Landroidx/preference/Preference$OnPreferenceChangeListener;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    // audit gap shim classes (okhttp)
    #[cfg(feature = "okhttp")]
    shim!("Lokhttp3/Cache;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/Cookie;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [sdef!(
            "Companion",
            "Lokhttp3/Cookie$Companion;",
            ShimValue::Lazy(native::lazy_cookie_companion)
        )]
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/Protocol;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [
            sdef!("HTTP_1_0", "Lokhttp3/Protocol;", ShimValue::Lazy(native::lazy_protocol)),
            sdef!("HTTP_1_1", "Lokhttp3/Protocol;", ShimValue::Lazy(native::lazy_protocol)),
            sdef!("HTTP_2", "Lokhttp3/Protocol;", ShimValue::Lazy(native::lazy_protocol)),
            sdef!("SPDY_3", "Lokhttp3/Protocol;", ShimValue::Lazy(native::lazy_protocol)),
            sdef!("QUIC", "Lokhttp3/Protocol;", ShimValue::Lazy(native::lazy_protocol)),
            sdef!("H2_PRIOR_KNOWLEDGE", "Lokhttp3/Protocol;", ShimValue::Lazy(native::lazy_protocol)),
        ]
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/Cookie$Companion;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/Cookie$Builder;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/CookieJar;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "okhttp")]
    shim!("Lokhttp3/Credentials;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "okhttp")]
    shim!("Lokhttp3/Dispatcher;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "okhttp")]
    shim!("Lokhttp3/Dns;", None, &[], ACC_INTERFACE | ACC_ABSTRACT),
    #[cfg(feature = "okhttp")]
    shim!(
        "Ljavax/net/ssl/HostnameVerifier;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/Headers$Companion;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/MultipartBody$Builder;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/ResponseBody$Companion;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokhttp3/internal/_UtilCommonKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    // audit gap shim classes (okio)
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokio/ByteString$Companion;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "okhttp")]
    shim!(
        "Lokio/ForwardingSource;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "okhttp")]
    shim!("Lokio/InflaterSource;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "okhttp")]
    shim!("Lokio/CipherSource;", Some("Ljava/lang/Object;"), &[], 0),
    // audit gap shim classes (jsoup)
    #[cfg(feature = "jsoup")]
    shim!(
        "Lorg/jsoup/helper/Validate;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "jsoup")]
    shim!(
        "Lorg/jsoup/nodes/Attribute;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "jsoup")]
    shim!(
        "Lorg/jsoup/nodes/Attributes;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "jsoup")]
    shim!(
        "Lorg/jsoup/nodes/Entities;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "jsoup")]
    shim!("Lorg/jsoup/nodes/Node;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "jsoup")]
    shim!(
        "Lorg/jsoup/nodes/TextNode;",
        Some("Lorg/jsoup/nodes/Node;"),
        &[],
        0
    ),
    #[cfg(feature = "jsoup")]
    shim!(
        "Lorg/jsoup/parser/Parser;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "jsoup")]
    shim!("Lorg/jsoup/parser/Tag;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "jsoup")]
    shim!(
        "Lorg/jsoup/safety/Safelist;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "jsoup")]
    shim!(
        "Lorg/jsoup/select/Collector;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "jsoup")]
    shim!(
        "Lorg/jsoup/select/Evaluator$Class;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "jsoup")]
    shim!(
        "Lorg/jsoup/select/Evaluator$Id;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "jsoup")]
    shim!(
        "Lorg/jsoup/select/Evaluator$Tag;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "jsoup")]
    shim!(
        "Lorg/jsoup/select/QueryParser;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    // audit gap shim classes (tachiyomi)
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Leu/kanade/tachiyomi/AppInfo;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Leu/kanade/tachiyomi/network/HttpException;",
        Some("Ljava/lang/Exception;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!("Lrx/Single;", Some("Ljava/lang/Object;"), &[], 0),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Ltachiyomi/decoder/ImageDecoder;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/BinaryFormat;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/ContextualSerializer;",
        Some("Ljava/lang/Object;"),
        &["Lkotlinx/serialization/KSerializer;"],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/PolymorphicSerializer;",
        Some("Ljava/lang/Object;"),
        &["Lkotlinx/serialization/KSerializer;"],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/internal/EnumSerializer;",
        Some("Ljava/lang/Object;"),
        &["Lkotlinx/serialization/KSerializer;"],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/SealedClassSerializer;",
        Some("Ljava/lang/Object;"),
        &["Lkotlinx/serialization/KSerializer;"],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/SerializationException;",
        Some("Ljava/lang/IllegalArgumentException;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/descriptors/SerialDescriptorsKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/internal/EnumsKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/internal/InlineClassDescriptor;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/internal/LinkedHashMapSerializer;",
        Some("Ljava/lang/Object;"),
        &["Lkotlinx/serialization/KSerializer;"],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/internal/LinkedHashSetSerializer;",
        Some("Ljava/lang/Object;"),
        &["Lkotlinx/serialization/KSerializer;"],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/internal/ObjectSerializer;",
        Some("Ljava/lang/Object;"),
        &["Lkotlinx/serialization/KSerializer;"],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/internal/PairSerializer;",
        Some("Ljava/lang/Object;"),
        &["Lkotlinx/serialization/KSerializer;"],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/internal/ReferenceArraySerializer;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        // wasm: serializer object used by 1.6-era kotlinx serialization code.
        "Lkotlinx/serialization/json/JsonElementSerializer;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [sdef!(
            "INSTANCE",
            "Lkotlinx/serialization/json/JsonElementSerializer;",
            ShimValue::Lazy(native::lazy_json_element_serializer)
        )]
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/json/JsonPrimitiveSerializer;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [sdef!(
            "INSTANCE",
            "Lkotlinx/serialization/json/JsonPrimitiveSerializer;",
            ShimValue::Lazy(native::lazy_json_primitive_serializer)
        )]
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        // wasm: 1.6-era code calls Json methods through `Json.Default`, so the
        // singleton must inherit from Json, not Object.
        "Lkotlinx/serialization/json/Json$Default;",
        Some("Lkotlinx/serialization/json/Json;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/json/JsonArray$Companion;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/json/JsonArrayBuilder;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/json/JsonBuilder;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/json/JsonClassDiscriminator;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/json/JsonKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/json/JsonNames;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/json/JsonObject$Companion;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/json/JsonTransformingSerializer;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/json/JvmStreamsKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/modules/PolymorphicModuleBuilder;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/modules/SerializersModuleBuilder;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/modules/SerializersModule;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/modules/SerializersModuleKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/protobuf/ProtoNumber;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/protobuf/ProtoBuf;",
        Some("Ljava/lang/Object;"),
        &["Lkotlinx/serialization/BinaryFormat;"],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/protobuf/ProtoBuf$Companion;",
        Some("Ljava/lang/Object;"),
        &["Lkotlinx/serialization/BinaryFormat;"],
        0
    ),
    // Composite decoder for the protobuf wire format. Methods are provided
    // by `native::proto::PROTO_TABLE`; declaring the Decoder/CompositeDecoder
    // interfaces lets interface-dispatch reach them.
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/serialization/protobuf/ProtoDecoder;",
        Some("Ljava/lang/Object;"),
        &[
            "Lkotlinx/serialization/encoding/Decoder;",
            "Lkotlinx/serialization/encoding/CompositeDecoder;",
        ],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/coroutines/CancellableContinuationImpl;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/coroutines/CompletableDeferred;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/coroutines/CompletableDeferredKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/coroutines/CompletableJob;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/coroutines/DelayKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/coroutines/MainCoroutineDispatcher;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/coroutines/SupervisorKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/coroutines/TimeoutKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/coroutines/sync/Mutex;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    #[cfg(feature = "tachiyomi")]
    shim!(
        "Lkotlinx/coroutines/sync/MutexKt;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    // audit gap shim classes (java)
    shim!("Ljava/net/InetAddress;", Some("Ljava/lang/Object;"), &[], 0),
    shim!("Ljava/net/URL;", Some("Ljava/lang/Object;"), &[], 0),
    shim!("Ljava/net/URLDecoder;", Some("Ljava/lang/Object;"), &[], 0),
    shim!("Ljava/net/URLEncoder;", Some("Ljava/lang/Object;"), &[], 0),
    shim!(
        "Ljava/net/UnknownHostException;",
        Some("Ljava/io/IOException;"),
        &[],
        0
    ),
    shim!(
        "Ljava/util/concurrent/CopyOnWriteArrayList;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/util/concurrent/CountDownLatch;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/util/concurrent/Semaphore;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/time/temporal/ChronoField;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [
            sdef!("NANO_OF_SECOND", "Ljava/time/temporal/ChronoField;", ShimValue::Lazy(native::lazy_chrono_field_nano_of_second)),
            sdef!("SECOND_OF_MINUTE", "Ljava/time/temporal/ChronoField;", ShimValue::Lazy(native::lazy_chrono_field_second_of_minute)),
            sdef!("MINUTE_OF_HOUR", "Ljava/time/temporal/ChronoField;", ShimValue::Lazy(native::lazy_chrono_field_minute_of_hour)),
            sdef!("HOUR_OF_DAY", "Ljava/time/temporal/ChronoField;", ShimValue::Lazy(native::lazy_chrono_field_hour_of_day)),
            sdef!("DAY_OF_WEEK", "Ljava/time/temporal/ChronoField;", ShimValue::Lazy(native::lazy_chrono_field_day_of_week)),
            sdef!("DAY_OF_MONTH", "Ljava/time/temporal/ChronoField;", ShimValue::Lazy(native::lazy_chrono_field_day_of_month)),
            sdef!("DAY_OF_YEAR", "Ljava/time/temporal/ChronoField;", ShimValue::Lazy(native::lazy_chrono_field_day_of_year)),
            sdef!("MONTH_OF_YEAR", "Ljava/time/temporal/ChronoField;", ShimValue::Lazy(native::lazy_chrono_field_month_of_year)),
            sdef!("YEAR", "Ljava/time/temporal/ChronoField;", ShimValue::Lazy(native::lazy_chrono_field_year)),
            sdef!("EPOCH_DAY", "Ljava/time/temporal/ChronoField;", ShimValue::Lazy(native::lazy_chrono_field_epoch_day)),
        ]
    ),
    shim!(
        "Ljava/security/Key;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/security/PublicKey;",
        None,
        &["Ljava/security/Key;"],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/security/spec/KeySpec;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/security/spec/EncodedKeySpec;",
        Some("Ljava/lang/Object;"),
        &["Ljava/security/spec/KeySpec;"],
        ACC_PUBLIC | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/security/spec/X509EncodedKeySpec;",
        Some("Ljava/security/spec/EncodedKeySpec;"),
        &[],
        0
    ),
    shim!(
        "Ljava/security/spec/AlgorithmParameterSpec;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/security/KeyFactory;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljavax/crypto/Cipher;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/time/ZoneId;",
        Some("Ljava/lang/Object;"),
        &[],
        ACC_PUBLIC
    ),
    shim!(
        "Ljava/time/ZoneOffset;",
        Some("Ljava/time/ZoneId;"),
        &[],
        ACC_PUBLIC,
        [sdef!(
            "UTC",
            "Ljava/time/ZoneOffset;",
            ShimValue::Lazy(native::lazy_zone_offset_utc)
        )]
    ),
    shim!(
        "Ljava/time/LocalDateTime;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/time/OffsetDateTime;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/time/ZonedDateTime;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/time/chrono/ChronoLocalDateTime;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/time/temporal/ChronoUnit;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [
            sdef!(
                "MILLIS",
                "Ljava/time/temporal/ChronoUnit;",
                ShimValue::Lazy(native::lazy_chrono_unit_millis)
            ),
            sdef!(
                "SECONDS",
                "Ljava/time/temporal/ChronoUnit;",
                ShimValue::Lazy(native::lazy_chrono_unit_seconds)
            ),
            sdef!(
                "MINUTES",
                "Ljava/time/temporal/ChronoUnit;",
                ShimValue::Lazy(native::lazy_chrono_unit_minutes)
            ),
            sdef!(
                "HOURS",
                "Ljava/time/temporal/ChronoUnit;",
                ShimValue::Lazy(native::lazy_chrono_unit_hours)
            ),
            sdef!(
                "DAYS",
                "Ljava/time/temporal/ChronoUnit;",
                ShimValue::Lazy(native::lazy_chrono_unit_days)
            ),
            sdef!(
                "WEEKS",
                "Ljava/time/temporal/ChronoUnit;",
                ShimValue::Lazy(native::lazy_chrono_unit_weeks)
            ),
            sdef!(
                "MONTHS",
                "Ljava/time/temporal/ChronoUnit;",
                ShimValue::Lazy(native::lazy_chrono_unit_months)
            ),
            sdef!(
                "YEARS",
                "Ljava/time/temporal/ChronoUnit;",
                ShimValue::Lazy(native::lazy_chrono_unit_years)
            ),
        ]
    ),
    shim!(
        "Ljava/time/temporal/TemporalUnit;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/time/temporal/TemporalField;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/time/format/DateTimeFormatterBuilder;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/util/zip/GZIPInputStream;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/util/zip/Inflater;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/util/zip/ZipEntry;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/util/zip/ZipInputStream;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/io/BufferedReader;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/io/EOFException;",
        Some("Ljava/io/IOException;"),
        &[],
        0
    ),
    shim!(
        "Ljava/io/FileNotFoundException;",
        Some("Ljava/io/IOException;"),
        &[],
        0
    ),
    shim!(
        "Ljava/io/FileOutputStream;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!("Ljava/nio/Buffer;", Some("Ljava/lang/Object;"), &[], 0),
    shim!("Ljava/nio/ByteBuffer;", Some("Ljava/nio/Buffer;"), &[], 0),
    shim!("Ljava/nio/CharBuffer;", Some("Ljava/nio/Buffer;"), &[], 0),
    shim!(
        "Ljava/nio/BufferUnderflowException;",
        Some("Ljava/lang/RuntimeException;"),
        &[],
        0
    ),
    shim!(
        "Ljava/nio/ByteOrder;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [
            sdef!(
                "BIG_ENDIAN",
                "Ljava/nio/ByteOrder;",
                ShimValue::Lazy(native::lazy_big_endian)
            ),
            sdef!(
                "LITTLE_ENDIAN",
                "Ljava/nio/ByteOrder;",
                ShimValue::Lazy(native::lazy_little_endian)
            ),
        ]
    ),
    shim!(
        "Ljava/nio/charset/CharsetDecoder;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/nio/charset/CharsetEncoder;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/util/Base64$Decoder;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/util/Base64$Encoder;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!("Ljava/util/Base64;", Some("Ljava/lang/Object;"), &[], 0),
    shim!(
        "Ljava/util/GregorianCalendar;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!("Ljava/util/TreeMap;", Some("Ljava/lang/Object;"), &[], 0),
    shim!("Ljava/util/UUID;", Some("Ljava/lang/Object;"), &[], 0),
    shim!("Ljava/math/BigDecimal;", Some("Ljava/lang/Object;"), &[], 0),
    shim!(
        "Ljava/math/BigInteger;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [
            sdef!("ZERO", "Ljava/math/BigInteger;", ShimValue::Lazy(native::lazy_bigint_zero)),
            sdef!("ONE", "Ljava/math/BigInteger;", ShimValue::Lazy(native::lazy_bigint_one)),
            sdef!("TWO", "Ljava/math/BigInteger;", ShimValue::Lazy(native::lazy_bigint_two)),
            sdef!("TEN", "Ljava/math/BigInteger;", ShimValue::Lazy(native::lazy_bigint_ten)),
        ]
    ),
    // wasm: 1.6-era sources read RoundingMode enum constants before calling
    // BigDecimal.setScale(int, RoundingMode); the native ignores the mode.
    shim!(
        "Ljava/math/RoundingMode;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [
            sdef!(
                "UP",
                "Ljava/math/RoundingMode;",
                ShimValue::Lazy(native::lazy_rounding_mode)
            ),
            sdef!(
                "DOWN",
                "Ljava/math/RoundingMode;",
                ShimValue::Lazy(native::lazy_rounding_mode)
            ),
            sdef!(
                "CEILING",
                "Ljava/math/RoundingMode;",
                ShimValue::Lazy(native::lazy_rounding_mode)
            ),
            sdef!(
                "FLOOR",
                "Ljava/math/RoundingMode;",
                ShimValue::Lazy(native::lazy_rounding_mode)
            ),
            sdef!(
                "HALF_UP",
                "Ljava/math/RoundingMode;",
                ShimValue::Lazy(native::lazy_rounding_mode)
            ),
            sdef!(
                "HALF_DOWN",
                "Ljava/math/RoundingMode;",
                ShimValue::Lazy(native::lazy_rounding_mode)
            ),
            sdef!(
                "HALF_EVEN",
                "Ljava/math/RoundingMode;",
                ShimValue::Lazy(native::lazy_rounding_mode)
            ),
            sdef!(
                "UNNECESSARY",
                "Ljava/math/RoundingMode;",
                ShimValue::Lazy(native::lazy_rounding_mode)
            ),
        ]
    ),
    shim!(
        "Ljava/lang/ref/SoftReference;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/security/DigestException;",
        Some("Ljava/lang/Exception;"),
        &[],
        0
    ),
    shim!(
        "Ljava/security/InvalidParameterException;",
        Some("Ljava/lang/IllegalArgumentException;"),
        &[],
        0
    ),
    shim!(
        "Ljava/security/KeyFactory;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/security/KeyPair;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/security/KeyPairGenerator;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/security/MessageDigestSpi;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/security/spec/PKCS8EncodedKeySpec;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/security/spec/RSAKeyGenParameterSpec;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/security/spec/X509EncodedKeySpec;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!("Ljava/lang/Runtime;", Some("Ljava/lang/Object;"), &[], 0),
    shim!(
        "Ljava/lang/StringBuffer;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/lang/ThreadLocal;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/lang/reflect/Array;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/lang/reflect/Method;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/util/concurrent/atomic/AtomicReference;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/util/concurrent/atomic/AtomicReferenceArray;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/text/DecimalFormat;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/text/DecimalFormatSymbols;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!("Ljava/text/Format;", Some("Ljava/lang/Object;"), &[], 0),
    shim!("Ljava/text/Normalizer;", Some("Ljava/lang/Object;"), &[], 0),
    shim!(
        "Ljava/text/Normalizer$Form;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [
            sdef!(
                "NFC",
                "Ljava/text/Normalizer$Form;",
                ShimValue::Lazy(native::lazy_form_nfc)
            ),
            sdef!(
                "NFD",
                "Ljava/text/Normalizer$Form;",
                ShimValue::Lazy(native::lazy_form_nfd)
            ),
            sdef!(
                "NFKC",
                "Ljava/text/Normalizer$Form;",
                ShimValue::Lazy(native::lazy_form_nfkc)
            ),
            sdef!(
                "NFKD",
                "Ljava/text/Normalizer$Form;",
                ShimValue::Lazy(native::lazy_form_nfkd)
            ),
        ]
    ),
    shim!(
        "Ljava/text/StringCharacterIterator;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljavax/crypto/CipherInputStream;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!("Ljavax/crypto/Mac;", Some("Ljava/lang/Object;"), &[], 0),
    shim!(
        "Ljavax/crypto/SecretKeyFactory;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljavax/crypto/ShortBufferException;",
        Some("Ljava/lang/Exception;"),
        &[],
        0
    ),
    shim!(
        "Ljavax/crypto/spec/OAEPParameterSpec;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljavax/crypto/spec/PBEKeySpec;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    // audit gap shim classes (plain)
    shim!("Lorg/json/JSONArray;", Some("Ljava/lang/Object;"), &[], 0),
    shim!("Lorg/json/JSONObject;", Some("Ljava/lang/Object;"), &[], 0),
    shim!(
        "Lorg/json/JSONException;",
        Some("Ljava/lang/Exception;"),
        &[],
        0
    ),
    shim!(
        "Lapp/cash/quickjs/QuickJs;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljavax/net/ssl/SSLContext;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljavax/net/ssl/SSLSocketFactory;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    #[cfg(feature = "tachiyomi")]
    shim!("Lrx/Subscription;", Some("Ljava/lang/Object;"), &[], 0),
    // gap-scan additions: classes referenced across the zh corpus
    shim!(
        "Lkotlin/enums/EnumEntries;",
        None,
        &["Ljava/util/List;"],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Lkotlin/Metadata;",
        None,
        &["Ljava/lang/annotation/Annotation;"],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Lkotlinx/serialization/Serializable;",
        None,
        &["Ljava/lang/annotation/Annotation;"],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Lkotlinx/serialization/internal/FloatSerializer;",
        Some("Ljava/lang/Object;"),
        &["Lkotlinx/serialization/KSerializer;"],
        0,
        [sdef!(
            "INSTANCE",
            "Lkotlinx/serialization/internal/FloatSerializer;",
            ShimValue::Lazy(native::lazy_float_serializer)
        )]
    ),
    shim!(
        "Lkotlinx/serialization/internal/DoubleSerializer;",
        Some("Ljava/lang/Object;"),
        &["Lkotlinx/serialization/KSerializer;"],
        0,
        [sdef!(
            "INSTANCE",
            "Lkotlinx/serialization/internal/DoubleSerializer;",
            ShimValue::Lazy(native::lazy_double_serializer)
        )]
    ),
    shim!(
        "Lkotlinx/serialization/internal/IntArraySerializer;",
        Some("Ljava/lang/Object;"),
        &["Lkotlinx/serialization/KSerializer;"],
        0,
        [sdef!(
            "INSTANCE",
            "Lkotlinx/serialization/internal/IntArraySerializer;",
            ShimValue::Lazy(native::lazy_int_array_serializer)
        )]
    ),
    shim!(
        "Lkotlinx/serialization/json/JsonArraySerializer;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [sdef!(
            "INSTANCE",
            "Lkotlinx/serialization/json/JsonArraySerializer;",
            ShimValue::Lazy(native::lazy_json_element_serializer)
        )]
    ),
    shim!(
        "Lkotlinx/serialization/json/JsonObjectSerializer;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [sdef!(
            "INSTANCE",
            "Lkotlinx/serialization/json/JsonObjectSerializer;",
            ShimValue::Lazy(native::lazy_json_element_serializer)
        )]
    ),
    shim!(
        "Lkotlinx/coroutines/CoroutineStart;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [
            sdef!("DEFAULT", "Lkotlinx/coroutines/CoroutineStart;", ShimValue::Lazy(native::kotlinx::coroutines::lazy_coroutine_start)),
            sdef!("LAZY", "Lkotlinx/coroutines/CoroutineStart;", ShimValue::Lazy(native::kotlinx::coroutines::lazy_coroutine_start)),
            sdef!("ATOMIC", "Lkotlinx/coroutines/CoroutineStart;", ShimValue::Lazy(native::kotlinx::coroutines::lazy_coroutine_start)),
            sdef!("UNDISPATCHED", "Lkotlinx/coroutines/CoroutineStart;", ShimValue::Lazy(native::kotlinx::coroutines::lazy_coroutine_start)),
        ]
    ),
    shim!(
        "Lkotlinx/coroutines/TimeoutCancellationException;",
        Some("Ljava/util/concurrent/CancellationException;"),
        &[],
        0
    ),
    shim!("Lokhttp3/Connection;", Some("Ljava/lang/Object;"), &[], 0),
    shim!(
        "Lokhttp3/Callback;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Lokhttp3/MultipartBody;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [
            sdef!("FORM", "Lokhttp3/MediaType;", ShimValue::Lazy(native::lazy_media_type_form)),
            sdef!("MIXED", "Lokhttp3/MediaType;", ShimValue::Lazy(native::lazy_media_type_mixed)),
            sdef!("ALTERNATE", "Lokhttp3/MediaType;", ShimValue::Lazy(native::lazy_media_type_alternate)),
            sdef!("DIGEST", "Lokhttp3/MediaType;", ShimValue::Lazy(native::lazy_media_type_digest)),
            sdef!("PARALLEL", "Lokhttp3/MediaType;", ShimValue::Lazy(native::lazy_media_type_parallel)),
        ]
    ),
    shim!(
        "Lokhttp3/MultipartBody$Builder;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!("Landroid/os/LocaleList;", Some("Ljava/lang/Object;"), &[], 0),
    shim!(
        "Ljava/util/Locale$Builder;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Landroid/text/Layout$Alignment;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [
            sdef!("ALIGN_NORMAL", "Landroid/text/Layout$Alignment;", ShimValue::Lazy(native::android::lazy_alignment_normal)),
            sdef!("ALIGN_CENTER", "Landroid/text/Layout$Alignment;", ShimValue::Lazy(native::android::lazy_alignment_center)),
            sdef!("ALIGN_OPPOSITE", "Landroid/text/Layout$Alignment;", ShimValue::Lazy(native::android::lazy_alignment_opposite)),
        ]
    ),
    shim!(
        "Landroid/text/TextWatcher;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Landroid/view/ViewParent;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Landroid/text/Spanned;",
        None,
        &["Ljava/lang/CharSequence;"],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Landroid/text/style/MetricAffectingSpan;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Landroid/widget/Button;",
        Some("Landroid/widget/TextView;"),
        &[],
        0
    ),
    shim!(
        "Landroidx/preference/EditTextPreference$OnBindEditTextListener;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Landroid/webkit/ValueCallback;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Landroid/webkit/WebResourceError;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Landroid/webkit/ConsoleMessage$MessageLevel;",
        Some("Ljava/lang/Object;"),
        &[],
        0,
        [
            sdef!("TIP", "Landroid/webkit/ConsoleMessage$MessageLevel;", ShimValue::Lazy(native::android::lazy_console_level)),
            sdef!("LOG", "Landroid/webkit/ConsoleMessage$MessageLevel;", ShimValue::Lazy(native::android::lazy_console_level)),
            sdef!("WARNING", "Landroid/webkit/ConsoleMessage$MessageLevel;", ShimValue::Lazy(native::android::lazy_console_level)),
            sdef!("ERROR", "Landroid/webkit/ConsoleMessage$MessageLevel;", ShimValue::Lazy(native::android::lazy_console_level)),
        ]
    ),
    shim!(
        "Landroid/webkit/JavascriptInterface;",
        None,
        &["Ljava/lang/annotation/Annotation;"],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljavax/net/ssl/SSLSession;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/lang/reflect/InvocationHandler;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Ljava/lang/ref/Reference;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Ljava/lang/ref/WeakReference;",
        Some("Ljava/lang/ref/Reference;"),
        &[],
        0
    ),
    shim!("Ljava/util/Properties;", Some("Ljava/lang/Object;"), &[], 0),
    shim!("Ljava/util/zip/CRC32;", Some("Ljava/lang/Object;"), &[], 0),
    shim!(
        "Ljava/util/zip/ZipException;",
        Some("Ljava/lang/Exception;"),
        &[],
        0
    ),
    shim!(
        "Ljava/util/concurrent/CopyOnWriteArraySet;",
        Some("Ljava/util/concurrent/CopyOnWriteArrayList;"),
        &[],
        0
    ),
    shim!(
        "Ljava/util/concurrent/ConcurrentHashMap$KeySetView;",
        Some("Ljava/util/AbstractSet;"),
        &[],
        0
    ),
    shim!(
        "Lkotlin/jvm/internal/TypeIntrinsics;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Lkotlin/jvm/internal/markers/KMutableList;",
        None,
        &["Ljava/util/List;"],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Lkotlin/jvm/internal/AdaptedFunctionReference;",
        Some("Lkotlin/jvm/internal/FunctionReferenceImpl;"),
        &[],
        0
    ),
    shim!(
        "Lkotlin/ranges/OpenEndRange;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Lkotlin/collections/Grouping;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Landroid/util/Patterns;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Landroid/content/res/Configuration;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!("Landroid/view/Window;", Some("Ljava/lang/Object;"), &[], 0),
    shim!("Landroid/app/Dialog;", Some("Ljava/lang/Object;"), &[], 0),
    shim!(
        "Landroid/content/DialogInterface;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Landroid/content/DialogInterface$OnDismissListener;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Landroid/content/DialogInterface$OnCancelListener;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Landroid/app/Application$ActivityLifecycleCallbacks;",
        None,
        &[],
        ACC_INTERFACE | ACC_ABSTRACT
    ),
    shim!(
        "Landroid/graphics/drawable/Drawable;",
        Some("Ljava/lang/Object;"),
        &[],
        0
    ),
    shim!(
        "Landroid/graphics/drawable/ColorDrawable;",
        Some("Landroid/graphics/drawable/Drawable;"),
        &[],
        0
    ),
];

#[derive(Debug, Clone, Default)]
pub struct Class {
    pub id: u32,
    /// Interned full descriptor (e.g. `Lcom/foo/Bar;` or `[I`).
    pub descriptor: u32,
    pub superclass: Option<u32>,
    pub interfaces: Vec<u32>,
    pub access_flags: u32,
    pub is_interface: bool,
    pub is_abstract: bool,
    /// For array classes: (dex index, element type id).
    pub array_elem: Option<(u32, u32)>,
    /// Instance fields in declaration order (walk order == offset).
    pub instance_fields: Vec<(u32, u32, u32)>, // (name, ty_desc, access)
    /// (name, ty_desc) -> instance offset. Inherited fields are copied in.
    pub field_offsets: HashMap<(u32, u32), u32>,
    /// (name, ty_desc) -> (owning class id, offset in that class's `statics`).
    pub static_fields: HashMap<(u32, u32), (u32, u32)>,
    /// Own static field values (offset == index).
    pub statics: Vec<JValue>,
    /// Lazy static materializers for shim classes.
    pub statics_lazy: Vec<Option<ShimLazy>>,
    /// 0 = uninitialized, 1 = initializing, 2 = initialized.
    pub clinit_state: u8,
    /// Cached `java.lang.Class` instance for this class (identity-stable).
    pub class_obj: Option<u32>,
    pub methods: Vec<Method>,
    /// (name, sig) -> slot into `methods`.
    pub dispatch: HashMap<(u32, u32), u32>,
}

impl Class {
    /// Find the `<clinit>` static initializer slot (if any). `clinit_name`
    /// must be the VM-interned id of `"<clinit>"`.
    pub fn clinit_slot(&self, clinit_name: u32) -> Option<u32> {
        self.methods
            .iter()
            .find(|m| m.static_method && m.name == clinit_name)
            .map(|m| m.slot)
    }
}
