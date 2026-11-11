//! Engine registry + the `op` table.

use dexvm::keiyoushi::{
    Chapter, FilterDef, FilterKind, FilterState, HttpData, HttpResp, Keiyoushi, Manga, PageRef,
    Source,
};
use dexvm::vm::error::JvmError;
use dexvm::vm::object::{Native, PreferenceValue};
use dexvm::vm::value::JValue;
use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::HashMap;

type R<T> = Result<T, Value>;

fn err(kind: &str, msg: impl Into<String>) -> Value {
    json!({"kind": kind, "message": msg.into()})
}

struct Engine {
    k: Keiyoushi,
    sources: Option<Vec<Source>>,
}

#[derive(Clone, Debug, Default)]
struct Captured {
    url: String,
    method: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
}

thread_local! {
    static ENGINES: RefCell<Vec<Option<Engine>>> = const { RefCell::new(Vec::new()) };
    static CAPTURE: RefCell<Option<Captured>> = const { RefCell::new(None) };
    static LAST_HTTP_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
    static LAST_CONTENT_TYPE: RefCell<Option<String>> = const { RefCell::new(None) };
    // Image CDNs in front of some sites reject requests without a Referer;
    // mihon's own client ends up sending one. While an image op is running we
    // fill it in when the extension's request does not.
    static DEFAULT_REFERER: RefCell<Option<String>> = const { RefCell::new(None) };
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

/// The callback handed to `Keiyoushi::set_http`. Synchronous by construction:
/// the host import does a synchronous XHR under the hood.
fn on_http(req: &HttpData) -> HttpResp {
    let mut req = req.clone();
    let has_referer = req
        .headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("referer") && !v.is_empty());
    if !has_referer {
        let referer = DEFAULT_REFERER.with(|c| c.borrow().clone());
        if let Some(r) = referer {
            // Some sources compute the Referer from a Page field that is empty
            // in the headless flow; replace the empty header, don't append.
            req.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("referer"));
            req.headers.push(("Referer".to_string(), r));
        }
    }
    let req = &req;
    if CAPTURE.with(|c| c.borrow().is_some()) {
        CAPTURE.with(|c| {
            *c.borrow_mut() = Some(Captured {
                url: req.url.clone(),
                method: req.method.clone(),
                headers: req.headers.clone(),
                body: req.body.clone(),
            })
        });
        // A capture run only wants the outgoing request; answer with an empty
        // 200 so the chain unwinds without touching the network.
        return HttpResp {
            code: 200,
            message: "OK".into(),
            headers: Vec::new(),
            body: Some(Vec::new()),
        };
    }
    match crate::host::http_call(req) {
        Ok(r) => {
            LAST_CONTENT_TYPE.with(|c| {
                *c.borrow_mut() = r
                    .header("content-type")
                    .map(|s| s.to_string())
            });
            r
        }
        Err(e) => {
            LAST_HTTP_ERROR.with(|c| *c.borrow_mut() = Some(e.clone()));
            HttpResp {
                code: 0,
                message: "host-http-error".into(),
                headers: Vec::new(),
                body: Some(format!("dexvm host http error: {e}").into_bytes()),
            }
        }
    }
}

fn take_http_error() -> Option<String> {
    LAST_HTTP_ERROR.with(|c| c.borrow_mut().take())
}

fn java_err(k: &mut Keiyoushi, e: JvmError) -> Value {
    let msg = k.describe_error(&e);
    let kind = match &e {
        JvmError::Uncaught(_) => "java",
        JvmError::Resolution(_) | JvmError::Decode(_) => "vm",
        JvmError::BudgetExceeded => "budget",
        JvmError::StackOverflow => "stack",
        JvmError::Exit(_) => "exit",
        JvmError::Fatal(_) => "fatal",
    };
    let mut v = err(kind, msg);
    if let Some(net) = take_http_error() {
        v["message"] = json!(format!("{} (network: {})", v["message"].as_str().unwrap_or(""), net));
        v["httpError"] = json!(net);
    }
    v
}

fn e_arg(k: &mut Keiyoushi, e: JvmError) -> Value {
    java_err(k, e)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn handle_of(req: &Value) -> R<u32> {
    req.get("handle")
        .and_then(|h| h.as_u64())
        .map(|h| h as u32)
        .ok_or_else(|| err("bad_args", "missing \"handle\""))
}

fn with_engine<T>(h: u32, f: impl FnOnce(&mut Engine) -> R<T>) -> R<T> {
    ENGINES.with(|e| {
        let mut v = e.borrow_mut();
        match v.get_mut(h as usize).and_then(|x| x.as_mut()) {
            Some(eng) => f(eng),
            None => Err(err("not_found", format!("no engine for handle {h}"))),
        }
    })
}

fn sources_of(e: &mut Engine) -> R<Vec<Source>> {
    if e.sources.is_none() {
        match e.k.sources() {
            Ok(s) => e.sources = Some(s),
            Err(er) => return Err(e_arg(&mut e.k, er)),
        }
    }
    Ok(e.sources.clone().unwrap_or_default())
}

fn id_arg(req: &Value) -> i64 {
    match req.get("sourceId") {
        Some(Value::String(s)) => s.parse::<i64>().unwrap_or(-1),
        Some(v) => v.as_i64().unwrap_or(-1),
        None => -1,
    }
}

fn source_by_id(e: &mut Engine, id: i64) -> R<Source> {
    let srcs = sources_of(e)?;
    for s in srcs {
        if let Ok(sid) = e.k.source_id(&s) {
            if sid == id {
                return Ok(s);
            }
        }
    }
    Err(err("not_found", format!("no source with id {id}")))
}

fn str_of_opt(k: &mut Keiyoushi, v: JValue) -> Option<String> {
    k.ctx().vm().str_of_jvalue(v)
}

fn manga_json(m: &Manga) -> Value {
    json!({
        "title": m.title,
        "author": m.author,
        "artist": m.artist,
        "description": m.description,
        "genre": m.genre,
        "status": m.status,
        "thumbnailUrl": m.thumbnail_url,
        "url": m.url,
    })
}

fn manga_from(v: &Value) -> Manga {
    Manga {
        title: s(v, "title"),
        author: s(v, "author"),
        artist: s(v, "artist"),
        description: s(v, "description"),
        genre: s(v, "genre"),
        status: v.get("status").and_then(|x| x.as_i64()).unwrap_or(0) as i32,
        thumbnail_url: s(v, "thumbnailUrl"),
        url: s(v, "url"),
    }
}

fn chapter_json(c: &Chapter) -> Value {
    json!({
        "name": c.name,
        "url": c.url,
        "dateUpload": c.date_upload,
        "scanlator": c.scanlator,
    })
}

fn chapter_from(v: &Value) -> Chapter {
    Chapter {
        name: s(v, "name"),
        url: s(v, "url"),
        date_upload: v.get("dateUpload").and_then(|x| x.as_i64()).unwrap_or(0),
        scanlator: s(v, "scanlator"),
    }
}

fn page_json(p: &PageRef) -> Value {
    json!({
        "index": p.index,
        "name": p.name,
        "url": p.url,
        "imageUrl": p.image_url,
    })
}

fn page_from(v: &Value) -> PageRef {
    PageRef {
        index: v.get("index").and_then(|x| x.as_i64()).unwrap_or(0) as i32,
        name: s(v, "name"),
        url: s(v, "url"),
        image_url: s(v, "imageUrl"),
    }
}

fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or_default().to_string()
}

fn pages_json(p: &dexvm::keiyoushi::MangaPages) -> Value {
    json!({
        "mangas": p.mangas.iter().map(manga_json).collect::<Vec<_>>(),
        "hasNextPage": p.has_next,
    })
}

fn filter_kind_str(k: FilterKind) -> &'static str {
    match k {
        FilterKind::Plain => "plain",
        FilterKind::Header => "header",
        FilterKind::Separator => "separator",
        FilterKind::Text => "text",
        FilterKind::Select => "select",
        FilterKind::TriState => "tristate",
        FilterKind::Group => "group",
    }
}

fn filter_json(f: &FilterDef) -> Value {
    json!({
        "kind": filter_kind_str(f.kind),
        "name": f.name,
        "state": f.state,
        "options": f.options,
    })
}

fn filters_from(v: &Value) -> Vec<FilterState> {
    let mut out = Vec::new();
    if let Some(arr) = v.get("filters").and_then(|f| f.as_array()) {
        for item in arr {
            out.push(FilterState {
                name: s(item, "name"),
                state: item.get("state").and_then(|x| x.as_i64()).unwrap_or(0) as i32,
            });
        }
    }
    out
}

fn page_obj(k: &mut Keiyoushi, p: &PageRef) -> Result<JValue, JvmError> {
    let cid = k
        .ctx()
        .vm()
        .ensure_class_by_desc("Leu/kanade/tachiyomi/source/model/Page;")?;
    let id = k.ctx().vm().arena.alloc(
        cid,
        Vec::new(),
        Some(Native::SPPage {
            index: p.index,
            name: p.name.clone(),
            url: p.url.clone(),
            image_url: p.image_url.clone(),
        }),
    );
    Ok(JValue::Obj(id))
}

/// Runs `fetchImageUrl(page)` (the lazy image-URL step some sources need) and
/// falls back to the URL the page list already carried.
fn base_url_of(k: &mut Keiyoushi, src: &Source) -> Option<String> {
    k.ctx()
        .invoke_on(src.inst(), "getBaseUrl", "()Ljava/lang/String;", &[])
        .ok()
        .and_then(|v| str_of_opt(k, v))
        .filter(|s| !s.is_empty())
}

fn resolve_image_url(k: &mut Keiyoushi, src: &Source, p: &PageRef) -> String {
    if let Ok(pj) = page_obj(k, p) {
        let sig = "(Leu/kanade/tachiyomi/source/model/Page;)Lrx/Observable;";
        if let Ok(v) = k.ctx().invoke_on(src.inst(), "fetchImageUrl", sig, &[pj]) {
            if let Some(Native::RxObservable {
                values, error, ..
            }) = k.ctx().vm().payload_of(v)
            {
                if matches!(error, JValue::Null) {
                    if let Some(first) = values.first().copied() {
                        if let Some(s) = str_of_opt(k, first) {
                            if !s.is_empty() {
                                return s;
                            }
                        }
                    }
                }
            }
        }
    }
    p.image_url.clone()
}

/// Builds the request via the extension's own `getImageRequest(page)` and
/// executes it through its client, so per-page headers (Referer, Accept, …)
/// and image interceptors run exactly like in Mihon.
fn image_response(
    k: &mut Keiyoushi,
    src: &Source,
    p: &PageRef,
    url: &str,
) -> Result<JValue, JvmError> {
    let pj = page_obj(k, p)?;
    // 1.6 sources override `getImageRequest(Page)`; older ones override the
    // legacy `imageRequest(Page)`. Try both and keep the request that actually
    // carries headers (the one the extension customised).
    let mut req = match k.ctx().invoke_on(
        src.inst(),
        "getImageRequest",
        "(Leu/kanade/tachiyomi/source/model/Page;)Lokhttp3/Request;",
        &[pj],
    ) {
        Ok(r) => r,
        Err(e) => {
            log::debug!("bridge: getImageRequest failed ({e}); falling back to a bare GET");
            let cid = k.ctx().vm().ensure_class_by_desc("Lokhttp3/Request;")?;
            let inst = k.ctx().vm().arena.alloc(
                cid,
                Vec::new(),
                Some(Native::Request {
                    url: url.to_string(),
                    method: "GET".to_string(),
                    headers: Vec::new(),
                    body: None,
                }),
            );
            JValue::Obj(inst)
        }
    };
    if request_headers(k, req).map_or(true, |h| h.is_empty()) {
        if let Ok(r2) = k.ctx().invoke_on(
            src.inst(),
            "imageRequest",
            "(Leu/kanade/tachiyomi/source/model/Page;)Lokhttp3/Request;",
            &[pj],
        ) {
            if request_headers(k, r2).is_some_and(|h| !h.is_empty()) {
                req = r2;
            }
        }
    }
    if log::log_enabled!(log::Level::Debug) {
        if let Some(Native::Request {
            url: ru,
            method: rm,
            headers: rh,
            ..
        }) = k.ctx().vm().payload_of(req)
        {
            log::debug!("bridge: getImageRequest -> {rm} {ru} headers={rh:?}");
        }
    }
    let client = k
        .ctx()
        .invoke_on(src.inst(), "getClient", "()Lokhttp3/OkHttpClient;", &[])
        .map_err(|e| {
            log::debug!("bridge: image getClient failed: {e}");
            e
        })?;
    let call = k
        .ctx()
        .invoke_on(
            client.as_obj(),
            "newCall",
            "(Lokhttp3/Request;)Lokhttp3/Call;",
            &[req],
        )
        .map_err(|e| {
            log::debug!("bridge: image newCall failed: {e}");
            e
        })?;
    k.ctx()
        .invoke_on(call.as_obj(), "execute", "()Lokhttp3/Response;", &[])
        .map_err(|e| {
            log::debug!("bridge: image execute failed: {e}");
            e
        })
}

fn request_headers(k: &mut Keiyoushi, req: JValue) -> Option<Vec<(String, String)>> {
    match k.ctx().vm().payload_of(req) {
        Some(Native::Request { headers, .. }) => Some(headers.clone()),
        _ => None,
    }
}

fn response_bytes(k: &mut Keiyoushi, resp: JValue) -> Option<Vec<u8>> {
    match k.ctx().vm().payload_of(resp) {
        Some(Native::Response { body: Some(b), .. }) => Some(b.clone()),
        Some(Native::Response { body: None, .. }) => Some(Vec::new()),
        _ => None,
    }
}


fn preference_value(v: &Value) -> PreferenceValue {
    match v {
        Value::Bool(b) => PreferenceValue::Bool(*b),
        Value::String(s) => PreferenceValue::String(s.clone()),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                if i >= i32::MIN as i64 && i <= i32::MAX as i64 {
                    PreferenceValue::Int(i as i32)
                } else {
                    PreferenceValue::Long(i)
                }
            } else {
                PreferenceValue::Float(n.as_f64().unwrap_or(0.0) as f32)
            }
        }
        _ => PreferenceValue::String(String::new()),
    }
}

fn preference_json(v: &PreferenceValue) -> Value {
    match v {
        PreferenceValue::Bool(b) => json!(b),
        PreferenceValue::String(s) => json!(s),
        PreferenceValue::Int(i) => json!(i),
        PreferenceValue::Long(l) => json!(l),
        PreferenceValue::Float(f) => json!(f),
    }
}

fn setting_json(k: &mut Keiyoushi, d: &dexvm::context::SettingDefinition) -> Value {
    let default = match d.default_value {
        JValue::Int(i) => json!(i),
        JValue::Long(l) => json!(l),
        JValue::Float(f) => json!(f),
        JValue::Double(f) => json!(f),
        JValue::Obj(id) => match k.string_of(id) {
            Some(s) => json!(s),
            None => Value::Null,
        },
        JValue::Null => Value::Null,
    };
    json!({
        "key": d.key,
        "title": d.title,
        "summary": d.summary,
        "defaultValue": default,
        "enabled": d.enabled,
        "visible": d.visible,
        "kind": d.kind,
        "entries": d.entries,
        "entryValues": d.entry_values,
        "defaultText": d.default_text,
        "defaultValues": d.default_values,
        "children": d.children.iter().map(|c| setting_json(k, c)).collect::<Vec<_>>(),
    })
}


// --- op wrappers -----------------------------------------------------------
// Modern (1.6-era) extensions override the suspend/coroutine entry points and
// leave the Rx request/parse pair as stubs, while older ones do the opposite.
// Try the upstream path first, then the coroutine path; report the first error
// if both fail (it is usually the informative one).

fn both(k: &mut Keiyoushi, first: JvmError, second: JvmError) -> String {
    let a = k.describe_error(&first);
    let b = k.describe_error(&second);
    format!("{a}  [fallback: {b}]")
}

fn do_popular(e: &mut Engine, src: &Source, page: i32) -> Result<dexvm::keiyoushi::MangaPages, String> {
    match e.k.popular(src, page) {
        Ok(v) => Ok(v),
        Err(first) => match e.k.popular_coro(src, page) {
            Ok(v) => Ok(v),
            Err(second) => Err(both(&mut e.k, first, second)),
        },
    }
}

fn do_latest(e: &mut Engine, src: &Source, page: i32) -> Result<dexvm::keiyoushi::MangaPages, String> {
    match e.k.latest(src, page) {
        Ok(v) => Ok(v),
        Err(first) => match e.k.latest_coro(src, page) {
            Ok(v) => Ok(v),
            Err(second) => Err(both(&mut e.k, first, second)),
        },
    }
}

fn do_search(
    e: &mut Engine,
    src: &Source,
    page: i32,
    query: &str,
    filters: &[FilterState],
) -> Result<dexvm::keiyoushi::MangaPages, String> {
    match e.k.search(src, page, query, filters) {
        Ok(v) => Ok(v),
        Err(first) => match e.k.search_coro(src, page, query, filters) {
            Ok(v) => Ok(v),
            Err(second) => Err(both(&mut e.k, first, second)),
        },
    }
}

fn do_details(e: &mut Engine, src: &Source, m: &Manga) -> Result<Manga, String> {
    match e.k.manga_details(src, m) {
        Ok(v) => Ok(v),
        Err(first) => match e.k.manga_update_details(src, m) {
            Ok(v) => Ok(v),
            Err(second) => Err(both(&mut e.k, first, second)),
        },
    }
}

fn do_chapters(e: &mut Engine, src: &Source, m: &Manga) -> Result<Vec<Chapter>, String> {
    match e.k.chapters(src, m) {
        Ok(v) => Ok(v),
        Err(first) => match e.k.manga_update_chapters(src, m) {
            Ok(v) => Ok(v),
            Err(second) => Err(both(&mut e.k, first, second)),
        },
    }
}

fn do_pages(e: &mut Engine, src: &Source, c: &Chapter) -> Result<Vec<PageRef>, String> {
    match e.k.pages(src, c) {
        Ok(v) => Ok(v),
        Err(first) => match e.k.pages_coro(src, c) {
            Ok(v) => Ok(v),
            Err(second) => Err(both(&mut e.k, first, second)),
        },
    }
}

/// Attaches the last host HTTP error (if any) to a message.
fn fail(e: &mut Engine, kind: &str, msg: String) -> Value {
    let _ = e;
    let mut v = err(kind, msg);
    if let Some(net) = take_http_error() {
        v["message"] = json!(format!("{} (network: {})", v["message"].as_str().unwrap_or(""), net));
        v["httpError"] = json!(net);
    }
    v
}

// ---------------------------------------------------------------------------
// dispatch
// ---------------------------------------------------------------------------

pub fn dispatch(op: &str, req: &Value) -> R<Value> {
    match op {
        "open" => op_open(req),
        _ => {
            let h = handle_of(req)?;
            match op {
                "sources" => with_engine(h, |e| { let srcs = sources_of(e)?; Ok(sources_json(&mut e.k, &srcs)) }),
                "popular" | "latest" => with_engine(h, |e| op_list(e, req, op)),
                "filters" => with_engine(h, |e| op_filters(e, req)),
                "search" => with_engine(h, |e| op_search(e, req)),
                "details" => with_engine(h, |e| op_details(e, req)),
                "chapters" => with_engine(h, |e| op_chapters(e, req)),
                "pages" => with_engine(h, |e| op_pages(e, req)),
                "imageUrl" => with_engine(h, |e| op_image_url(e, req)),
                "imageRequest" => with_engine(h, |e| op_image_request(e, req)),
                "fetchImage" => with_engine(h, |e| op_fetch_image(e, req)),
                "preferences" => with_engine(h, |e| op_preferences(e, req)),
                "setPreference" => with_engine(h, |e| op_set_preference(e, req)),
                "exportPrefs" => with_engine(h, |e| op_export_prefs(e)),
                "close" => op_close(h),
                "debug" => with_engine(h, |e| {
                    let desc = s(req, "class");
                    let loc = e.k.ctx().vm().class_location(&desc);
                    let cid = e.k.ctx().vm().ensure_class_by_desc(&desc).ok();
                    let mut info = serde_json::Map::new();
                    info.insert("location".into(), json!(loc));
                    if let Some(cid) = cid {
                        let vm = e.k.ctx().vm();
                        let c = &vm.classes[cid as usize];
                        info.insert("cid".into(), json!(cid));
                        info.insert("descriptor".into(), json!(vm.str_of(c.descriptor)));
                        info.insert("superclass".into(), json!(vm.str_of(c.superclass.unwrap_or(0))));
                        info.insert("methods".into(), json!(c.methods.len()));
                    }
                    info.insert("classes_loaded".into(), json!(e.k.ctx().vm().classes.len()));
                    info.insert("dexes".into(), json!(e.k.ctx().vm().dexes.len()));
                    Ok(Value::Object(info))
                }),
                other => Err(err("bad_args", format!("unknown op {other}"))),
            }
        }
    }
}

fn op_open(req: &Value) -> R<Value> {
    use base64::Engine as _;
    let b64 = req
        .get("apkBase64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err("bad_args", "missing \"apkBase64\""))?;
    let data = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| err("bad_args", format!("apkBase64 is not valid base64: {e}")))?;
    crate::install_host_logger();
    // Optional per-open log level (0..4 = trace..error); default is warnings.
    if let Some(lvl) = req.get("logLevel").and_then(|v| v.as_u64()) {
        log::set_max_level(match lvl {
            0 => log::LevelFilter::Trace,
            1 => log::LevelFilter::Debug,
            2 => log::LevelFilter::Info,
            3 => log::LevelFilter::Warn,
            _ => log::LevelFilter::Error,
        });
    }
    let mut k = Keiyoushi::new(&data).map_err(|e| err("load", format!("cannot load extension: {e}")))?;
    k.set_http(on_http);
    // Bridge-side extras (Jsoup InputStream overload, quickjs replacement).
    if let Err(e) = k.ctx().register_natives(&[crate::shims::EXTRA_NATIVES]) {
        crate::host::log_line(3, &format!("dexvm-bridge: extra natives failed: {e}"));
    }

    if let Some(prefs) = req.get("prefs").and_then(|p| p.as_object()) {
        for (file, values) in prefs {
            let mut map: HashMap<String, PreferenceValue> = HashMap::new();
            if let Some(obj) = values.as_object() {
                for (key, val) in obj {
                    map.insert(key.clone(), preference_value(val));
                }
            }
            k.seed_preferences(file, &map);
        }
    }

    let manifest = k.manifest().ok();
    let manifest_json = match &manifest {
        Some(m) => json!({
            "packageId": m.package_id,
            "appName": m.app_name,
            "versionName": m.version_name,
            "minSdk": m.min_sdk,
            "targetSdk": m.target_sdk,
            "iconResourceId": m.icon_resource_id,
            // Mihon keeps NSFW in the extension index, not in the APK.
            "nsfw": Value::Null,
        }),
        None => Value::Null,
    };

    let handle = ENGINES.with(|e| {
        let mut v = e.borrow_mut();
        v.push(Some(Engine { k, sources: None }));
        (v.len() - 1) as u32
    });

    Ok(json!({"handle": handle, "manifest": manifest_json}))
}

fn sources_json(k: &mut Keiyoushi, srcs: &[Source]) -> Value {
    let mut out = Vec::new();
    for src in srcs {
        let id = k.source_id(src).unwrap_or(-1);
        let name = k.source_name(src).unwrap_or_default();
        let lang = k.source_lang(src).unwrap_or_default();
        let supports_latest = k.supports_latest(src).unwrap_or(false);
        let base_url = k
            .ctx()
            .invoke_on(src.inst(), "getBaseUrl", "()Ljava/lang/String;", &[])
            .ok()
            .and_then(|v| str_of_opt(k, v))
            .unwrap_or_default();
        out.push(json!({
            // i64 source ids do not survive a JSON number round-trip through
            // JS doubles (they exceed 2^53), so they are sent as strings.
            "id": id.to_string(),
            "name": name,
            "lang": lang,
            "baseUrl": base_url,
            "supportsLatest": supports_latest,
            "nsfw": Value::Null,
        }));
    }
    Value::Array(out)
}

fn op_list(e: &mut Engine, req: &Value, op: &str) -> R<Value> {
    let id = id_arg(req);
    let page = req.get("page").and_then(|v| v.as_i64()).unwrap_or(1) as i32;
    let src = source_by_id(e, id)?;
    let res = if op == "popular" {
        do_popular(e, &src, page)
    } else {
        do_latest(e, &src, page)
    };
    match res {
        Ok(p) => Ok(pages_json(&p)),
        Err(msg) => Err(fail(e, "java", msg)),
    }
}

fn op_filters(e: &mut Engine, req: &Value) -> R<Value> {
    let id = id_arg(req);
    let src = source_by_id(e, id)?;
    match e.k.filters(&src) {
        Ok(f) => Ok(Value::Array(f.iter().map(filter_json).collect())),
        Err(er) => Err(java_err(&mut e.k, er)),
    }
}

fn op_search(e: &mut Engine, req: &Value) -> R<Value> {
    let id = id_arg(req);
    let page = req.get("page").and_then(|v| v.as_i64()).unwrap_or(1) as i32;
    let query = s(req, "query");
    let filters = filters_from(req);
    let src = source_by_id(e, id)?;
    match do_search(e, &src, page, &query, &filters) {
        Ok(p) => Ok(pages_json(&p)),
        Err(msg) => Err(fail(e, "java", msg)),
    }
}

fn op_details(e: &mut Engine, req: &Value) -> R<Value> {
    let id = id_arg(req);
    let manga = manga_from(req.get("manga").unwrap_or(&Value::Null));
    let src = source_by_id(e, id)?;
    match do_details(e, &src, &manga) {
        Ok(m) => Ok(manga_json(&m)),
        Err(msg) => Err(fail(e, "java", msg)),
    }
}

fn op_chapters(e: &mut Engine, req: &Value) -> R<Value> {
    let id = id_arg(req);
    let manga = manga_from(req.get("manga").unwrap_or(&Value::Null));
    let src = source_by_id(e, id)?;
    match do_chapters(e, &src, &manga) {
        Ok(c) => Ok(Value::Array(c.iter().map(chapter_json).collect())),
        Err(msg) => Err(fail(e, "java", msg)),
    }
}

fn op_pages(e: &mut Engine, req: &Value) -> R<Value> {
    let id = id_arg(req);
    let chapter = chapter_from(req.get("chapter").unwrap_or(&Value::Null));
    let src = source_by_id(e, id)?;
    match do_pages(e, &src, &chapter) {
        Ok(p) => Ok(Value::Array(p.iter().map(page_json).collect())),
        Err(msg) => Err(fail(e, "java", msg)),
    }
}

fn op_image_url(e: &mut Engine, req: &Value) -> R<Value> {
    let id = id_arg(req);
    let page = page_from(req.get("page").unwrap_or(&Value::Null));
    let src = source_by_id(e, id)?;
    let url = resolve_image_url(&mut e.k, &src, &page);
    Ok(json!({"imageUrl": url}))
}

fn op_image_request(e: &mut Engine, req: &Value) -> R<Value> {
    let id = id_arg(req);
    let page = page_from(req.get("page").unwrap_or(&Value::Null));
    let src = source_by_id(e, id)?;
    let url = resolve_image_url(&mut e.k, &src, &page);
    if url.is_empty() {
        return Err(err("bad_args", "page has no image url"));
    }
    DEFAULT_REFERER.with(|c| *c.borrow_mut() = base_url_of(&mut e.k, &src));
    CAPTURE.with(|c| *c.borrow_mut() = Some(Captured::default()));
    // The chain stops at the first network touch: our capture hook records the
    // request as it leaves the interceptors and answers with an empty 200, so
    // decrypt/auth interceptors may throw here — the captured request is what
    // we are after.
    if image_response(&mut e.k, &src, &page, &url).is_err() {
        let _ = e.k.image_data(&src, &url);
    }
    let cap = CAPTURE.with(|c| c.borrow_mut().take());
    match cap {
        Some(c) if !c.url.is_empty() => Ok(json!({
            "url": c.url,
            "method": c.method,
            "headers": c.headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
        })),
        _ => Ok(json!({
            "url": url,
            "method": "GET",
            "headers": [],
            "note": "no interceptor reached the host layer; returned the plain image request",
        })),
    }
}

fn op_fetch_image(e: &mut Engine, req: &Value) -> R<Value> {
    use base64::Engine as _;
    let id = id_arg(req);
    let page = page_from(req.get("page").unwrap_or(&Value::Null));
    let src = source_by_id(e, id)?;
    let url = resolve_image_url(&mut e.k, &src, &page);
    if url.is_empty() {
        return Err(err("bad_args", "page has no image url"));
    }
    LAST_CONTENT_TYPE.with(|c| *c.borrow_mut() = None);
    DEFAULT_REFERER.with(|c| *c.borrow_mut() = base_url_of(&mut e.k, &src));
    take_http_error();
    let bytes = match image_response(&mut e.k, &src, &page, &url)
        .ok()
        .and_then(|resp| response_bytes(&mut e.k, resp))
    {
        Some(b) => b,
        None => match e.k.image_data(&src, &url) {
            Ok(b) => b,
            Err(er) => return Err(java_err(&mut e.k, er)),
        },
    };
    let mime = LAST_CONTENT_TYPE.with(|c| c.borrow_mut().take());
    Ok(json!({
        "url": url,
        "bytes": bytes.len(),
        "mime": mime,
        "base64": base64::engine::general_purpose::STANDARD.encode(&bytes),
    }))
}

fn op_preferences(e: &mut Engine, req: &Value) -> R<Value> {
    let id = id_arg(req);
    let src = source_by_id(e, id)?;
    match e.k.preference_definitions(&src) {
        Ok(defs) => {
            let mut out = Vec::new();
            for d in &defs {
                out.push(setting_json(&mut e.k, d));
            }
            Ok(Value::Array(out))
        }
        // Sources without ConfigurableSource simply declare nothing.
        Err(JvmError::Resolution(_)) => Ok(Value::Array(Vec::new())),
        Err(er) => Err(java_err(&mut e.k, er)),
    }
}

fn op_set_preference(e: &mut Engine, req: &Value) -> R<Value> {
    let id = id_arg(req);
    let key = req
        .get("key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err("bad_args", "missing \"key\""))?
        .to_string();
    let value = preference_value(req.get("value").unwrap_or(&Value::Null));
    let src = source_by_id(e, id)?;
    let file = match e.k.preference_file(&src) {
        Ok(f) => f,
        Err(er) => return Err(java_err(&mut e.k, er)),
    };
    match e.k.update_setting(&file, &key, value) {
        Ok(()) => Ok(json!({"file": file, "key": key})),
        Err(er) => Err(err("io", format!("cannot persist setting: {er}"))),
    }
}

fn op_export_prefs(e: &mut Engine) -> R<Value> {
    let names = e.k.preference_file_names();
    let mut out = serde_json::Map::new();
    for name in names {
        let values = e.k.get_settings(&name);
        let mut obj = serde_json::Map::new();
        for (key, value) in values {
            obj.insert(key, preference_json(&value));
        }
        out.insert(name, Value::Object(obj));
    }
    Ok(Value::Object(out))
}

fn op_close(h: u32) -> R<Value> {
    ENGINES.with(|e| {
        let mut v = e.borrow_mut();
        match v.get_mut(h as usize) {
            Some(slot @ Some(_)) => {
                *slot = None;
                Ok(json!(null))
            }
            _ => Err(err("not_found", format!("no engine for handle {h}"))),
        }
    })
}
