//! Bridge-side natives registered on top of the stock dexvm shim tables.
//!
//! These cover host APIs that dexvm 0.2.0 either lacks (`Jsoup.parse(InputStream,
//! String, String)`, used by 1.6-era sources) or implements behind the `quickjs`
//! C feature (`app.cash.quickjs.QuickJs`, which we replace with the loader's
//! `host.eval_js` import). Nothing here changes the upstream crate.

use dexvm::vm::error::JvmError;
use dexvm::vm::object::{ArrayData, Native};
use dexvm::vm::value::JValue;
use dexvm::vm::{NatErr, NativeEntry, Vm};
use serde_json::Value;

fn fatal(msg: impl Into<String>) -> NatErr {
    NatErr::Fatal(JvmError::Resolution(msg.into()))
}

fn stream_bytes(vm: &Vm, v: JValue) -> Result<Vec<u8>, NatErr> {
    let id = v.as_obj();
    match vm
        .arena
        .objects
        .get(id as usize)
        .and_then(|o| o.native.clone())
    {
        Some(Native::ByteArrayInputStream { bytes, pos }) => {
            Ok(bytes[pos.min(bytes.len())..].to_vec())
        }
        Some(Native::Reader(s)) => Ok(s.into_bytes()),
        _ => Err(fatal(
            "Jsoup.parse(InputStream,…): unsupported InputStream kind",
        )),
    }
}

/// `org.jsoup.Jsoup.parse(InputStream, String baseUri, String charset)`.
/// The stream is drained and handed to the registered `parse(String,String)`
/// shim, so callers get the same Document object as the string overload.
fn jsoup_parse_stream(vm: &mut Vm, args: &[JValue]) -> Result<JValue, NatErr> {
    let bytes = stream_bytes(vm, args[0])?;
    let html = String::from_utf8_lossy(&bytes).into_owned();
    // jsoup's signature is parse(InputStream, String charsetName, String baseUri).
    // The base URI is the third argument — using the charset here left
    // Document.location() empty, which some 1.6 sources build Referers from.
    let base = if args.len() > 2 && vm.payload_of(args[2]).is_some() {
        args[2]
    } else {
        vm.alloc_string("")
    };
    let html_obj = vm.alloc_string(&html);
    vm.invoke_static(
        "Lorg/jsoup/Jsoup;",
        "parse",
        "(Ljava/lang/String;Ljava/lang/String;)Lorg/jsoup/nodes/Document;",
        vec![html_obj, base],
    )
    .map_err(NatErr::Fatal)
}

// --- app.cash.quickjs ------------------------------------------------------
// The C QuickJS engine is compiled out for wasm; `evaluate` forwards the
// script to the loader's `eval_js` import. Like Suwayomi's GraalVM shim, JS
// arrays/objects are translated into real Java values (typed arrays, HashMap)
// instead of being stringified, and `compile`/`execute` round-trip the source.

fn quickjs_create(vm: &mut Vm, _args: &[JValue]) -> Result<JValue, NatErr> {
    let cid = vm
        .ensure_class_by_desc("Lapp/cash/quickjs/QuickJs;")
        .map_err(NatErr::Fatal)?;
    let inst = vm.alloc_instance(cid).map_err(NatErr::Fatal)?;
    Ok(JValue::Obj(inst))
}

fn alloc_array(vm: &mut Vm, elem_desc: &str, data: ArrayData) -> Result<JValue, NatErr> {
    let class_desc = format!("[{elem_desc}");
    let cid = vm
        .ensure_class_by_desc(&class_desc)
        .map_err(NatErr::Fatal)?;
    let inst = vm.arena.alloc(cid, Vec::new(), Some(Native::Array(data)));
    Ok(JValue::Obj(inst))
}

fn alloc_ref_array(vm: &mut Vm, elem_desc: &str, values: Vec<JValue>) -> Result<JValue, NatErr> {
    let class_desc = format!("[{elem_desc}");
    let cid = vm
        .ensure_class_by_desc(&class_desc)
        .map_err(NatErr::Fatal)?;
    let inst = vm
        .arena
        .alloc(cid, Vec::new(), Some(Native::Array(ArrayData::Obj(values))));
    Ok(JValue::Obj(inst))
}

fn json_number(n: &serde_json::Number) -> JValue {
    if let Some(i) = n.as_i64() {
        if i >= i32::MIN as i64 && i <= i32::MAX as i64 {
            JValue::Int(i as i32)
        } else {
            JValue::Long(i)
        }
    } else {
        JValue::Double(n.as_f64().unwrap_or(0.0))
    }
}

fn json_array_to_jvalue(vm: &mut Vm, items: &[Value]) -> Result<JValue, NatErr> {
    // Mirrors Suwayomi's QuickJs.translateType: pick a primitive/object array
    // element type so `is IntArray`, `is Array<String>` etc. behave as on ART.
    if items.is_empty() {
        // Suwayomi returns `new int[0]`; a Null here would break `as Array<*>`.
        return alloc_array(vm, "I", ArrayData::Int(Vec::new()));
    }
    if items.iter().all(|v| v.is_boolean()) {
        let data: Vec<bool> = items.iter().map(|v| v.as_bool().unwrap_or(false)).collect();
        return alloc_array(vm, "Z", ArrayData::Bool(data));
    }
    if items.iter().all(|v| v.is_number()) {
        let all_i32 = items.iter().all(|v| {
            v.as_i64()
                .map(|i| i >= i32::MIN as i64 && i <= i32::MAX as i64)
                .unwrap_or(false)
        });
        if all_i32 {
            let data: Vec<i32> = items
                .iter()
                .map(|v| v.as_i64().unwrap_or(0) as i32)
                .collect();
            return alloc_array(vm, "I", ArrayData::Int(data));
        }
        let all_i64 = items.iter().all(|v| v.as_i64().is_some());
        if all_i64 {
            let data: Vec<i64> = items.iter().map(|v| v.as_i64().unwrap_or(0)).collect();
            return alloc_array(vm, "J", ArrayData::Long(data));
        }
        let data: Vec<f64> = items.iter().map(|v| v.as_f64().unwrap_or(0.0)).collect();
        return alloc_array(vm, "D", ArrayData::Double(data));
    }
    if items.iter().all(|v| v.is_string()) {
        let values: Vec<JValue> = items
            .iter()
            .map(|v| vm.alloc_string(v.as_str().unwrap_or_default()))
            .collect();
        return alloc_ref_array(vm, "Ljava/lang/String;", values);
    }
    let values: Vec<JValue> = items.iter().map(|v| json_to_jvalue(vm, v)).collect();
    alloc_ref_array(vm, "Ljava/lang/Object;", values)
}

fn json_object_to_jvalue(
    vm: &mut Vm,
    map: &serde_json::Map<String, Value>,
) -> Result<JValue, NatErr> {
    let mut entries: Vec<(JValue, JValue)> = Vec::with_capacity(map.len());
    for (key, value) in map {
        entries.push((vm.alloc_string(key), json_to_jvalue(vm, value)));
    }
    let cid = vm
        .ensure_class_by_desc("Ljava/util/HashMap;")
        .map_err(NatErr::Fatal)?;
    let inst = vm
        .arena
        .alloc(cid, Vec::new(), Some(Native::Map(entries)));
    Ok(JValue::Obj(inst))
}

fn json_to_jvalue(vm: &mut Vm, v: &Value) -> JValue {
    match v {
        Value::Null => JValue::Null,
        Value::Bool(b) => JValue::Int(i32::from(*b)),
        Value::String(s) => vm.alloc_string(s),
        Value::Number(n) => json_number(n),
        Value::Array(items) => {
            json_array_to_jvalue(vm, items).unwrap_or(JValue::Null)
        }
        Value::Object(map) => {
            json_object_to_jvalue(vm, map).unwrap_or(JValue::Null)
        }
    }
}

fn eval_js(vm: &mut Vm, src: &str) -> Result<JValue, NatErr> {
    match crate::host::host_eval(src) {
        Ok(v) => Ok(json_to_jvalue(vm, &v)),
        Err(e) => {
            log::warn!("quickjs shim: evaluate failed: {e}");
            Ok(JValue::Null)
        }
    }
}

fn quickjs_evaluate(vm: &mut Vm, args: &[JValue]) -> Result<JValue, NatErr> {
    let src = vm.str_of_jvalue(args[0]).unwrap_or_default();
    eval_js(vm, &src)
}

fn quickjs_compile(vm: &mut Vm, args: &[JValue]) -> Result<JValue, NatErr> {
    let src = vm.str_of_jvalue(args[0]).unwrap_or_default();
    let bytes: Vec<i8> = src.into_bytes().into_iter().map(|b| b as i8).collect();
    alloc_array(vm, "B", ArrayData::Byte(bytes))
}

fn quickjs_execute(vm: &mut Vm, args: &[JValue]) -> Result<JValue, NatErr> {
    let src = match vm.payload_of(args[0]) {
        Some(Native::Array(ArrayData::Byte(bytes))) => {
            let raw: Vec<u8> = bytes.iter().map(|b| *b as u8).collect();
            String::from_utf8_lossy(&raw).into_owned()
        }
        _ => String::new(),
    };
    eval_js(vm, &src)
}

fn quickjs_close(_vm: &mut Vm, _args: &[JValue]) -> Result<JValue, NatErr> {
    Ok(JValue::Null)
}

// --- android.webkit.CookieManager ------------------------------------------
// Backed by the bridge's cookie jar, which `host.http` also reads/writes, so
// cookies set by an extension (or pushed in by the host's WebView flow) are
// sent on the next request.

fn cookie_manager_get(vm: &mut Vm, args: &[JValue]) -> Result<JValue, NatErr> {
    let url = vm.str_of_jvalue(args[1]).unwrap_or_default();
    match crate::cookies::cookie_header(&url) {
        Some(c) => Ok(vm.alloc_string(&c)),
        None => Ok(JValue::Null),
    }
}

fn cookie_manager_set(vm: &mut Vm, args: &[JValue]) -> Result<JValue, NatErr> {
    let url = vm.str_of_jvalue(args[1]).unwrap_or_default();
    let value = vm.str_of_jvalue(args[2]).unwrap_or_default();
    if !url.is_empty() && !value.is_empty() {
        crate::cookies::set_cookie(&url, &value);
    }
    Ok(JValue::Null)
}

fn cookie_manager_clear(_vm: &mut Vm, _args: &[JValue]) -> Result<JValue, NatErr> {
    crate::cookies::clear();
    Ok(JValue::Null)
}

fn noop(_vm: &mut Vm, _args: &[JValue]) -> Result<JValue, NatErr> {
    Ok(JValue::Null)
}

// --- okhttp Headers$Builder ------------------------------------------------
// dexvm registers `add`/`set`/`removeAll`/`build` but not the getter that
// 1.6 sources use to read back a header before rebuilding the request.

fn headers_builder_get(vm: &mut Vm, args: &[JValue]) -> Result<JValue, NatErr> {
    let name = vm.str_of_jvalue(args[1]).unwrap_or_default();
    let value = match vm.payload_of(args[0]) {
        Some(Native::Headers(entries)) => entries
            .iter()
            .rev()
            .find(|(k, _)| k.eq_ignore_ascii_case(&name))
            .map(|(_, v)| v.clone()),
        _ => None,
    };
    Ok(match value {
        Some(v) => vm.alloc_string(&v),
        None => JValue::Null,
    })
}

// --- java.time.format.DateTimeFormatter -------------------------------------
// dexvm 0.2.0 only registers the two-arg `ofPattern(String, Locale)`.
// 1.6-era sources (dm5, others) call the single-arg overload.

fn dtf_of_pattern_one(vm: &mut Vm, args: &[JValue]) -> Result<JValue, NatErr> {
    let pattern = vm.str_of_jvalue(args[0]).unwrap_or_default();
    let cid = vm
        .ensure_class_by_desc("Ljava/time/format/DateTimeFormatter;")
        .map_err(NatErr::Fatal)?;
    let inst = vm.arena.alloc(
        cid,
        Vec::new(),
        Some(Native::DateFormatter {
            pattern,
            zone: String::new(),
        }),
    );
    Ok(JValue::Obj(inst))
}

macro_rules! entry {
    ($c:expr, $n:expr, $s:expr, $i:expr, $f:expr $(,)?) => {
        NativeEntry {
            class: $c,
            name: $n,
            sig: $s,
            instance: $i,
            f: $f,
        }
    };
}

pub const EXTRA_NATIVES: &[NativeEntry] = &[
    entry!(
        "Ljava/time/format/DateTimeFormatter;",
        "ofPattern",
        "(Ljava/lang/String;)Ljava/time/format/DateTimeFormatter;",
        false,
        dtf_of_pattern_one,
    ),
    entry!(
        "Lorg/jsoup/Jsoup;",
        "parse",
        "(Ljava/io/InputStream;Ljava/lang/String;Ljava/lang/String;)Lorg/jsoup/nodes/Document;",
        false,
        jsoup_parse_stream,
    ),
    entry!(
        "Lapp/cash/quickjs/QuickJs;",
        "create",
        "()Lapp/cash/quickjs/QuickJs;",
        false,
        quickjs_create,
    ),
    entry!(
        "Lapp/cash/quickjs/QuickJs;",
        "evaluate",
        "(Ljava/lang/String;)Ljava/lang/Object;",
        true,
        quickjs_evaluate,
    ),
    entry!(
        "Lapp/cash/quickjs/QuickJs;",
        "evaluate",
        "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Object;",
        true,
        quickjs_evaluate,
    ),
    entry!(
        "Lapp/cash/quickjs/QuickJs;",
        "close",
        "()V",
        true,
        quickjs_close,
    ),
    entry!(
        "Lapp/cash/quickjs/QuickJs;",
        "compile",
        "(Ljava/lang/String;Ljava/lang/String;)[B",
        true,
        quickjs_compile,
    ),
    entry!(
        "Lapp/cash/quickjs/QuickJs;",
        "execute",
        "([B)Ljava/lang/Object;",
        true,
        quickjs_execute,
    ),
    entry!(
        "Landroid/webkit/CookieManager;",
        "getCookie",
        "(Ljava/lang/String;)Ljava/lang/String;",
        true,
        cookie_manager_get,
    ),
    entry!(
        "Landroid/webkit/CookieManager;",
        "setCookie",
        "(Ljava/lang/String;Ljava/lang/String;)V",
        true,
        cookie_manager_set,
    ),
    entry!(
        "Landroid/webkit/CookieManager;",
        "removeAllCookies",
        "(Landroid/webkit/ValueCallback;)V",
        true,
        cookie_manager_clear,
    ),
    entry!(
        "Landroid/webkit/CookieManager;",
        "removeSessionCookies",
        "(Landroid/webkit/ValueCallback;)V",
        true,
        cookie_manager_clear,
    ),
    entry!(
        "Landroid/webkit/CookieManager;",
        "flush",
        "()V",
        true,
        noop,
    ),
    entry!(
        "Landroid/webkit/CookieManager;",
        "setAcceptCookie",
        "(Z)V",
        true,
        noop,
    ),
    entry!(
        "Lokhttp3/Headers$Builder;",
        "get",
        "(Ljava/lang/String;)Ljava/lang/String;",
        true,
        headers_builder_get,
    ),
];
