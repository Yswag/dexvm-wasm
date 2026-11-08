//! Bridge-side natives registered on top of the stock dexvm shim tables.
//!
//! These cover host APIs that dexvm 0.2.0 either lacks (`Jsoup.parse(InputStream,
//! String, String)`, used by 1.6-era sources) or implements behind the `quickjs`
//! C feature (`app.cash.quickjs.QuickJs`, which we replace with the loader's
//! `host.eval_js` import). Nothing here changes the upstream crate.

use dexvm::vm::error::JvmError;
use dexvm::vm::object::Native;
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
    // Extensions commonly pass a null baseUri/charset; treat those as "".
    let base = if args.len() > 1 && vm.payload_of(args[1]).is_some() {
        args[1]
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
// script to the loader's `eval_js` import and converts the JSON result back
// to a primitive. `compile`/`execute` (QuickJS bytecode) are not supported.

fn quickjs_create(vm: &mut Vm, _args: &[JValue]) -> Result<JValue, NatErr> {
    let cid = vm
        .ensure_class_by_desc("Lapp/cash/quickjs/QuickJs;")
        .map_err(NatErr::Fatal)?;
    let inst = vm.alloc_instance(cid).map_err(NatErr::Fatal)?;
    Ok(JValue::Obj(inst))
}

fn json_to_jvalue(vm: &mut Vm, v: &Value) -> JValue {
    match v {
        Value::Null => JValue::Null,
        Value::Bool(b) => JValue::Int(i32::from(*b)),
        Value::String(s) => vm.alloc_string(s),
        Value::Number(n) => {
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
        other => vm.alloc_string(&other.to_string()),
    }
}

fn quickjs_evaluate(vm: &mut Vm, args: &[JValue]) -> Result<JValue, NatErr> {
    let src = vm.str_of_jvalue(args[0]).unwrap_or_default();
    match crate::host::host_eval(&src) {
        Ok(v) => Ok(json_to_jvalue(vm, &v)),
        Err(e) => {
            log::warn!("quickjs shim: evaluate failed: {e}");
            Ok(JValue::Null)
        }
    }
}

fn quickjs_close(_vm: &mut Vm, _args: &[JValue]) -> Result<JValue, NatErr> {
    Ok(JValue::Null)
}

fn unsupported(_vm: &mut Vm, _args: &[JValue]) -> Result<JValue, NatErr> {
    log::warn!("quickjs shim: compile/execute (QuickJS bytecode) is not supported");
    Ok(JValue::Null)
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
        unsupported,
    ),
    entry!(
        "Lapp/cash/quickjs/QuickJs;",
        "execute",
        "([B)Ljava/lang/Object;",
        true,
        unsupported,
    ),
];
