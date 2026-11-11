//! `dexvm-bridge` — wasm32-wasip1 ABI around the `dexvm` keiyoushi engine.
//!
//! ABI: JSON string in, JSON string out.
//!   alloc(len) -> ptr
//!   dealloc(ptr, len)
//!   call(ptr, len) -> (ptr << 32) | len   (call `dealloc` on the result)
//!
//! The network is never touched here: every OkHttp request that reaches the
//! host layer is forwarded to the imported `host.http` function.

mod cookies;
mod engine;
mod host;
mod shims;

use serde_json::{json, Value};
use std::alloc::{alloc as rust_alloc, dealloc as rust_dealloc, Layout};
use std::panic::{self, AssertUnwindSafe};

#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    if len == 0 {
        return std::ptr::null_mut();
    }
    match Layout::from_size_align(len, 1) {
        Ok(l) => unsafe { rust_alloc(l) },
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn dealloc(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    if let Ok(l) = Layout::from_size_align(len, 1) {
        unsafe { rust_dealloc(ptr, l) }
    }
}

fn pack(bytes: Vec<u8>) -> u64 {
    let mut boxed = bytes.into_boxed_slice();
    let len = boxed.len();
    let ptr = boxed.as_mut_ptr();
    std::mem::forget(boxed);
    ((ptr as u64) << 32) | (len as u64)
}

fn error_envelope(kind: &str, message: impl Into<String>) -> Vec<u8> {
    json!({"ok": false, "error": {"kind": kind, "message": message.into()}})
        .to_string()
        .into_bytes()
}

struct HostLogger;

impl log::Log for HostLogger {
    fn enabled(&self, _m: &log::Metadata) -> bool {
        true
    }
    fn log(&self, record: &log::Record) {
        let level = match record.level() {
            log::Level::Trace => 0,
            log::Level::Debug => 1,
            log::Level::Info => 2,
            log::Level::Warn => 3,
            log::Level::Error => 4,
        };
        host::log_line(level, &format!("{}: {}", record.target(), record.args()));
    }
    fn flush(&self) {}
}

fn install_host_logger() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = log::set_logger(&HostLogger);
        log::set_max_level(log::LevelFilter::Warn);
    });
}

fn install_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        panic::set_hook(Box::new(|info| {
            let msg = if let Some(s) = info.payload().downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = info.payload().downcast_ref::<String>() {
                s.clone()
            } else {
                "panic".to_string()
            };
            let loc = info
                .location()
                .map(|l| format!("{}:{}", l.file(), l.line()))
                .unwrap_or_default();
            let native = dexvm::vm::current_native_label().unwrap_or_else(|| "-".into());
            host::log_line(4, &format!("dexvm panic in native [{native}] at {loc}: {msg}"));
        }));
    });
}

#[no_mangle]
pub extern "C" fn call(ptr: *mut u8, len: usize) -> u64 {
    install_panic_hook();
    let input: Vec<u8> = if ptr.is_null() || len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
    };
    let out = match panic::catch_unwind(AssertUnwindSafe(|| dispatch(&input))) {
        Ok(v) => v,
        Err(_) => error_envelope("panicked", "panic caught at the ABI boundary"),
    };
    pack(out)
}

fn dispatch(input: &[u8]) -> Vec<u8> {
    let req: Value = match serde_json::from_slice(input) {
        Ok(v) => v,
        Err(e) => return error_envelope("bad_args", format!("invalid JSON request: {e}")),
    };
    let Some(op) = req.get("op").and_then(|o| o.as_str()) else {
        return error_envelope("bad_args", "missing \"op\"");
    };
    match engine::dispatch(op, &req) {
        Ok(v) => json!({"ok": true, "value": v}).to_string().into_bytes(),
        Err(e) => json!({"ok": false, "error": e}).to_string().into_bytes(),
    }
}
