//! Host imports provided by `dexvm-host.js` (module name `host`).
//!
//! All three imports are synchronous. The host returns a packed `u64`
//! (`ptr << 32 | len`) pointing at memory it allocated through our `alloc`
//! export; we copy the bytes out and free them through `dealloc`.

use dexvm::keiyoushi::HttpData;
use dexvm::keiyoushi::HttpResp;
use serde_json::{json, Value};

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "host")]
extern "C" {
    fn http(req_ptr: *const u8, req_len: usize) -> u64;
    fn log(level: u32, ptr: *const u8, len: usize);
    fn eval_js(ptr: *const u8, len: usize) -> u64;
}

#[cfg(not(target_arch = "wasm32"))]
mod stubs {
    // Native (non-wasm) builds are only used for `cargo check`/unit tests;
    // there is no host, so every import fails cleanly.
    pub unsafe fn http(_p: *const u8, _l: usize) -> u64 {
        0
    }
    pub unsafe fn log(_l: u32, _p: *const u8, _n: usize) {}
    pub unsafe fn eval_js(_p: *const u8, _l: usize) -> u64 {
        0
    }
}
#[cfg(not(target_arch = "wasm32"))]
use stubs::{eval_js, http, log};

fn unpack(v: u64) -> (u32, u32) {
    ((v >> 32) as u32, (v & 0xffff_ffff) as u32)
}

/// Takes ownership of a buffer the host allocated via `alloc` and copies it out.
unsafe fn take_buf(packed: u64) -> Option<Vec<u8>> {
    let (ptr, len) = unpack(packed);
    if ptr == 0 {
        return None;
    }
    let bytes = std::slice::from_raw_parts(ptr as *const u8, len as usize).to_vec();
    crate::dealloc(ptr as *mut u8, len as usize);
    Some(bytes)
}

pub fn log_line(level: u32, msg: &str) {
    unsafe { log(level, msg.as_ptr(), msg.len()) }
}

/// Calls the host `http` import for one request.
pub fn http_call(req: &HttpData) -> Result<HttpResp, String> {
    let mut body = json!({
        "url": req.url,
        "method": req.method,
        "headers": req.headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
    });
    if let Some(b) = &req.body {
        use base64::Engine as _;
        body["bodyBase64"] = json!(base64::engine::general_purpose::STANDARD.encode(b.as_bytes()));
    }
    let bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
    let packed = unsafe { http(bytes.as_ptr(), bytes.len()) };
    let out = unsafe { take_buf(packed) }
        .ok_or_else(|| "host http returned null (alloc failed)".to_string())?;
    let v: Value =
        serde_json::from_slice(&out).map_err(|e| format!("bad host http json: {e}"))?;
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        return Err(err.to_string());
    }
    let code = v.get("status").and_then(|s| s.as_i64()).unwrap_or(0) as i32;
    let mut headers = Vec::new();
    if let Some(arr) = v.get("headers").and_then(|h| h.as_array()) {
        for pair in arr {
            if let Some(p) = pair.as_array() {
                if p.len() == 2 {
                    let k = p[0].as_str().unwrap_or_default().to_string();
                    let val = p[1].as_str().unwrap_or_default().to_string();
                    headers.push((k, val));
                }
            }
        }
    }
    let body = v
        .get("bodyBase64")
        .and_then(|b| b.as_str())
        .and_then(|b| {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.decode(b).ok()
        });
    Ok(HttpResp {
        code,
        message: "OK".into(),
        headers,
        body,
    })
}

/// Runs a JS snippet in the host (`new Function`/`eval`), returning its JSON
/// encoded result: `{"ok":true,"value":...}` or `{"ok":false,"error":"..."}`.
pub fn host_eval(src: &str) -> Result<Value, String> {
    let packed = unsafe { eval_js(src.as_ptr(), src.len()) };
    let out = unsafe { take_buf(packed) }
        .ok_or_else(|| "host eval_js returned null (not provided by loader)".to_string())?;
    let v: Value =
        serde_json::from_slice(&out).map_err(|e| format!("bad host eval_js json: {e}"))?;
    if v.get("ok").and_then(|o| o.as_bool()).unwrap_or(false) {
        Ok(v.get("value").cloned().unwrap_or(Value::Null))
    } else {
        Err(v
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("eval_js failed")
            .to_string())
    }
}
