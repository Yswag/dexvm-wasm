//! Shared, in-wasm cookie jar.
//!
//! `host.http` and `android.webkit.CookieManager` must see the same store:
//! extensions (and the host's WebView challenge flow) set cookies through
//! CookieManager, and the next HTTP request has to send them. Keeping the jar
//! bridge-side needs no extra wasm import — the host can seed/read it through
//! the `cookies` op.

use std::cell::RefCell;
use std::collections::BTreeMap;

thread_local! {
    static JAR: RefCell<BTreeMap<String, BTreeMap<String, String>>> =
        const { RefCell::new(BTreeMap::new()) };
}

/// Lowercased host of an absolute URL, or "" when it cannot be parsed.
pub fn host_of(url: &str) -> String {
    let Some((_, rest)) = url.split_once("://") else {
        return String::new();
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host);
    host.to_ascii_lowercase()
}

fn domain_key(url_or_host: &str) -> String {
    let h = host_of(url_or_host);
    if h.is_empty() {
        url_or_host.trim_start_matches('.').to_ascii_lowercase()
    } else {
        h
    }
}

/// `a=b; c=d` for the URL's host, or None when the jar has nothing.
pub fn cookie_header(url: &str) -> Option<String> {
    let host = host_of(url);
    JAR.with(|jar| {
        let jar = jar.borrow();
        let values = jar.get(&host)?;
        if values.is_empty() {
            return None;
        }
        Some(
            values
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    })
}

fn parse_attrs(attrs: &[&str]) -> (Option<String>, bool) {
    let mut domain = None;
    let mut expired = false;
    for attr in attrs {
        let Some((k, v)) = attr.split_once('=') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case("domain") {
            domain = Some(v.trim().trim_start_matches('.').to_ascii_lowercase());
        } else if k.trim().eq_ignore_ascii_case("max-age") {
            if v.trim().parse::<i64>().map(|n| n <= 0).unwrap_or(false) {
                expired = true;
            }
        } else if k.trim().eq_ignore_ascii_case("expires") {
            // A past date is a deletion; checking for 1970 is enough here.
            if v.contains("1970") {
                expired = true;
            }
        }
    }
    (domain, expired)
}

/// Stores one `Set-Cookie` header value, honouring `Domain` and deletions.
pub fn store_set_cookie(request_url: &str, set_cookie: &str) {
    let mut parts = set_cookie.split(';');
    let Some(pair) = parts.next() else { return };
    let Some((name, value)) = pair.split_once('=') else {
        return;
    };
    let name = name.trim();
    if name.is_empty() {
        return;
    }
    let attrs: Vec<&str> = parts.collect();
    let (domain, expired) = parse_attrs(&attrs);
    let host = domain.unwrap_or_else(|| host_of(request_url));
    if host.is_empty() {
        return;
    }
    JAR.with(|jar| {
        let mut jar = jar.borrow_mut();
        if expired || value.trim().is_empty() {
            if let Some(values) = jar.get_mut(&host) {
                values.remove(name);
            }
            return;
        }
        jar.entry(host)
            .or_default()
            .insert(name.to_string(), value.trim().to_string());
    });
}

/// `CookieManager.setCookie(url, "name=value; Path=/; ...")`.
pub fn set_cookie(url: &str, value: &str) {
    store_set_cookie(url, value);
}

pub fn set_cookie_pair(host: &str, name: &str, value: &str) {
    JAR.with(|jar| {
        jar.borrow_mut()
            .entry(domain_key(host))
            .or_default()
            .insert(name.to_string(), value.to_string());
    });
}

pub fn clear() {
    JAR.with(|jar| jar.borrow_mut().clear());
}

pub fn export() -> serde_json::Value {
    JAR.with(|jar| {
        let mut out = serde_json::Map::new();
        for (host, values) in jar.borrow().iter() {
            let mut obj = serde_json::Map::new();
            for (k, v) in values {
                obj.insert(k.clone(), serde_json::Value::String(v.clone()));
            }
            out.insert(host.clone(), serde_json::Value::Object(obj));
        }
        serde_json::Value::Object(out)
    })
}

pub fn import(value: &serde_json::Value) {
    let Some(hosts) = value.as_object() else { return };
    for (host, values) in hosts {
        let Some(values) = values.as_object() else {
            continue;
        };
        for (name, value) in values {
            if let Some(value) = value.as_str() {
                set_cookie_pair(host, name, value);
            }
        }
    }
}
