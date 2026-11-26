//! Shared, in-wasm cookie jar.
//!
//! `host.http` and `android.webkit.CookieManager` must see the same store:
//! extensions (and the host's WebView challenge flow) set cookies through
//! CookieManager, and the next HTTP request has to send them. Keeping the jar
//! bridge-side needs no extra wasm import — the host can seed/read it through
//! the `cookies` op.
//!
//! Keys in `JAR` distinguish cookie scope:
//! - `".example.com"` (leading dot) = domain-scoped cookie (RFC 6265
//!   domain-match: matches `example.com` and any subdomain `*.example.com`).
//! - `"www.example.com"` (no leading dot) = host-only cookie (matches only
//!   `www.example.com`).
//! Ports are always stripped (cookies are port-independent per RFC 6265).

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr};

thread_local! {
    static JAR: RefCell<BTreeMap<String, BTreeMap<String, String>>> =
        const { RefCell::new(BTreeMap::new()) };
}

fn is_ip_address(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    if let Some(inner) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return inner.parse::<Ipv6Addr>().is_ok();
    }
    false
}

fn strip_port(authority: &str) -> &str {
    let hostport = authority.rsplit('@').next().unwrap_or(authority);
    if hostport.starts_with('[') {
        if let Some(end) = hostport.find(']') {
            return &hostport[..=end];
        }
        return hostport;
    }
    // Single ':' means host:port; multiple ':' means a bare IPv6 address.
    if hostport.bytes().filter(|&b| b == b':').count() == 1 {
        hostport.split(':').next().unwrap_or(hostport)
    } else {
        hostport
    }
}

/// Lowercased host (without port) of an absolute URL, or "" when it cannot be parsed.
pub fn host_of(url: &str) -> String {
    let Some((_, rest)) = url.split_once("://") else {
        return String::new();
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    strip_port(authority).to_ascii_lowercase()
}

/// Normalizes a URL or host/domain string into a jar key (without port).
///
/// - Full URLs (`https://host:port/...`) become host-only keys (`"host"`).
/// - Bare strings starting with `'.'` (e.g. `".example.com"` or `".example.com:8443"`)
///   become domain-scoped keys (`".example.com"`).
/// - Bare hosts (e.g. `"127.0.0.1:52987"` or `"www.example.com"`) become host-only
///   keys (`"127.0.0.1"`, `"www.example.com"`).
fn domain_key(url_or_host: &str) -> String {
    let trimmed = url_or_host.trim();
    if trimmed.contains("://") {
        return host_of(trimmed);
    }
    let is_domain = trimmed.starts_with('.');
    let rest = trimmed.trim_start_matches('.');
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = strip_port(authority).to_ascii_lowercase();
    if host.is_empty() {
        return String::new();
    }
    if is_domain {
        format!(".{host}")
    } else {
        host
    }
}

/// RFC 6265 §5.1.3 domain-match: `domain` (lowercased, no leading dot) matches
/// `host` (lowercased, no port) iff they are identical, or `host` is a non-IP
/// subdomain ending with `".{domain}"`.
fn domain_matches(host: &str, domain: &str) -> bool {
    if host.is_empty() || domain.is_empty() {
        return false;
    }
    if host == domain {
        return true;
    }
    if is_ip_address(host) {
        return false;
    }
    host.len() > domain.len()
        && host.ends_with(domain)
        && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
}

/// All `(name, value)` pairs in the jar that match `url`'s host, with more
/// specific domains (and host-only entries) taking precedence on name collision.
pub fn cookie_pairs_for(url: &str) -> Vec<(String, String)> {
    let host = host_of(url);
    if host.is_empty() {
        return Vec::new();
    }
    JAR.with(|jar| {
        let jar = jar.borrow();
        let mut matched: Vec<(bool, usize, &BTreeMap<String, String>)> = Vec::new();
        for (key, values) in jar.iter() {
            if values.is_empty() {
                continue;
            }
            if let Some(domain) = key.strip_prefix('.') {
                if domain_matches(&host, domain) {
                    matched.push((false, domain.len(), values));
                }
            } else if key == &host {
                matched.push((true, key.len(), values));
            }
        }
        if matched.is_empty() {
            return Vec::new();
        }
        // Apply less-specific domain cookies first, then more-specific domains,
        // and host-only cookies last so more-specific entries win on collision.
        matched.sort_by_key(|(is_host_only, len, _)| (*is_host_only, *len));
        let mut merged: BTreeMap<String, String> = BTreeMap::new();
        for (_, _, values) in matched {
            for (k, v) in values {
                merged.insert(k.clone(), v.clone());
            }
        }
        merged.into_iter().collect()
    })
}

/// `a=b; c=d` for the URL's host, or None when the jar has nothing matching.
pub fn cookie_header(url: &str) -> Option<String> {
    let pairs = cookie_pairs_for(url);
    if pairs.is_empty() {
        return None;
    }
    Some(
        pairs
            .into_iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; "),
    )
}

/// Merges matching jar cookies into an existing `Cookie` header value.
///
/// Preserves all pairs already present in `existing` and appends any matching
/// jar cookies whose name is not already present. Returns `None` if no jar
/// cookies match `url`.
pub fn merge_cookie_header(existing: &str, url: &str) -> Option<String> {
    let jar_pairs = cookie_pairs_for(url);
    if jar_pairs.is_empty() {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    let mut existing_names: Vec<String> = Vec::new();
    for raw in existing.split(';') {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((name, _)) = trimmed.split_once('=') {
            existing_names.push(name.trim().to_string());
        }
        parts.push(trimmed.to_string());
    }
    for (k, v) in jar_pairs {
        if !existing_names.iter().any(|n| n == &k) {
            parts.push(format!("{k}={v}"));
        }
    }
    Some(parts.join("; "))
}

fn parse_attrs(attrs: &[&str]) -> (Option<String>, bool) {
    let mut domain = None;
    let mut expired = false;
    for attr in attrs {
        let Some((k, v)) = attr.split_once('=') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case("domain") {
            let cleaned = strip_port(v.trim().trim_start_matches('.')).to_ascii_lowercase();
            if !cleaned.is_empty() {
                domain = Some(cleaned);
            }
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

/// Stores one `Set-Cookie` header value, honouring RFC 6265 `Domain` scoping and deletions.
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
    let req_host = host_of(request_url);
    let key = match domain {
        Some(dom) => {
            // RFC 6265 §5.3 step 6: ignore cookies whose Domain does not domain-match request host.
            if !req_host.is_empty() && !domain_matches(&req_host, &dom) {
                return;
            }
            format!(".{dom}")
        }
        None => {
            if req_host.is_empty() {
                return;
            }
            req_host
        }
    };
    JAR.with(|jar| {
        let mut jar = jar.borrow_mut();
        if expired || value.trim().is_empty() {
            if let Some(values) = jar.get_mut(&key) {
                values.remove(name);
            }
            return;
        }
        jar.entry(key)
            .or_default()
            .insert(name.to_string(), value.trim().to_string());
    });
}

/// `CookieManager.setCookie(url, "name=value; Path=/; ...")`.
pub fn set_cookie(url: &str, value: &str) {
    store_set_cookie(url, value);
}

pub fn set_cookie_pair(host: &str, name: &str, value: &str) {
    let key = domain_key(host);
    if key.is_empty() || name.is_empty() {
        return;
    }
    JAR.with(|jar| {
        jar.borrow_mut()
            .entry(key)
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
