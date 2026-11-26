//! java.security host shims.

use crate::vm::native::*;

pub(crate) mod ec; // wasm:
mod message_digest;
pub(crate) mod rsa;
mod secure_random;
mod ssl_context;

#[cfg(test)]
mod tests;

/// All java.security native tables, grouped for `register`.
pub(crate) const SECURITY_TABLE: &[&[NativeEntry]] = &[
    ec::TABLE, // wasm:
    message_digest::TABLE,
    rsa::TABLE,
    secure_random::TABLE,
    ssl_context::TABLE,
];
