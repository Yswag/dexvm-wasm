//! java.math host shims.

mod bigdecimal;
mod biginteger;

pub(crate) use biginteger::{
    lazy_bigint_one, lazy_bigint_ten, lazy_bigint_two, lazy_bigint_zero,
};

use crate::vm::native::*;

/// wasm: materializer for the `RoundingMode` enum constants; the object is
/// opaque because every RoundingMode-taking native ignores the mode.
pub(crate) fn lazy_rounding_mode(vm: &mut Vm) -> JValue {
    alloc(vm, "Ljava/math/RoundingMode;", Native::Opaque).unwrap_or(JValue::Null)
}

/// All java.math native tables, grouped for `register`.
pub(crate) const MATH_TABLE: &[&[crate::vm::native::NativeEntry]] =
    &[biginteger::TABLE, bigdecimal::TABLE];
