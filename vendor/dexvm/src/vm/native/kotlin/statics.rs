//! Lazy materializers for Kotlin singleton and companion fields.
use super::support::opaque_inst;
use crate::vm::native::*;

pub(crate) fn duration_companion(vm: &mut Vm) -> JValue {
    opaque_inst(vm, "Lkotlin/time/Duration$Companion;")
}
// wasm: distinguish DurationUnit variants so toDuration(n, MILLISECONDS/MINUTES/HOURS/DAYS)
// produces accurate millisecond values (fixes RateLimitInterceptor sliding windows).
fn duration_unit_enum(vm: &mut Vm, name: &str, ordinal: i32) -> JValue {
    alloc(
        vm,
        "Lkotlin/time/DurationUnit;",
        Native::Enum {
            name: name.to_string(),
            ordinal,
        },
    )
    .unwrap_or(JValue::Null)
}

pub(crate) fn duration_unit_nanos(vm: &mut Vm) -> JValue {
    duration_unit_enum(vm, "NANOSECONDS", 0)
}
pub(crate) fn duration_unit_micros(vm: &mut Vm) -> JValue {
    duration_unit_enum(vm, "MICROSECONDS", 1)
}
pub(crate) fn duration_unit_millis(vm: &mut Vm) -> JValue {
    duration_unit_enum(vm, "MILLISECONDS", 2)
}
pub(crate) fn duration_unit_seconds(vm: &mut Vm) -> JValue {
    duration_unit_enum(vm, "SECONDS", 3)
}
pub(crate) fn duration_unit_minutes(vm: &mut Vm) -> JValue {
    duration_unit_enum(vm, "MINUTES", 4)
}
pub(crate) fn duration_unit_hours(vm: &mut Vm) -> JValue {
    duration_unit_enum(vm, "HOURS", 5)
}
pub(crate) fn duration_unit_days(vm: &mut Vm) -> JValue {
    duration_unit_enum(vm, "DAYS", 6)
}
pub(crate) fn clock_system_instance(vm: &mut Vm) -> JValue {
    opaque_inst(vm, "Lkotlin/time/Clock$System;")
}
pub(crate) fn unit_instance(vm: &mut Vm) -> JValue {
    opaque_inst(vm, "Lkotlin/Unit;")
}
pub(crate) fn global_scope(vm: &mut Vm) -> JValue {
    opaque_inst(vm, "Lkotlinx/coroutines/GlobalScope;")
}
pub(crate) fn result_companion(vm: &mut Vm) -> JValue {
    opaque_inst(vm, "Lkotlin/Result$Companion;")
}
