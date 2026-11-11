//! `java.time.ZoneOffset` — only the `UTC` constant is surfaced. The fixed
//! offset time model in `java.time` ignores the zone object itself, so the
//! constant carries a plain "Z" tag.

use crate::vm::native::*;

pub(crate) fn utc(vm: &mut Vm) -> JValue {
    let Ok(class) = vm.ensure_class_by_desc("Ljava/time/ZoneOffset;") else {
        return JValue::Null;
    };
    JValue::Obj(vm.arena.alloc(class, Vec::new(), Some(Native::Str("Z".into()))))
}

pub(crate) const TABLE: &[NativeEntry] = &[];
