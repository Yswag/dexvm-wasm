//! java.util.ListIterator host shims.

use crate::vm::native::*;

/// wasm: `ListIterator.hasPrevious()` for the list-backed iterator.
pub(crate) fn iter_has_previous(vm: &mut Vm, args: &[JValue]) -> R {
    let Some(Native::Iter(k)) = payload(vm, args[0]) else {
        return Err(npe(vm));
    };
    let idx = match &k {
        IterKind::List { idx, .. } => *idx,
        _ => return Err(npe(vm)),
    };
    Ok(JValue::Int(i32::from(idx > 0)))
}

/// wasm: `ListIterator.previous()` — steps back and returns the element.
pub(crate) fn iter_previous(vm: &mut Vm, args: &[JValue]) -> R {
    let k = match payload(vm, args[0]) {
        Some(Native::Iter(k)) => k.clone(),
        _ => return Err(npe(vm)),
    };
    let IterKind::List { list, idx } = k else {
        return Err(npe(vm));
    };
    if idx == 0 {
        return Err(no_such_elem(vm));
    }
    let item = match payload(vm, JValue::Obj(list)) {
        Some(Native::List(items)) => items
            .get(idx - 1)
            .copied()
            .ok_or_else(|| no_such_elem(vm))?,
        _ => return Err(npe(vm)),
    };
    if let Some(Native::Iter(IterKind::List { idx: i, .. })) = payload_mut(vm, args[0]) {
        *i = idx - 1;
    }
    Ok(item)
}

// ListIterator shares the iter_* impls with Iterator (see iterator.rs).

/// Native methods for Ljava/util/ListIterator;
pub(crate) const TABLE: &[NativeEntry] = &[
    ne!(
        "Ljava/util/ListIterator;",
        "hasNext",
        "()Z",
        true,
        iter_has_next
    ),
    ne!(
        "Ljava/util/ListIterator;",
        "next",
        "()Ljava/lang/Object;",
        true,
        iter_next
    ),
    ne!(
        "Ljava/util/ListIterator;",
        "remove",
        "()V",
        true,
        iter_remove
    ),
    ne!(
        "Ljava/util/ListIterator;",
        "hasPrevious",
        "()Z",
        true,
        iter_has_previous
    ),
    ne!(
        "Ljava/util/ListIterator;",
        "previous",
        "()Ljava/lang/Object;",
        true,
        iter_previous
    ),
];
