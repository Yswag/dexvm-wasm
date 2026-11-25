//! java.lang.Object host shims.

use crate::vm::native::*;

// java.lang.Object
// ---------------------------------------------------------------------------

pub(crate) fn object_init(_vm: &mut Vm, _args: &[JValue]) -> R {
    Ok(JValue::Null)
}

pub(crate) fn object_get_class(vm: &mut Vm, args: &[JValue]) -> R {
    let recv = args[0].as_obj();
    let class = obj_class(vm, recv);
    vm.class_obj(class).map_err(nat_fatal)
}

pub(crate) fn object_hash_code(_vm: &mut Vm, args: &[JValue]) -> R {
    Ok(JValue::Int(args[0].as_obj() as i32))
}

pub(crate) fn object_equals(_vm: &mut Vm, args: &[JValue]) -> R {
    let eq = match (args[0], args[1]) {
        (JValue::Obj(x), JValue::Obj(y)) => x == y,
        (JValue::Null, JValue::Null) => true,
        _ => false,
    };
    Ok(JValue::Int(i32::from(eq)))
}

pub(crate) fn object_to_string(vm: &mut Vm, args: &[JValue]) -> R {
    let recv = args[0].as_obj();
    let class = obj_class(vm, recv);
    let name = vm.class_desc_str(class);
    Ok(new_str(vm, &format!("{name}@{:x}", recv)))
}

pub(crate) fn thread_local_get(vm: &mut Vm, args: &[JValue]) -> R {
    match payload(vm, args[0]) {
        Some(Native::Lazy(v)) => Ok(*v),
        _ => Err(npe(vm)),
    }
}
pub(crate) fn thread_local_set(vm: &mut Vm, args: &[JValue]) -> R {
    let Some(Native::Lazy(dst)) = payload_mut(vm, args[0]) else {
        return Err(npe(vm));
    };
    *dst = args[1];
    Ok(JValue::Null)
}

pub(crate) fn object_clone(vm: &mut Vm, args: &[JValue]) -> R {
    let recv = args[0].as_obj();
    let class = obj_class(vm, recv);
    let Some(n) = payload(vm, args[0]) else {
        return Err(npe(vm));
    };
    match n {
        Native::Array(d) => Ok(JValue::Obj(vm.arena.alloc(
            class,
            Vec::new(),
            Some(Native::Array(d.clone())),
        ))),
        _ => Err(uoe(vm, "clone not supported")),
    }
}

// wasm: timed Object.wait delegates to std::thread::sleep (-> WASI poll_oneoff).
pub(crate) fn object_wait_timed(vm: &mut Vm, args: &[JValue]) -> R {
    let millis = match args.get(1) {
        Some(JValue::Long(v)) => *v,
        Some(JValue::Int(v)) => i64::from(*v),
        _ => return Err(iae(vm, "invalid wait timeout")),
    };
    let nanos = match args.get(2) {
        Some(JValue::Int(v)) => *v,
        Some(_) => return Err(iae(vm, "invalid nanosecond value")),
        None => 0,
    };
    if millis < 0 || !(0..=999_999).contains(&nanos) {
        return Err(iae(vm, "invalid wait timeout"));
    }
    if millis > 0 || nanos > 0 {
        std::thread::sleep(
            std::time::Duration::from_millis(millis as u64)
                + std::time::Duration::from_nanos(nanos as u64),
        );
    }
    Ok(JValue::Null)
}

pub(crate) fn object_wait_noop(_vm: &mut Vm, _args: &[JValue]) -> R {
    Ok(JValue::Null)
}

/// Native methods for Ljava/lang/Object;
pub(crate) const TABLE: &[NativeEntry] = &[
    ne!("Ljava/lang/Object;", "<init>", "()V", true, object_init),
    ne!(
        "Ljava/lang/Object;",
        "getClass",
        "()Ljava/lang/Class;",
        true,
        object_get_class
    ),
    ne!(
        "Ljava/lang/Object;",
        "hashCode",
        "()I",
        true,
        object_hash_code
    ),
    ne!(
        "Ljava/lang/Object;",
        "equals",
        "(Ljava/lang/Object;)Z",
        true,
        object_equals
    ),
    ne!(
        "Ljava/lang/Object;",
        "toString",
        "()Ljava/lang/String;",
        true,
        object_to_string
    ),
    ne!(
        "Ljava/lang/Object;",
        "clone",
        "()Ljava/lang/Object;",
        true,
        object_clone
    ),
    // wasm: Object.wait / notify shims (timed wait sleeps via WASI poll_oneoff).
    ne!("Ljava/lang/Object;", "wait", "()V", true, object_wait_noop),
    ne!("Ljava/lang/Object;", "wait", "(J)V", true, object_wait_timed),
    ne!("Ljava/lang/Object;", "wait", "(JI)V", true, object_wait_timed),
    ne!("Ljava/lang/Object;", "notify", "()V", true, object_wait_noop),
    ne!("Ljava/lang/Object;", "notifyAll", "()V", true, object_wait_noop),
    ne!(
        "Ljava/lang/ThreadLocal;",
        "get",
        "()Ljava/lang/Object;",
        true,
        thread_local_get
    ),
    ne!(
        "Ljava/lang/ThreadLocal;",
        "set",
        "(Ljava/lang/Object;)V",
        true,
        thread_local_set
    ),
];
