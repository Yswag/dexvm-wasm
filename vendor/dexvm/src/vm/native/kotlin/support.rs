//! Kotlin runtime support classes outside text/collections APIs.
pub(super) fn object_noop(_vm: &mut Vm, _args: &[JValue]) -> R {
    Ok(JValue::Null)
}
use crate::vm::native::*;

pub(super) fn enum_entries(vm: &mut Vm, args: &[JValue]) -> R {
    let entries = coll_elems(vm, args[0])?;
    list_alloc(vm, entries)
}
pub(super) fn boxing_box_boolean(vm: &mut Vm, args: &[JValue]) -> R {
    boxed(
        vm,
        "Ljava/lang/Boolean;",
        Native::BoolBox(int_of(vm, args[0]) != 0),
    )
}
pub(super) fn boxing_box_int(vm: &mut Vm, args: &[JValue]) -> R {
    boxed(
        vm,
        "Ljava/lang/Integer;",
        Native::IntBox(int_of(vm, args[0])),
    )
}
pub(super) fn boxing_box_long(vm: &mut Vm, args: &[JValue]) -> R {
    boxed(
        vm,
        "Ljava/lang/Long;",
        Native::LongBox(long_of(vm, args[0])),
    )
}
pub(super) fn boxing_identity(_vm: &mut Vm, args: &[JValue]) -> R {
    Ok(args[0])
}
pub(super) fn boxing_box_double(vm: &mut Vm, args: &[JValue]) -> R {
    boxed(
        vm,
        "Ljava/lang/Double;",
        Native::DoubleBox(double_of(vm, args[0])),
    )
}
pub(super) fn kotlin_random_default_next_int(vm: &mut Vm, args: &[JValue]) -> R {
    let first = if args.len() >= 2 && matches!(args[0], JValue::Obj(_)) {
        1
    } else {
        0
    };
    let (from, until) = if args.len() >= first + 2 {
        (args[first].as_int(), args[first + 1].as_int())
    } else if args.len() >= first + 1 {
        (0, args[first].as_int())
    } else {
        (0, 1)
    };
    if until <= from {
        return Err(NatErr::Throw(vm.throwable_of(
            "Ljava/lang/IllegalArgumentException;",
            "empty random range",
        )));
    }
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    Ok(JValue::Int(from + (seed % (until - from) as u32) as i32))
}
pub(super) fn kotlin_random_next_double(_vm: &mut Vm, _args: &[JValue]) -> R {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    Ok(JValue::Double(f64::from(seed % 1_000_000) / 1_000_000.0))
}

fn random_u64() -> u64 {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0x9E37_79B9_7F4A_7C15, |d| d.as_nanos() as u64);
    // xorshift64*: enough for chapter ids, nonces and shuffles.
    let mut x = seed | 1;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    x.wrapping_mul(0x2545_F491_4F6C_DD1D)
}

fn random_byte_arg(args: &[JValue]) -> i32 {
    args.iter()
        .skip(1)
        .find_map(|v| match v {
            JValue::Int(i) => Some(*i),
            _ => None,
        })
        .unwrap_or(0)
}

/// wasm: `Random.nextBytes(Int)` — fills a fresh `[B`.
pub(super) fn kotlin_random_next_bytes(vm: &mut Vm, args: &[JValue]) -> R {
    let n = random_byte_arg(args).max(0) as usize;
    let mut x = random_u64();
    let mut bytes = Vec::with_capacity(n);
    for _ in 0..n {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        bytes.push(x as u8 as i8);
    }
    alloc(vm, "[B", Native::Array(ArrayData::Byte(bytes)))
}

pub(super) fn kotlin_random_next_long(_vm: &mut Vm, _args: &[JValue]) -> R {
    Ok(JValue::Long(random_u64() as i64))
}

pub(super) fn kotlin_random_next_float(_vm: &mut Vm, _args: &[JValue]) -> R {
    let bits = (random_u64() >> 40) as u32;
    Ok(JValue::Float((bits as f32) / (1u32 << 24) as f32))
}

pub(super) fn kotlin_random_next_boolean(_vm: &mut Vm, _args: &[JValue]) -> R {
    Ok(JValue::Int(i32::from(random_u64() & 1 == 1)))
}

/// `Random.nextInt()` with no bounds.
pub(super) fn kotlin_random_next_int(_vm: &mut Vm, _args: &[JValue]) -> R {
    Ok(JValue::Int(random_u64() as i32))
}
pub(super) fn kotlin_random_kt_random(vm: &mut Vm, _args: &[JValue]) -> R {
    Ok(opaque_inst(vm, "Lkotlin/random/Random;"))
}
pub(super) fn kotlin_reflection_class(_vm: &mut Vm, args: &[JValue]) -> R {
    Ok(args[0])
}
pub(super) fn kotlin_type_projection_invariant(_vm: &mut Vm, args: &[JValue]) -> R {
    Ok(args[0])
}
pub(super) fn exceptions_stack_trace_to_string(vm: &mut Vm, args: &[JValue]) -> R {
    let s = to_string_of(vm, args[0])?;
    Ok(new_str(vm, &s))
}
pub(super) fn exceptions_add_suppressed(_vm: &mut Vm, _args: &[JValue]) -> R {
    Ok(JValue::Null)
}
/// `thread(start, isDaemon, contextClassLoader, name, priority, block)`:
/// this VM has no real concurrency, so a "started" thread just runs its
/// block synchronously (and any exception it throws is swallowed, matching
/// a real thread's uncaught-exception-terminates-just-that-thread behavior).
pub(super) fn threads_kt_thread_default(vm: &mut Vm, args: &[JValue]) -> R {
    let start = args.first().map(|v| v.as_int() != 0).unwrap_or(true);
    let block = args[5];
    if start && !block.is_null() {
        let _ = vm.invoke_virtual_args(block, "invoke", "()Ljava/lang/Object;", vec![]);
    }
    alloc(vm, "Ljava/lang/Thread;", Native::Opaque)
}
pub(super) fn mathkt_round_to_int_double(vm: &mut Vm, args: &[JValue]) -> R {
    Ok(JValue::Int(double_of(vm, args[0]).round() as i32))
}
pub(super) fn mathkt_round_to_int_float(vm: &mut Vm, args: &[JValue]) -> R {
    Ok(JValue::Int(float_of(vm, args[0]).round() as i32))
}
pub(super) fn mathkt_round_to_long_double(vm: &mut Vm, args: &[JValue]) -> R {
    Ok(JValue::Long(double_of(vm, args[0]).round() as i64))
}
pub(super) fn coroutines_suspended(vm: &mut Vm, _args: &[JValue]) -> R {
    Ok(opaque_inst(vm, "Ljava/lang/Object;"))
}

pub(super) fn comparisons_compare_values(vm: &mut Vm, args: &[JValue]) -> R {
    Ok(JValue::Int(java_cmp(vm, args[0], args[1])? as i32))
}

pub(super) fn comparisons_max_of(vm: &mut Vm, args: &[JValue]) -> R {
    let a = args[0];
    let b = args[1];
    match java_cmp(vm, a, b)? {
        Ordering::Less => Ok(b),
        _ => Ok(a),
    }
}

pub(super) fn comparisons_max_of3(vm: &mut Vm, args: &[JValue]) -> R {
    let mut best = args[0];
    for v in [args[1], args[2]] {
        if java_cmp(vm, v, best)? == Ordering::Greater {
            best = v;
        }
    }
    Ok(best)
}

pub(crate) fn opaque_inst(vm: &mut Vm, desc: &str) -> JValue {
    let Ok(class) = vm.ensure_class_by_desc(desc) else {
        return JValue::Null;
    };
    JValue::Obj(vm.arena.alloc(class, Vec::new(), Some(Native::Opaque)))
}

/// wasm: `kotlin.random.Random.Default` static field (1.6 sources read it
/// directly instead of calling `RandomKt.Random`).
pub(crate) fn lazy_random_default(vm: &mut Vm) -> JValue {
    opaque_inst(vm, "Lkotlin/random/Random$Default;")
}

pub(crate) const TABLE: &[NativeEntry] = &[
    ne!("Lkotlin/NoWhenBranchMatchedException;", "<init>", "()V", true, object_noop),
    ne!("Lkotlin/enums/EnumEntriesKt;", "enumEntries", "([Ljava/lang/Enum;)Lkotlin/enums/EnumEntries;", false, enum_entries),
    ne!("Lkotlin/coroutines/jvm/internal/Boxing;", "boxBoolean", "(Z)Ljava/lang/Boolean;", false, boxing_box_boolean),
    ne!("Lkotlin/coroutines/jvm/internal/Boxing;", "boxInt", "(I)Ljava/lang/Integer;", false, boxing_box_int),
    ne!("Lkotlin/coroutines/jvm/internal/Boxing;", "boxFloat", "(F)Ljava/lang/Float;", false, boxing_identity),
    ne!("Lkotlin/coroutines/jvm/internal/Boxing;", "boxLong", "(J)Ljava/lang/Long;", false, boxing_box_long),
    ne!("Lkotlin/coroutines/jvm/internal/Boxing;", "boxChar", "(C)Ljava/lang/Character;", false, boxing_identity),
    ne!("Lkotlin/coroutines/jvm/internal/Boxing;", "boxDouble", "(D)Ljava/lang/Double;", false, boxing_box_double),
    ne!("Lkotlin/random/Random$Default;", "nextDouble", "()D", true, kotlin_random_next_double),
    // wasm: rest of the Random surface used by 1.6 sources (nonces/ids).
    ne!("Lkotlin/random/Random$Default;", "nextBytes", "(I)[B", true, kotlin_random_next_bytes),
    ne!("Lkotlin/random/Random$Default;", "nextLong", "()J", true, kotlin_random_next_long),
    ne!("Lkotlin/random/Random$Default;", "nextFloat", "()F", true, kotlin_random_next_float),
    ne!("Lkotlin/random/Random$Default;", "nextBoolean", "()Z", true, kotlin_random_next_boolean),
    ne!("Lkotlin/random/Random$Default;", "nextInt", "()I", true, kotlin_random_next_int),
    ne!("Lkotlin/random/Random;", "nextBytes", "(I)[B", true, kotlin_random_next_bytes),
    ne!("Lkotlin/random/Random;", "nextLong", "()J", true, kotlin_random_next_long),
    ne!("Lkotlin/random/Random;", "nextFloat", "()F", true, kotlin_random_next_float),
    ne!("Lkotlin/random/Random;", "nextBoolean", "()Z", true, kotlin_random_next_boolean),
    ne!("Lkotlin/random/Random;", "nextInt", "()I", true, kotlin_random_next_int),
    ne!("Lkotlin/random/RandomKt;", "Random", "(J)Lkotlin/random/Random;", false, kotlin_random_kt_random),
    ne!("Lkotlin/jvm/internal/Reflection;", "getOrCreateKotlinClass", "(Ljava/lang/Class;)Lkotlin/reflect/KClass;", false, kotlin_reflection_class),
    ne!("Lkotlin/jvm/internal/Reflection;", "typeOf", "(Ljava/lang/Class;)Lkotlin/reflect/KType;", false, kotlin_reflection_class),
    ne!("Lkotlin/jvm/internal/Reflection;", "typeOf", "(Ljava/lang/Class;Lkotlin/reflect/KTypeProjection;)Lkotlin/reflect/KType;", false, kotlin_reflection_class),
    ne!("Lkotlin/jvm/internal/Reflection;", "nullableTypeOf", "(Ljava/lang/Class;)Lkotlin/reflect/KType;", false, kotlin_reflection_class),
    ne!("Lkotlin/reflect/KTypeProjection$Companion;", "invariant", "(Lkotlin/reflect/KType;)Lkotlin/reflect/KTypeProjection;", true, kotlin_type_projection_invariant),
    ne!("Lkotlin/ExceptionsKt;", "stackTraceToString", "(Ljava/lang/Throwable;)Ljava/lang/String;", false, exceptions_stack_trace_to_string),
    ne!("Lkotlin/ExceptionsKt;", "addSuppressed", "(Ljava/lang/Throwable;Ljava/lang/Throwable;)V", false, exceptions_add_suppressed),
    ne!("Lkotlin/concurrent/ThreadsKt;", "thread$default", "(ZZLjava/lang/ClassLoader;Ljava/lang/String;ILkotlin/jvm/functions/Function0;ILjava/lang/Object;)Ljava/lang/Thread;", false, threads_kt_thread_default),
    ne!("Lkotlin/math/MathKt;", "roundToInt", "(D)I", false, mathkt_round_to_int_double),
    ne!("Lkotlin/math/MathKt;", "roundToInt", "(F)I", false, mathkt_round_to_int_float),
    ne!("Lkotlin/math/MathKt;", "roundToLong", "(D)J", false, mathkt_round_to_long_double),
    ne!("Lkotlin/comparisons/ComparisonsKt;", "maxOf", "(Ljava/lang/Comparable;Ljava/lang/Comparable;)Ljava/lang/Comparable;", false, comparisons_max_of),
    ne!("Lkotlin/comparisons/ComparisonsKt;", "maxOf", "(Ljava/lang/Comparable;Ljava/lang/Comparable;Ljava/lang/Comparable;)Ljava/lang/Comparable;", false, comparisons_max_of3),
    ne!("Lkotlin/comparisons/ComparisonsKt;", "compareValues", "(Ljava/lang/Comparable;Ljava/lang/Comparable;)I", false, comparisons_compare_values),
    ne!("Lkotlin/random/Random;", "nextInt", "(I)I", true, kotlin_random_default_next_int),
    ne!("Lkotlin/random/Random;", "nextInt", "(II)I", true, kotlin_random_default_next_int),
    ne!("Lkotlin/random/Random$Default;", "nextInt", "(I)I", true, kotlin_random_default_next_int),
    ne!("Lkotlin/random/Random$Default;", "nextInt", "(II)I", true, kotlin_random_default_next_int),
    ne!("Lkotlin/jvm/internal/DefaultConstructorMarker;", "<init>", "()V", true, object_noop),
    ne!("Lkotlin/jvm/internal/Lambda;", "<init>", "(I)V", true, object_noop),
    ne!("Lkotlin/jvm/internal/FunctionReferenceImpl;", "<init>", "(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V", true, object_noop),
    ne!("Lkotlin/coroutines/intrinsics/IntrinsicsKt;", "getCOROUTINE_SUSPENDED", "()Ljava/lang/Object;", false, coroutines_suspended),
];
