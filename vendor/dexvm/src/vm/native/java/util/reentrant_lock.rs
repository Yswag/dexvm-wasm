//! java.util.concurrent.locks.ReentrantLock / Condition host shims.

use crate::vm::native::*;

pub(crate) fn reentrant_lock_init(vm: &mut Vm, args: &[JValue]) -> R {
    let Some(Native::ReentrantLock { locked }) = payload_mut(vm, args[0]) else {
        return Err(npe(vm));
    };
    // Fairness controls waiter ordering; it must not make a new lock held.
    // This VM executes synchronously, so both constructors start unlocked.
    *locked = false;
    Ok(JValue::Null)
}

pub(crate) fn reentrant_lock_lock(vm: &mut Vm, args: &[JValue]) -> R {
    let Some(Native::ReentrantLock { locked }) = payload_mut(vm, args[0]) else {
        return Err(npe(vm));
    };
    *locked = true;
    Ok(JValue::Null)
}

pub(crate) fn reentrant_lock_unlock(vm: &mut Vm, args: &[JValue]) -> R {
    let Some(Native::ReentrantLock { locked }) = payload_mut(vm, args[0]) else {
        return Err(npe(vm));
    };
    *locked = false;
    Ok(JValue::Null)
}

pub(crate) fn reentrant_lock_new_condition(vm: &mut Vm, _args: &[JValue]) -> R {
    alloc(vm, "Ljava/util/concurrent/locks/Condition;", Native::Opaque)
}

/// `ReentrantReadWriteLock`: the VM is single-threaded, so the read/write
/// halves are the same uncontended lock object.
pub(crate) fn rwlock_init(vm: &mut Vm, args: &[JValue]) -> R {
    let JValue::Obj(id) = args[0] else {
        return Err(npe(vm));
    };
    let Some(object) = vm.arena.objects.get_mut(id as usize) else {
        return Err(npe(vm));
    };
    object.native = Some(Native::ReentrantLock { locked: false });
    Ok(JValue::Null)
}

pub(crate) fn rwlock_read_lock(vm: &mut Vm, _args: &[JValue]) -> R {
    alloc(
        vm,
        "Ljava/util/concurrent/locks/ReentrantReadWriteLock$ReadLock;",
        Native::ReentrantLock { locked: false },
    )
}

pub(crate) fn rwlock_write_lock(vm: &mut Vm, _args: &[JValue]) -> R {
    alloc(
        vm,
        "Ljava/util/concurrent/locks/ReentrantReadWriteLock$WriteLock;",
        Native::ReentrantLock { locked: false },
    )
}

pub(crate) fn reentrant_lock_try_lock(_vm: &mut Vm, _args: &[JValue]) -> R {
    Ok(JValue::Int(1))
}

pub(crate) fn reentrant_lock_is_held(_vm: &mut Vm, _args: &[JValue]) -> R {
    Ok(JValue::Int(0))
}

// wasm: convert (timeout, TimeUnit) to Duration for Condition.await and CountDownLatch.await.
pub(crate) fn time_unit_duration(vm: &Vm, timeout: i64, unit: JValue) -> std::time::Duration {
    if timeout <= 0 {
        return std::time::Duration::ZERO;
    }
    let t = timeout as u64;
    let name = match payload(vm, unit) {
        Some(Native::Enum { name, .. }) => name.as_str(),
        _ => "MILLISECONDS",
    };
    match name {
        "NANOSECONDS" => std::time::Duration::from_nanos(t),
        "MICROSECONDS" => std::time::Duration::from_micros(t),
        "MILLISECONDS" => std::time::Duration::from_millis(t),
        "SECONDS" => std::time::Duration::from_secs(t),
        "MINUTES" => std::time::Duration::from_secs(t.saturating_mul(60)),
        "HOURS" => std::time::Duration::from_secs(t.saturating_mul(3600)),
        "DAYS" => std::time::Duration::from_secs(t.saturating_mul(86_400)),
        _ => std::time::Duration::from_millis(t),
    }
}

pub(crate) fn condition_await_nanos(vm: &mut Vm, args: &[JValue]) -> R {
    // wasm: sleep via std::thread::sleep (-> WASI poll_oneoff) instead of spinning.
    let nanos = long_of(vm, args[1]);
    if nanos <= 0 {
        return Ok(JValue::Long(nanos));
    }
    std::thread::sleep(std::time::Duration::from_nanos(nanos as u64));
    Ok(JValue::Long(0))
}

pub(crate) fn condition_await_timed(vm: &mut Vm, args: &[JValue]) -> R {
    // wasm: timed Condition.await(long, TimeUnit) -> WASI poll_oneoff.
    let timeout = long_of(vm, args[1]);
    let dur = time_unit_duration(vm, timeout, args[2]);
    if !dur.is_zero() {
        std::thread::sleep(dur);
    }
    Ok(JValue::Int(0))
}

pub(crate) fn condition_await(_vm: &mut Vm, _args: &[JValue]) -> R {
    Ok(JValue::Null)
}

pub(crate) fn condition_signal(_vm: &mut Vm, _args: &[JValue]) -> R {
    Ok(JValue::Null)
}

pub(crate) fn condition_signal_all(_vm: &mut Vm, _args: &[JValue]) -> R {
    Ok(JValue::Null)
}

/// Native methods for Ljava/util/concurrent/locks/ReentrantLock;
pub(crate) const TABLE: &[NativeEntry] = &[
    ne!(
        "Ljava/util/concurrent/locks/ReentrantLock;",
        "<init>",
        "()V",
        true,
        reentrant_lock_init
    ),
    ne!(
        "Ljava/util/concurrent/locks/ReentrantLock;",
        "<init>",
        "(Z)V",
        true,
        reentrant_lock_init
    ),
    ne!(
        "Ljava/util/concurrent/locks/ReentrantLock;",
        "lock",
        "()V",
        true,
        reentrant_lock_lock
    ),
    ne!(
        "Ljava/util/concurrent/locks/ReentrantLock;",
        "unlock",
        "()V",
        true,
        reentrant_lock_unlock
    ),
    ne!(
        "Ljava/util/concurrent/locks/ReentrantLock;",
        "newCondition",
        "()Ljava/util/concurrent/locks/Condition;",
        true,
        reentrant_lock_new_condition
    ),
    ne!(
        "Ljava/util/concurrent/locks/ReentrantLock;",
        "tryLock",
        "()Z",
        true,
        reentrant_lock_try_lock
    ),
    ne!(
        "Ljava/util/concurrent/locks/ReentrantReadWriteLock;",
        "<init>",
        "()V",
        true,
        rwlock_init
    ),
    ne!(
        "Ljava/util/concurrent/locks/ReentrantReadWriteLock;",
        "<init>",
        "(Z)V",
        true,
        rwlock_init
    ),
    ne!(
        "Ljava/util/concurrent/locks/ReentrantReadWriteLock;",
        "readLock",
        "()Ljava/util/concurrent/locks/ReentrantReadWriteLock$ReadLock;",
        true,
        rwlock_read_lock
    ),
    ne!(
        "Ljava/util/concurrent/locks/ReentrantReadWriteLock;",
        "writeLock",
        "()Ljava/util/concurrent/locks/ReentrantReadWriteLock$WriteLock;",
        true,
        rwlock_write_lock
    ),
    ne!(
        "Ljava/util/concurrent/locks/ReentrantReadWriteLock;",
        "isWriteLocked",
        "()Z",
        true,
        reentrant_lock_is_held
    ),
    ne!(
        "Ljava/util/concurrent/locks/ReentrantReadWriteLock;",
        "isWriteLockedByCurrentThread",
        "()Z",
        true,
        reentrant_lock_is_held
    ),
    ne!(
        "Ljava/util/concurrent/locks/ReentrantReadWriteLock;",
        "getReadHoldCount",
        "()I",
        true,
        reentrant_lock_is_held
    ),
    ne!(
        "Ljava/util/concurrent/locks/ReentrantReadWriteLock$ReadLock;",
        "lock",
        "()V",
        true,
        reentrant_lock_lock
    ),
    ne!(
        "Ljava/util/concurrent/locks/ReentrantReadWriteLock$ReadLock;",
        "unlock",
        "()V",
        true,
        reentrant_lock_unlock
    ),
    ne!(
        "Ljava/util/concurrent/locks/ReentrantReadWriteLock$ReadLock;",
        "tryLock",
        "()Z",
        true,
        reentrant_lock_try_lock
    ),
    ne!(
        "Ljava/util/concurrent/locks/ReentrantReadWriteLock$WriteLock;",
        "lock",
        "()V",
        true,
        reentrant_lock_lock
    ),
    ne!(
        "Ljava/util/concurrent/locks/ReentrantReadWriteLock$WriteLock;",
        "unlock",
        "()V",
        true,
        reentrant_lock_unlock
    ),
    ne!(
        "Ljava/util/concurrent/locks/ReentrantReadWriteLock$WriteLock;",
        "tryLock",
        "()Z",
        true,
        reentrant_lock_try_lock
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Context, SandboxOptions};

    #[test]
    fn both_constructors_start_unlocked() {
        let data = std::fs::read("fixtures/classes.dex").unwrap();
        let mut ctx = Context::new_with(&data, SandboxOptions::allow_all()).unwrap();
        let vm = ctx.vm();
        let lock = alloc(
            vm,
            "Ljava/util/concurrent/locks/ReentrantLock;",
            Native::ReentrantLock { locked: true },
        )
        .unwrap();
        reentrant_lock_init(vm, &[lock]).unwrap();
        assert!(matches!(
            payload(vm, lock),
            Some(Native::ReentrantLock { locked: false })
        ));
        reentrant_lock_init(vm, &[lock, JValue::Int(1)]).unwrap();
        assert!(matches!(
            payload(vm, lock),
            Some(Native::ReentrantLock { locked: false })
        ));
    }
}
