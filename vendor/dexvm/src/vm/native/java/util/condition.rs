//! java.util.concurrent.locks.Condition host shims.

use crate::vm::native::*;

/// Native methods for Ljava/util/concurrent/locks/Condition;
pub(crate) const TABLE: &[NativeEntry] = &[
    ne!(
        "Ljava/util/concurrent/locks/Condition;",
        "awaitNanos",
        "(J)J",
        true,
        condition_await_nanos
    ),
    ne!(
        "Ljava/util/concurrent/locks/Condition;",
        "await",
        "()V",
        true,
        condition_await
    ),
    // wasm: timed Condition.await(long, TimeUnit) -> WASI poll_oneoff.
    ne!(
        "Ljava/util/concurrent/locks/Condition;",
        "await",
        "(JLjava/util/concurrent/TimeUnit;)Z",
        true,
        condition_await_timed
    ),
    ne!(
        "Ljava/util/concurrent/locks/Condition;",
        "signal",
        "()V",
        true,
        condition_signal
    ),
    ne!(
        "Ljava/util/concurrent/locks/Condition;",
        "signalAll",
        "()V",
        true,
        condition_signal_all
    ),
];
