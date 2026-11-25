//! kotlinx.coroutines host shims.

use crate::vm::native::*;

pub(crate) fn coroutine_scope_create(vm: &mut Vm, _args: &[JValue]) -> R {
    alloc(vm, "Lkotlinx/coroutines/CoroutineScope;", Native::Opaque)
}
pub(crate) fn coroutines_global_scope(vm: &mut Vm, _args: &[JValue]) -> R {
    alloc(vm, "Lkotlinx/coroutines/GlobalScope;", Native::Opaque)
}
pub(crate) fn coroutines_dispatchers_io(vm: &mut Vm, _args: &[JValue]) -> R {
    alloc(
        vm,
        "Lkotlinx/coroutines/CoroutineDispatcher;",
        Native::Opaque,
    )
}
pub(crate) fn coroutines_dispatchers_main(vm: &mut Vm, _args: &[JValue]) -> R {
    alloc(
        vm,
        "Lkotlinx/coroutines/MainCoroutineDispatcher;",
        Native::Opaque,
    )
}
pub(crate) fn coroutines_run_blocking(vm: &mut Vm, args: &[JValue]) -> R {
    inv_virt(
        vm,
        args[1],
        "invoke",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
        &[JValue::Null, JValue::Null],
    )
}
pub(crate) fn coroutines_with_timeout(vm: &mut Vm, args: &[JValue]) -> R {
    inv_virt(
        vm,
        args[1],
        "invoke",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
        &[JValue::Null, args[2]],
    )
}
pub(crate) fn completable_deferred_default(vm: &mut Vm, _args: &[JValue]) -> R {
    alloc(
        vm,
        "Lkotlinx/coroutines/CompletableDeferred;",
        Native::Deferred {
            value: JValue::Null,
            error: JValue::Null,
        },
    )
}

/// wasm: `CompletableDeferred(value)` overload (completed immediately).
pub(crate) fn completable_deferred_value(vm: &mut Vm, args: &[JValue]) -> R {
    alloc(
        vm,
        "Lkotlinx/coroutines/CompletableDeferred;",
        Native::Deferred {
            value: args[0],
            error: JValue::Null,
        },
    )
}
pub(crate) fn mutex_default(vm: &mut Vm, _args: &[JValue]) -> R {
    alloc(
        vm,
        "Lkotlinx/coroutines/sync/Mutex;",
        Native::Mutex { locked: false },
    )
}
pub(crate) fn mutex_lock(vm: &mut Vm, args: &[JValue]) -> R {
    let Some(Native::Mutex { locked }) = payload_mut(vm, args[0]) else {
        return Err(npe(vm));
    };
    *locked = true;
    Ok(JValue::Null)
}
pub(crate) fn mutex_try_lock(vm: &mut Vm, args: &[JValue]) -> R {
    let Some(Native::Mutex { locked }) = payload_mut(vm, args[0]) else {
        return Err(npe(vm));
    };
    if *locked {
        return Ok(JValue::Int(0));
    }
    *locked = true;
    Ok(JValue::Int(1))
}
pub(crate) fn mutex_unlock(vm: &mut Vm, args: &[JValue]) -> R {
    let Some(Native::Mutex { locked }) = payload_mut(vm, args[0]) else {
        return Err(npe(vm));
    };
    if !*locked {
        return Err(iae(vm, "Mutex is not locked"));
    }
    *locked = false;
    Ok(JValue::Null)
}
pub(crate) fn mutex_is_locked(vm: &mut Vm, args: &[JValue]) -> R {
    match payload(vm, args[0]) {
        Some(Native::Mutex { locked }) => Ok(JValue::Int(i32::from(*locked))),
        _ => Err(npe(vm)),
    }
}
// wasm: run one step of a PendingJob; returns Ok(true) if suspended again, Ok(false) if completed.
fn execute_pending_step(vm: &mut Vm, job: &mut crate::vm::PendingJob, allow_suspend: bool) -> Result<bool, crate::vm::error::JvmError> {
    let prev_running = vm.running_pending_job;
    let prev_suspend = vm.pending_suspend.take();
    vm.running_pending_job = allow_suspend;

    let res = match job.continuation {
        None => vm.invoke_virtual_args(
            job.block,
            "invoke",
            "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
            vec![job.scope, JValue::Null],
        ),
        Some(cont) => resume_continuation_chain(vm, cont),
    };

    let susp = vm.pending_suspend.take();
    vm.running_pending_job = prev_running;
    vm.pending_suspend = prev_suspend;

    match res {
        Ok(val) if allow_suspend && vm.is_coroutine_suspended(val) => {
            if let Some((next_cont, due_at_ms)) = susp {
                job.continuation = Some(next_cont);
                job.due_at_ms = due_at_ms;
                Ok(true)
            } else {
                Ok(false)
            }
        }
        Ok(_) => Ok(false),
        Err(e) => Err(e),
    }
}

fn resume_continuation_chain(
    vm: &mut Vm,
    start: JValue,
) -> Result<JValue, crate::vm::error::JvmError> {
    let mut cur = start;
    let mut param = lazy_unit_instance(vm);
    loop {
        let val = vm.invoke_virtual_args(
            cur,
            "invokeSuspend",
            "(Ljava/lang/Object;)Ljava/lang/Object;",
            vec![param],
        )?;
        if vm.is_coroutine_suspended(val) {
            return Ok(val);
        }
        let parent = match cur {
            JValue::Obj(id) => vm.continuation_completions.get(&id).copied(),
            _ => None,
        };
        match parent {
            Some(p) if !p.is_null_ref() => {
                cur = p;
                param = val;
            }
            _ => return Ok(val),
        }
    }
}

fn format_jvm_error(vm: &Vm, e: &crate::vm::error::JvmError) -> String {
    match e {
        crate::vm::error::JvmError::Uncaught(id) => {
            let class = vm
                .arena
                .objects
                .get(*id as usize)
                .map(|o| vm.class_desc_str(o.class))
                .unwrap_or_default();
            let msg = vm
                .payload_of(JValue::Obj(*id))
                .and_then(|p| match p {
                    Native::Throwable { message, .. } => message.clone(),
                    _ => None,
                })
                .unwrap_or_default();
            format!("uncaught {class}: {msg}")
        }
        other => other.to_string(),
    }
}

/// Runs currently-due pending detached coroutine jobs in this VM instance.
/// Returns `(ran, remaining, next_due_ms)`.
// wasm:
pub fn run_pending_jobs(vm: &mut Vm, max_jobs: Option<usize>) -> (usize, usize, Option<u64>) {
    let limit = max_jobs.unwrap_or(usize::MAX).max(1);
    let mut ran = 0usize;

    while ran < limit {
        let now_ms = Vm::monotonic_ms();
        let Some(pos) = vm.pending_jobs.iter().position(|j| j.due_at_ms <= now_ms) else {
            break;
        };
        let mut job = vm.pending_jobs.remove(pos);
        let job_id = job.job_obj;
        vm.job_states.insert(job_id, crate::vm::JobState::Running);
        ran += 1;

        match execute_pending_step(vm, &mut job, true) {
            Ok(true) => {
                // Suspended again via delay(); re-queue unless cancelled during step.
                if vm.job_states.get(&job_id) != Some(&crate::vm::JobState::Cancelled) {
                    vm.job_states.insert(job_id, crate::vm::JobState::Pending);
                    vm.pending_jobs.push(job);
                }
            }
            Ok(false) => {
                if vm.job_states.get(&job_id) != Some(&crate::vm::JobState::Cancelled) {
                    vm.job_states.insert(job_id, crate::vm::JobState::Completed);
                }
            }
            Err(e) => {
                let desc = format_jvm_error(vm, &e);
                log::warn!("dexvm pending job failed: {desc}");
                vm.job_states.insert(job_id, crate::vm::JobState::Completed);
            }
        }
    }

    let now_ms = Vm::monotonic_ms();
    let remaining = vm.pending_jobs.len();
    let next_due_ms = vm
        .pending_jobs
        .iter()
        .map(|j| j.due_at_ms.saturating_sub(now_ms))
        .min();
    (ran, remaining, next_due_ms)
}

pub(crate) fn coroutines_launch_default(vm: &mut Vm, args: &[JValue]) -> R {
    // wasm: structured concurrency scopes (`coroutineScope { launch {} }`,
    // `supervisorScope`, `withContext`) run inline; detached launches
    // (`GlobalScope.launch`, `CoroutineScope(...).launch`) are enqueued to
    // `vm.pending_jobs` and executed later via `runPending` (or inline on `join()`).
    let is_structured = match args.first() {
        Some(JValue::Obj(id)) => vm.structured_scopes.contains(id),
        _ => false,
    };
    let job = alloc(vm, "Lkotlinx/coroutines/Job;", Native::Opaque)?;
    let job_id = job.as_obj();
    if is_structured {
        vm.job_states.insert(job_id, crate::vm::JobState::Running);
        let _ = vm.invoke_virtual_args(
            args[3],
            "invoke",
            "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
            vec![args[0], JValue::Null],
        );
        vm.job_states.insert(job_id, crate::vm::JobState::Completed);
    } else {
        vm.job_states.insert(job_id, crate::vm::JobState::Pending);
        vm.pending_jobs.push(crate::vm::PendingJob {
            job_obj: job_id,
            scope: args[0],
            block: args[3],
            continuation: None,
            due_at_ms: 0,
        });
    }
    Ok(job)
}
/// wasm: `CoroutineStart` constants.
pub(crate) fn lazy_coroutine_start(vm: &mut Vm) -> JValue {
    alloc(vm, "Lkotlinx/coroutines/CoroutineStart;", Native::Opaque).unwrap_or(JValue::Null)
}

/// `delay(millis, continuation)` / `delay-VtjQ1oo(durationMs, continuation)`.
// wasm: inside `runPending`, suspend truly by returning COROUTINE_SUSPENDED and
// recording the continuation + due timestamp; elsewhere sleep via WASI poll_oneoff.
pub(crate) fn coroutines_delay(vm: &mut Vm, args: &[JValue]) -> R {
    let millis = long_of(vm, args[0]);
    if millis > 0 {
        if vm.running_pending_job && args.len() > 1 && !args[1].is_null_ref() {
            let due_at_ms = Vm::monotonic_ms().saturating_add(millis as u64);
            vm.pending_suspend = Some((args[1], due_at_ms));
            return Ok(vm.coroutine_suspended_token());
        }
        std::thread::sleep(std::time::Duration::from_millis(millis as u64));
    }
    Ok(lazy_unit_instance(vm))
}

pub(crate) fn job_is_active(vm: &mut Vm, args: &[JValue]) -> R {
    let active = match args.first() {
        Some(JValue::Obj(id)) => matches!(
            vm.job_states.get(id),
            Some(crate::vm::JobState::Pending | crate::vm::JobState::Running) | None
        ),
        _ => false,
    };
    Ok(JValue::Int(i32::from(active)))
}

pub(crate) fn job_is_completed(vm: &mut Vm, args: &[JValue]) -> R {
    let completed = match args.first() {
        Some(JValue::Obj(id)) => matches!(
            vm.job_states.get(id),
            Some(crate::vm::JobState::Completed | crate::vm::JobState::Cancelled)
        ),
        _ => false,
    };
    Ok(JValue::Int(i32::from(completed)))
}

pub(crate) fn job_is_cancelled(vm: &mut Vm, args: &[JValue]) -> R {
    let cancelled = match args.first() {
        Some(JValue::Obj(id)) => {
            matches!(vm.job_states.get(id), Some(crate::vm::JobState::Cancelled))
        }
        _ => false,
    };
    Ok(JValue::Int(i32::from(cancelled)))
}

pub(crate) fn job_join(vm: &mut Vm, args: &[JValue]) -> R {
    let Some(JValue::Obj(job_id)) = args.first().copied() else {
        return Ok(lazy_unit_instance(vm));
    };
    if let Some(pos) = vm.pending_jobs.iter().position(|j| j.job_obj == job_id) {
        let mut job = vm.pending_jobs.remove(pos);
        vm.job_states.insert(job_id, crate::vm::JobState::Running);
        if let Err(e) = execute_pending_step(vm, &mut job, false) {
            let desc = format_jvm_error(vm, &e);
            log::warn!("dexvm joined job failed: {desc}");
        }
        if vm.job_states.get(&job_id) != Some(&crate::vm::JobState::Cancelled) {
            vm.job_states.insert(job_id, crate::vm::JobState::Completed);
        }
    }
    Ok(lazy_unit_instance(vm))
}

pub(crate) fn coroutines_supervisor_job_default(vm: &mut Vm, _args: &[JValue]) -> R {
    alloc(vm, "Lkotlinx/coroutines/CompletableJob;", Native::Opaque)
}
pub(crate) fn coroutines_job_cancel_default(vm: &mut Vm, args: &[JValue]) -> R {
    if let Some(JValue::Obj(id)) = args.first().copied() {
        vm.job_states.insert(id, crate::vm::JobState::Cancelled);
        vm.pending_jobs.retain(|j| j.job_obj != id);
    }
    Ok(JValue::Null)
}
pub(crate) fn coroutines_is_active(_vm: &mut Vm, _args: &[JValue]) -> R {
    Ok(JValue::Int(1))
}
pub(crate) fn coroutines_get_immediate(_vm: &mut Vm, args: &[JValue]) -> R {
    Ok(args[0])
}
pub(crate) fn coroutines_supervisor_scope(vm: &mut Vm, args: &[JValue]) -> R {
    let scope = alloc(vm, "Lkotlinx/coroutines/CoroutineScope;", Native::Opaque)?;
    vm.structured_scopes.insert(scope.as_obj());
    inv_virt(
        vm,
        args[0],
        "invoke",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
        &[scope, args[1]],
    )
}
pub(crate) fn coroutines_scope(vm: &mut Vm, args: &[JValue]) -> R {
    let scope = alloc(vm, "Lkotlinx/coroutines/CoroutineScope;", Native::Opaque)?;
    vm.structured_scopes.insert(scope.as_obj());
    inv_virt(
        vm,
        args[0],
        "invoke",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
        &[scope, args[1]],
    )
}
pub(crate) fn coroutines_with_context(vm: &mut Vm, args: &[JValue]) -> R {
    let scope = alloc(vm, "Lkotlinx/coroutines/CoroutineScope;", Native::Opaque)?;
    vm.structured_scopes.insert(scope.as_obj());
    inv_virt(
        vm,
        args[1],
        "invoke",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
        &[scope, args[2]],
    )
}
pub(crate) fn coroutines_async_default(vm: &mut Vm, args: &[JValue]) -> R {
    // Run the body eagerly; a failure must surface here (like `await` would
    // rethrow), not turn into a null Deferred value.
    let value = inv_virt(
        vm,
        args[3],
        "invoke",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
        &[args[0], JValue::Null],
    )?;
    alloc(
        vm,
        "Lkotlinx/coroutines/Deferred;",
        Native::Deferred {
            value,
            error: JValue::Null,
        },
    )
}
pub(crate) fn deferred_await(vm: &mut Vm, args: &[JValue]) -> R {
    match payload(vm, args[0]) {
        Some(Native::Deferred { value, .. }) => Ok(*value),
        _ => Err(npe(vm)),
    }
}

/// wasm: `CompletableDeferred.complete(value)` / `completeExceptionally` —
/// the VM has no scheduler, so completion is just the stored value.
pub(crate) fn deferred_complete(vm: &mut Vm, args: &[JValue]) -> R {
    let value = args[1];
    let Some(Native::Deferred { value: slot, .. }) = payload_mut(vm, args[0]) else {
        return Err(npe(vm));
    };
    *slot = value;
    Ok(JValue::Int(1))
}

pub(crate) fn deferred_complete_exceptionally(vm: &mut Vm, args: &[JValue]) -> R {
    let error = args[1];
    let Some(Native::Deferred { error: slot, .. }) = payload_mut(vm, args[0]) else {
        return Err(npe(vm));
    };
    *slot = error;
    Ok(JValue::Int(1))
}

pub(crate) fn deferred_is_completed(_vm: &mut Vm, _args: &[JValue]) -> R {
    Ok(JValue::Int(1))
}
pub(crate) fn deferred_await_all(vm: &mut Vm, args: &[JValue]) -> R {
    let values = coll_elems(vm, args[0])?
        .into_iter()
        .map(|v| deferred_await(vm, &[v]))
        .collect::<Result<Vec<_>, _>>()?;
    list_alloc(vm, values)
}

pub(crate) const TABLE: &[NativeEntry] = &[
    ne!("Lkotlinx/coroutines/CoroutineScopeKt;", "CoroutineScope", "(Lkotlin/coroutines/CoroutineContext;)Lkotlinx/coroutines/CoroutineScope;", false, coroutine_scope_create),
    ne!("Lkotlinx/coroutines/GlobalScope;", "getInstance", "()Lkotlinx/coroutines/GlobalScope;", false, coroutines_global_scope),
    ne!("Lkotlinx/coroutines/Dispatchers;", "getIO", "()Lkotlinx/coroutines/CoroutineDispatcher;", false, coroutines_dispatchers_io),
    ne!("Lkotlinx/coroutines/Dispatchers;", "getMain", "()Lkotlinx/coroutines/MainCoroutineDispatcher;", false, coroutines_dispatchers_main),
    ne!("Lkotlinx/coroutines/BuildersKt;", "runBlockingK", "(Lkotlin/coroutines/CoroutineContext;Lkotlin/jvm/functions/Function2;)Ljava/lang/Object;", false, coroutines_run_blocking),
    ne!("Lkotlinx/coroutines/BuildersKt;", "runBlockingK$default", "(Lkotlin/coroutines/CoroutineContext;Lkotlin/jvm/functions/Function2;ILjava/lang/Object;)Ljava/lang/Object;", false, coroutines_run_blocking),
    ne!("Lkotlinx/coroutines/TimeoutKt;", "withTimeout-KLykuaI", "(JLkotlin/jvm/functions/Function2;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", false, coroutines_with_timeout),
    ne!("Lkotlinx/coroutines/CompletableDeferredKt;", "CompletableDeferred$default", "(Lkotlinx/coroutines/Job;ILjava/lang/Object;)Lkotlinx/coroutines/CompletableDeferred;", false, completable_deferred_default),
    ne!("Lkotlinx/coroutines/CompletableDeferredKt;", "CompletableDeferred", "(Ljava/lang/Object;)Lkotlinx/coroutines/CompletableDeferred;", false, completable_deferred_value),
    ne!("Lkotlinx/coroutines/BuildersKt;", "launch", "(Lkotlinx/coroutines/CoroutineScope;Lkotlin/coroutines/CoroutineContext;Lkotlinx/coroutines/CoroutineStart;Lkotlin/jvm/functions/Function2;)Lkotlinx/coroutines/Job;", false, coroutines_launch_default),
    ne!("Lkotlinx/coroutines/BuildersKt;", "launch$default", "(Lkotlinx/coroutines/CoroutineScope;Lkotlin/coroutines/CoroutineContext;Lkotlinx/coroutines/CoroutineStart;Lkotlin/jvm/functions/Function2;ILjava/lang/Object;)Lkotlinx/coroutines/Job;", false, coroutines_launch_default),
    ne!("Lkotlinx/coroutines/BuildersKt;", "async$default", "(Lkotlinx/coroutines/CoroutineScope;Lkotlin/coroutines/CoroutineContext;Lkotlinx/coroutines/CoroutineStart;Lkotlin/jvm/functions/Function2;ILjava/lang/Object;)Lkotlinx/coroutines/Deferred;", false, coroutines_async_default),
    ne!("Lkotlinx/coroutines/CoroutineScopeKt;", "coroutineScope", "(Lkotlin/jvm/functions/Function2;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", false, coroutines_scope),
    ne!("Lkotlinx/coroutines/BuildersKt;", "withContext", "(Lkotlin/coroutines/CoroutineContext;Lkotlin/jvm/functions/Function2;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", false, coroutines_with_context),
    ne!("Lkotlinx/coroutines/Deferred;", "await", "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", true, deferred_await),
    ne!("Lkotlinx/coroutines/CompletableDeferred;", "await", "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", true, deferred_await),
    ne!("Lkotlinx/coroutines/CompletableDeferred;", "complete", "(Ljava/lang/Object;)Z", true, deferred_complete),
    ne!("Lkotlinx/coroutines/CompletableDeferred;", "completeExceptionally", "(Ljava/lang/Throwable;)Z", true, deferred_complete_exceptionally),
    ne!("Lkotlinx/coroutines/CompletableDeferred;", "isCompleted", "()Z", true, deferred_is_completed),
    ne!("Lkotlinx/coroutines/AwaitKt;", "awaitAll", "(Ljava/util/Collection;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", false, deferred_await_all),
    ne!("Lkotlinx/coroutines/sync/MutexKt;", "Mutex$default", "(ZILjava/lang/Object;)Lkotlinx/coroutines/sync/Mutex;", false, mutex_default),
    ne!("Lkotlinx/coroutines/sync/Mutex;", "lock", "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", true, mutex_lock),
    // wasm: Kotlin Mutex.lock/tryLock/unlock take an optional `owner: Any?` parameter.
    ne!("Lkotlinx/coroutines/sync/Mutex;", "lock", "(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", true, mutex_lock),
    ne!("Lkotlinx/coroutines/sync/Mutex;", "tryLock", "()Z", true, mutex_try_lock),
    ne!("Lkotlinx/coroutines/sync/Mutex;", "tryLock", "(Ljava/lang/Object;)Z", true, mutex_try_lock),
    ne!("Lkotlinx/coroutines/sync/Mutex;", "unlock", "()V", true, mutex_unlock),
    ne!("Lkotlinx/coroutines/sync/Mutex;", "unlock", "(Ljava/lang/Object;)V", true, mutex_unlock),
    ne!("Lkotlinx/coroutines/sync/Mutex;", "isLocked", "()Z", true, mutex_is_locked),
    ne!("Lkotlinx/coroutines/SupervisorKt;", "SupervisorJob$default", "(Lkotlinx/coroutines/Job;ILjava/lang/Object;)Lkotlinx/coroutines/CompletableJob;", false, coroutines_supervisor_job_default),
    ne!("Lkotlinx/coroutines/SupervisorKt;", "supervisorScope", "(Lkotlin/jvm/functions/Function2;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", false, coroutines_supervisor_scope),
    ne!("Lkotlinx/coroutines/Job;", "cancel$default", "(Lkotlinx/coroutines/Job;Ljava/util/concurrent/CancellationException;ILjava/lang/Object;)V", false, coroutines_job_cancel_default),
    ne!("Lkotlinx/coroutines/Job;", "cancel", "()V", true, coroutines_job_cancel_default),
    ne!("Lkotlinx/coroutines/Job;", "cancel", "(Ljava/util/concurrent/CancellationException;)V", true, coroutines_job_cancel_default),
    ne!("Lkotlinx/coroutines/Job;", "isActive", "()Z", true, job_is_active),
    ne!("Lkotlinx/coroutines/Job;", "isCompleted", "()Z", true, job_is_completed),
    ne!("Lkotlinx/coroutines/Job;", "isCancelled", "()Z", true, job_is_cancelled),
    ne!("Lkotlinx/coroutines/Job;", "join", "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", true, job_join),
    ne!("Lkotlinx/coroutines/CompletableJob;", "cancel", "()V", true, coroutines_job_cancel_default),
    ne!("Lkotlinx/coroutines/CompletableJob;", "cancel", "(Ljava/util/concurrent/CancellationException;)V", true, coroutines_job_cancel_default),
    ne!("Lkotlinx/coroutines/CompletableJob;", "isActive", "()Z", true, job_is_active),
    ne!("Lkotlinx/coroutines/CompletableJob;", "isCompleted", "()Z", true, job_is_completed),
    ne!("Lkotlinx/coroutines/CompletableJob;", "isCancelled", "()Z", true, job_is_cancelled),
    ne!("Lkotlinx/coroutines/CompletableJob;", "join", "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", true, job_join),
    ne!("Lkotlinx/coroutines/CoroutineScopeKt;", "cancel$default", "(Lkotlinx/coroutines/CoroutineScope;Ljava/util/concurrent/CancellationException;ILjava/lang/Object;)V", false, coroutines_job_cancel_default),
    ne!("Lkotlinx/coroutines/CoroutineScopeKt;", "cancel$default", "(Lkotlinx/coroutines/CoroutineScope;Ljava/lang/Throwable;ILjava/lang/Object;)V", false, coroutines_job_cancel_default),
    ne!("Lkotlinx/coroutines/CoroutineScopeKt;", "isActive", "(Lkotlinx/coroutines/CoroutineScope;)Z", false, coroutines_is_active),
    ne!("Lkotlinx/coroutines/MainCoroutineDispatcher;", "getImmediate", "()Lkotlinx/coroutines/MainCoroutineDispatcher;", true, coroutines_get_immediate),
    ne!("Lkotlinx/coroutines/DelayKt;", "delay", "(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;", false, coroutines_delay),
    ne!("Lkotlinx/coroutines/DelayKt;", "delay-VtjQ1oo", "(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;", false, coroutines_delay),
];
