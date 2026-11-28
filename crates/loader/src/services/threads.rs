// SPDX-License-Identifier: GPL-3.0-or-later

//! Guest thread table and the thread services.
//!
//! A guest thread is a CPU context, a guarded stack and a TEB. It is not a host
//! thread: [`crate::scheduler`] runs one guest thread at a time on one host
//! thread. Without an attached scheduler `CreateThread` reports
//! `ERROR_NOT_SUPPORTED`, no thread object exists, and waits behave as they do
//! for a single thread.

use super::events::{INFINITE, SYNCHRONIZE, TICKS_PER_MILLI, Waitable};
use super::{
    CURRENT_THREAD, ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER,
    ERROR_NOACCESS, ERROR_NOT_ENOUGH_MEMORY, ERROR_NOT_SUPPORTED, GuestObject, KERNEL32, PAGE_SIZE,
    PROCESS_THREADS_V1, ServicesState, THREAD_QUERY_RIGHTS,
};
use crate::cpu::{CpuState, ExitReason, Register};
use crate::imports::{CallbackStart, CallbackStep, CallbackTask, ImportRegistry, ServiceStatus};
use crate::memory::{ALLOCATION_GRANULARITY, GuestMemory, MemoryError, MemoryPermissions};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

/// Most guest threads alive at once, the main thread included.
pub const MAX_THREADS: usize = 64;
/// Stack of a thread created with a zero size.
pub const DEFAULT_STACK: u64 = 256 * 1024;
const MAX_STACK: u64 = 8 * 1024 * 1024;
/// Highest suspend count (MAXIMUM_SUSPEND_COUNT).
const MAX_SUSPEND: u32 = 127;
/// GetExitCodeThread result while the thread runs.
const STILL_ACTIVE: u32 = 259;
pub(super) const CREATE_SUSPENDED: u32 = 4;
pub(super) const STACK_SIZE_PARAM_IS_A_RESERVATION: u32 = 0x0001_0000;
pub(super) const THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;
const THREAD_TERMINATE: u32 = 1;
const THREAD_SUSPEND_RESUME: u32 = 2;
/// Rights that exist only on worker thread objects.
pub(super) const WORKER_RIGHTS: u32 = THREAD_TERMINATE | THREAD_SUSPEND_RESUME;
const ERROR_SIGNAL_REFUSED: u32 = 156;
const THREAD_SET_INFORMATION: u32 = 0x20;
const THREAD_QUERY_INFORMATION: u32 = 0x40;
/// Size of GROUP_AFFINITY: a KAFFINITY mask, a WORD group, three reserved WORDs.
const GROUP_AFFINITY_SIZE: usize = 16;

/// Each thread slot holds a guard page, the stack, a guard page and the TEB.
const THREAD_AREA: u64 = 0x0000_0006_0000_0000;
const THREAD_STRIDE: u64 = 0x0100_0000;
const TEB_OFFSET: u64 = 0x00F0_0000;
const TEB_SIZE: u64 = 0x2000;
const TEB_STACK_BASE: u64 = 0x08;
const TEB_STACK_LIMIT: u64 = 0x10;
const TEB_SELF: u64 = 0x30;

/// Return address of a thread's start routine. It is on the reserved
/// sentinel page, so the import dispatcher stops there before any fetch: a
/// start routine's return is a host event, never a guest fault.
pub(crate) const THREAD_RETURN: u64 =
    crate::tls::TLS_CALLBACK_RETURN - crate::imports::IMPORT_TRAMPOLINE_STRIDE;
const _: () = assert!(THREAD_RETURN & !0xFFF == crate::imports::RETURN_SENTINEL_PAGE);

/// Tail-call the actual ExitThread service with the worker's original return
/// slot and home area. The worker can use FLS without importing ExitThread.
pub(crate) fn prepare_worker_exit(
    registry: Option<&ImportRegistry>,
    cpu: &mut CpuState,
    memory: &mut GuestMemory,
    code: u32,
) -> Result<(), ExitReason> {
    let (registry, index) = registry
        .and_then(|registry| {
            registry
                .service_index(KERNEL32, "ExitThread")
                .map(|index| (registry, index))
        })
        .ok_or(ExitReason::ServiceAbiViolation)?;
    let rsp = cpu
        .get(Register::Rsp)
        .checked_sub(8)
        .ok_or(ExitReason::MemoryFault(MemoryError::Overflow))?;
    memory
        .write_u64(rsp, THREAD_RETURN)
        .map_err(ExitReason::MemoryFault)?;
    cpu.set(Register::Rsp, rsp);
    cpu.set(Register::Rcx, u64::from(code));
    cpu.rip = registry.dynamic_trampolines().expose(index);
    Ok(())
}

/// How a service asked the scheduler to act after it completed.
const SWITCH_NONE: u8 = 0;
const SWITCH_SIGNAL: u8 = 1;
const SWITCH_YIELD: u8 = 2;

/// Shared between the services, the import dispatcher and the scheduler.
#[derive(Default)]
pub(crate) struct SchedulerHooks {
    attached: AtomicBool,
    switch: AtomicU8,
}

impl SchedulerHooks {
    pub(crate) fn is_attached(&self) -> bool {
        self.attached.load(Ordering::SeqCst)
    }

    /// An object other threads may wait for changed.
    pub(super) fn signal(&self) {
        if self.is_attached() {
            self.switch.fetch_max(SWITCH_SIGNAL, Ordering::SeqCst);
        }
    }

    fn yield_turn(&self) {
        self.switch.store(SWITCH_YIELD, Ordering::SeqCst);
    }

    /// Whether the dispatcher should stop the current thread after the call.
    pub(crate) fn switch_requested(&self) -> bool {
        self.switch.load(Ordering::SeqCst) != SWITCH_NONE
    }

    /// Take the request; true if the thread gives up its turn.
    pub(crate) fn take_switch(&self) -> bool {
        self.switch.swap(SWITCH_NONE, Ordering::SeqCst) == SWITCH_YIELD
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RunState {
    Ready,
    /// Waiting in a service; the sequence number orders waiters.
    Blocked(u64),
}

pub(crate) struct GuestThread {
    teb: u64,
    /// Taken by the scheduler while the thread runs.
    pub(crate) cpu: Option<CpuState>,
    pub(crate) run: RunState,
    pub(crate) suspend: u32,
    /// What is left of a turn the thread interrupted by signaling.
    pub(crate) credit: Option<usize>,
    object: Arc<Mutex<Waitable>>,
    slot: Option<u64>,
    allocations: Vec<u64>,
    /// Set by ExitThread and TerminateThread.
    pub(crate) exit: Option<u32>,
    fls_cleanup_started: bool,
}

struct FlsThreadExit {
    state: Arc<ServicesState>,
    id: u32,
    code: u32,
    callbacks: std::vec::IntoIter<(u64, u64)>,
}

impl CallbackTask for FlsThreadExit {
    fn resume(&mut self, _: u64, _: u64, _: &mut GuestMemory) -> Result<CallbackStep, ExitReason> {
        match self.callbacks.next() {
            Some((entry, value)) => Ok(CallbackStep::Call {
                entry,
                args: [value, 0, 0, 0],
            }),
            None => Err(self.state.finish_thread_exit(self.id, self.code)),
        }
    }
}

/// Objects a blocked thread waits for, captured when it first blocked.
pub(super) struct PendingWait {
    pub(super) objects: Vec<Arc<Mutex<Waitable>>>,
    pub(super) all: bool,
    pub(super) deadline: Option<u64>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SrwMode {
    Exclusive,
    Shared,
}

/// Lock a condition-variable sleep released and takes back.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SleepLock {
    Section(u64),
    Srw(u64, SrwMode),
}

/// How far a condition-variable sleep has come.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SleepPhase {
    Asleep,
    Woken,
    TimedOut,
}

/// Condition-variable sleep of a thread.
#[derive(Clone, Copy)]
pub(super) struct ConditionSleep {
    pub(super) variable: u64,
    pub(super) lock: SleepLock,
    pub(super) deadline: Option<u64>,
    pub(super) phase: SleepPhase,
    /// Place among the sleepers, and among the lock waiters once awake.
    pub(super) ticket: u64,
}

/// A same-process address wait. Once signaled, it stays ready until resumed.
#[derive(Clone, Copy)]
pub(super) struct AddressWait {
    pub(super) address: u64,
    pub(super) deadline: Option<u64>,
    pub(super) ticket: u64,
    pub(super) woken: bool,
}

/// What the call a thread is blocked in has to remember between retries.
pub(super) enum Pending {
    Objects(PendingWait),
    Srw {
        lock: u64,
        mode: SrwMode,
        ticket: u64,
    },
    Condition(ConditionSleep),
    Address(AddressWait),
    /// No deadline sleeps until the thread is terminated.
    Sleep(Option<u64>),
    /// A task-queue dispatch waits for work, queue termination or its timeout.
    TaskQueue {
        timeout_deadline: Option<u64>,
        deadline: Option<u64>,
    },
}

impl Pending {
    /// Time at which the thread runs again unless something else wakes it.
    fn deadline(&self) -> Option<u64> {
        match self {
            Self::Objects(wait) => wait.deadline,
            Self::Condition(sleep) if sleep.phase == SleepPhase::Asleep => sleep.deadline,
            Self::Address(wait) if !wait.woken => wait.deadline,
            Self::Sleep(deadline) => *deadline,
            Self::TaskQueue { deadline, .. } => *deadline,
            Self::Srw { .. } | Self::Condition(_) | Self::Address(_) => None,
        }
    }

    /// Slim lock this thread waits to own exclusively, and its place.
    fn exclusive_wait(&self) -> Option<(u64, u64)> {
        match *self {
            Self::Srw {
                lock,
                mode: SrwMode::Exclusive,
                ticket,
            } => Some((lock, ticket)),
            Self::Condition(ConditionSleep {
                lock: SleepLock::Srw(lock, SrwMode::Exclusive),
                phase: SleepPhase::Woken | SleepPhase::TimedOut,
                ticket,
                ..
            }) => Some((lock, ticket)),
            _ => None,
        }
    }
}

#[derive(Default)]
pub(crate) struct ThreadTable {
    pub(crate) threads: BTreeMap<u32, GuestThread>,
    /// Ready threads in the order they run.
    pub(crate) queue: VecDeque<u32>,
    pub(super) waits: BTreeMap<u64, Pending>,
    /// Main thread wait of a run that stopped on its budget, and the context
    /// that continues it.
    continued: Option<(CpuState, Pending)>,
    slots: BTreeSet<u64>,
    last_id: u32,
    sequence: u64,
}

impl ThreadTable {
    pub(crate) fn ticket(&mut self) -> u64 {
        self.sequence += 1;
        self.sequence
    }

    /// End a condition-variable sleep. The thread now queues for its lock, behind
    /// the threads already waiting for it.
    pub(super) fn end_sleep(&mut self, teb: u64, phase: SleepPhase) {
        let place = self.ticket();
        if let Some(Pending::Condition(sleep)) = self.waits.get_mut(&teb) {
            (sleep.phase, sleep.ticket) = (phase, place);
        }
        if let Some(thread) = self.threads.values_mut().find(|t| t.teb == teb)
            && thread.run != RunState::Ready
        {
            thread.run = RunState::Blocked(place);
        }
    }

    /// Whether another thread that can run waits, since before `ticket`, to own
    /// the slim lock exclusively.
    pub(super) fn writer_waits(&self, lock: u64, teb: u64, ticket: u64) -> bool {
        self.threads.values().any(|thread| {
            thread.teb != teb
                && thread.suspend == 0
                && self
                    .waits
                    .get(&thread.teb)
                    .and_then(Pending::exclusive_wait)
                    .is_some_and(|(wanted, place)| wanted == lock && place < ticket)
        })
    }

    pub(super) fn id_of(&self, teb: u64) -> Option<u32> {
        self.threads
            .iter()
            .find(|(_, thread)| thread.teb == teb)
            .map(|(&id, _)| id)
    }

    fn by_object(&mut self, object: &Arc<Mutex<Waitable>>) -> Option<&mut GuestThread> {
        self.threads
            .values_mut()
            .find(|thread| Arc::ptr_eq(&thread.object, object))
    }

    /// Earliest deadline of any wait that is not suspended away.
    pub(crate) fn next_deadline(&self) -> Option<u64> {
        self.threads
            .values()
            .filter(|thread| thread.suspend == 0 && thread.run != RunState::Ready)
            .filter_map(|thread| self.waits.get(&thread.teb)?.deadline())
            .min()
    }
}

/// Arguments of CreateThread, shared with the CRT `_beginthreadex` form.
pub(super) struct ThreadRequest {
    pub(super) stack: u64,
    pub(super) start: u64,
    pub(super) parameter: u64,
    pub(super) suspended: bool,
    /// `stack` is the reservation rather than the initial commitment.
    pub(super) reservation: bool,
    pub(super) id_output: u64,
}

fn map_thread(
    memory: &mut GuestMemory,
    base: u64,
    stack: u64,
    allocations: &mut Vec<u64>,
) -> Result<(), MemoryError> {
    let low = base + PAGE_SIZE;
    let top = low + stack;
    let teb = base + TEB_OFFSET;
    for (address, size, permissions) in [
        (base, PAGE_SIZE, MemoryPermissions::NO_ACCESS),
        (low, stack, MemoryPermissions::READ_WRITE),
        (top, PAGE_SIZE, MemoryPermissions::NO_ACCESS),
        (teb, TEB_SIZE, MemoryPermissions::READ_WRITE),
    ] {
        allocations.push(memory.map_thread_region(address, size as usize, permissions)?);
    }
    // A recycled TEB address must not inherit the previous thread's errno.
    let errno = memory.crt_errno_address(teb)?;
    memory.write_u32_bypass(errno, 0)?;
    memory.write_u64_bypass(teb + TEB_STACK_BASE, top)?;
    memory.write_u64_bypass(teb + TEB_STACK_LIMIT, low)?;
    memory.write_u64_bypass(teb + TEB_SELF, teb)
}

impl ServicesState {
    /// Adopt the calling context as the main guest thread.
    pub(crate) fn attach_scheduler(&self, main: &CpuState) -> Result<u32, ExitReason> {
        let mut table = self.threads.lock().expect("guest thread table");
        if self.hooks.attached.swap(true, Ordering::SeqCst) {
            return Err(ExitReason::ServiceAbiViolation);
        }
        // IDs are never reused, even by a later run.
        table.last_id = table.last_id.max(self.thread_id);
        table.threads.insert(
            self.thread_id,
            GuestThread {
                teb: main.gs_base,
                cpu: Some(main.clone()),
                run: RunState::Ready,
                suspend: 0,
                credit: None,
                object: Arc::new(Mutex::new(Waitable::Thread {
                    id: self.thread_id,
                    exit_code: None,
                })),
                slot: None,
                allocations: Vec::new(),
                exit: None,
                fls_cleanup_started: false,
            },
        );
        table.queue.push_back(self.thread_id);
        if let Some((context, wait)) = table.continued.take()
            && context == *main
        {
            table.waits.insert(main.gs_base, wait);
        }
        Ok(self.thread_id)
    }

    /// Reclaim every created thread. The main thread keeps its per-thread state.
    /// `continues` is its context if the run stopped on its budget; its pending
    /// wait is then kept for that context.
    pub(crate) fn detach_scheduler(&self, memory: &mut GuestMemory, continues: Option<&CpuState>) {
        let workers: Vec<u32> = {
            let table = self.threads.lock().expect("guest thread table");
            let worker = |(&id, thread): (&u32, &GuestThread)| thread.slot.map(|_| id);
            table.threads.iter().filter_map(worker).collect()
        };
        for id in workers {
            self.end_thread(id, 0, memory);
        }
        let mut table = self.threads.lock().expect("guest thread table");
        if let Some(context) = continues {
            let wait = table.waits.remove(&context.gs_base);
            table.continued = wait.map(|wait| (context.clone(), wait));
        }
        table.threads.clear();
        table.queue.clear();
        table.waits.clear();
        drop(table);
        self.hooks.switch.store(SWITCH_NONE, Ordering::SeqCst);
        self.hooks.attached.store(false, Ordering::SeqCst);
    }

    pub(crate) fn has_thread_fls_callbacks(&self, teb: u64) -> bool {
        self.synch
            .lock()
            .expect("guest synchronization state")
            .has_thread_fls_callbacks(teb)
    }

    fn start_thread_exit(
        self: &Arc<Self>,
        teb: u64,
        code: u32,
    ) -> Result<CallbackStart, ExitReason> {
        let id = {
            let mut table = self.threads.lock().expect("guest thread table");
            let id = table
                .id_of(teb)
                .ok_or(ExitReason::IllegalInstruction(0xFE))?;
            let thread = table.threads.get_mut(&id).expect("thread found above");
            // Cleanup belongs to workers and runs at most once per worker.
            if thread.slot.is_none() || thread.fls_cleanup_started {
                thread.exit = Some(code);
                return Err(ExitReason::GuestThreadExited);
            }
            thread.fls_cleanup_started = true;
            id
        };
        let mut callbacks = self
            .synch
            .lock()
            .expect("guest synchronization state")
            .take_thread_fls_callbacks(teb)
            .into_iter();
        let Some((entry, value)) = callbacks.next() else {
            return Err(self.finish_thread_exit(id, code));
        };
        Ok(CallbackStart::Call {
            task: Box::new(FlsThreadExit {
                state: Arc::clone(self),
                id,
                code,
                callbacks,
            }),
            entry,
            args: [value, 0, 0, 0],
        })
    }

    fn finish_thread_exit(&self, id: u32, code: u32) -> ExitReason {
        let mut table = self.threads.lock().expect("guest thread table");
        let Some(thread) = table.threads.get_mut(&id) else {
            return ExitReason::IllegalInstruction(0xFE);
        };
        thread.exit = Some(code);
        ExitReason::GuestThreadExited
    }

    /// Record a thread's exit code, signal its object and reclaim its state.
    pub(crate) fn end_thread(&self, id: u32, code: u32, memory: &mut GuestMemory) {
        let thread = {
            let mut table = self.threads.lock().expect("guest thread table");
            let Some(thread) = table.threads.remove(&id) else {
                return;
            };
            table.queue.retain(|&queued| queued != id);
            table.waits.remove(&thread.teb);
            if let Some(slot) = thread.slot {
                table.slots.remove(&slot);
            }
            thread
        };
        if let Waitable::Thread { exit_code, .. } =
            &mut *thread.object.lock().expect("guest waitable state")
        {
            *exit_code = Some(code);
        }
        self.abandon_mutexes(thread.teb);
        self.retire_thread_last_error(thread.teb);
        self.com().retire_thread(thread.teb);
        self.synch
            .lock()
            .expect("guest synchronization state")
            .retire_thread(thread.teb);
        memory
            .callback_frames
            .retain(|&(teb, _), _| teb != thread.teb);
        for base in thread.allocations {
            memory.release_thread_region(base);
        }
        self.hooks.signal();
    }

    /// A lock or one-time initialization other threads may wait for changed.
    pub(super) fn wake_blocked(&self) {
        let table = self.threads.lock().expect("guest thread table");
        if table.threads.values().any(|t| t.run != RunState::Ready) {
            self.hooks.signal();
        }
    }

    /// Clock value a timeout ends at, or `None` for an infinite one.
    pub(super) fn deadline(&self, milliseconds: u32) -> Option<u64> {
        (milliseconds != INFINITE).then(|| {
            self.clock
                .performance_count()
                .saturating_add(u64::from(milliseconds) * TICKS_PER_MILLI)
        })
    }

    /// Sleep only the calling guest thread. Zero gives up the rest of its turn.
    pub(super) fn sleep_thread(&self, teb: u64, milliseconds: u32) -> Result<u64, ExitReason> {
        let mut table = self.threads.lock().expect("guest thread table");
        if let Some(Pending::Sleep(deadline)) = table.waits.get(&teb) {
            if deadline.is_none_or(|deadline| self.clock.performance_count() < deadline) {
                return Err(ExitReason::GuestBlocked);
            }
            table.waits.remove(&teb);
            return Ok(0);
        }
        if milliseconds == 0 {
            self.hooks.yield_turn();
            return Ok(0);
        }
        table
            .waits
            .insert(teb, Pending::Sleep(self.deadline(milliseconds)));
        Err(ExitReason::GuestBlocked)
    }

    /// Wake the oldest thread asleep on a condition variable, or all of them. A
    /// sleep whose timeout has passed is over and takes no wake-up.
    pub(super) fn wake_condition(&self, variable: u64, all: bool) {
        let now = self.clock.performance_count();
        let mut table = self.threads.lock().expect("guest thread table");
        let mut asleep: Vec<(u64, u64)> = table
            .waits
            .iter()
            .filter_map(|(&teb, pending)| match pending {
                Pending::Condition(sleep)
                    if sleep.variable == variable
                        && sleep.phase == SleepPhase::Asleep
                        && sleep.deadline.is_none_or(|deadline| now < deadline) =>
                {
                    Some((sleep.ticket, teb))
                }
                _ => None,
            })
            .collect();
        asleep.sort_unstable();
        asleep.truncate(if all { asleep.len() } else { 1 });
        for (_, teb) in asleep {
            table.end_sleep(teb, SleepPhase::Woken);
            self.hooks.signal();
        }
    }

    /// Mark the oldest eligible address waiter, or all eligible waiters.
    /// An expired or suspended waiter does not consume a wake.
    pub(super) fn wake_address(&self, address: u64, all: bool) {
        let now = self.clock.performance_count();
        let mut table = self.threads.lock().expect("guest thread table");
        let table = &mut *table;
        let threads = &table.threads;
        let eligible = table.waits.iter_mut().filter_map(|(&teb, pending)| {
            let Pending::Address(wait) = pending else {
                return None;
            };
            (wait.address == address
                && !wait.woken
                && wait.deadline.is_none_or(|deadline| now < deadline)
                && threads
                    .values()
                    .any(|thread| thread.teb == teb && thread.suspend == 0))
            .then_some(wait)
        });
        if all {
            for wait in eligible {
                wait.woken = true;
                self.hooks.signal();
            }
        } else if let Some(wait) = eligible.min_by_key(|wait| wait.ticket) {
            wait.woken = true;
            self.hooks.signal();
        }
    }

    /// ID of the guest thread whose TEB is `teb`.
    pub(super) fn thread_id_of(&self, teb: u64) -> u32 {
        self.threads
            .lock()
            .expect("guest thread table")
            .id_of(teb)
            .unwrap_or(self.thread_id)
    }

    /// Whether the main thread can still be named by its ID.
    pub(super) fn main_thread_alive(&self) -> bool {
        let table = self.threads.lock().expect("guest thread table");
        !self.hooks.is_attached() || table.threads.contains_key(&self.thread_id)
    }

    /// Thread object for an ID, if that thread is alive and not the main thread.
    pub(super) fn worker_object(&self, id: u32) -> Option<Arc<Mutex<Waitable>>> {
        let table = self.threads.lock().expect("guest thread table");
        table
            .threads
            .get(&id)
            .filter(|thread| thread.slot.is_some())
            .map(|thread| Arc::clone(&thread.object))
    }

    /// Thread object of the calling worker, or `None` in the main thread.
    pub(super) fn current_worker(&self, teb: u64) -> Option<Arc<Mutex<Waitable>>> {
        let table = self.threads.lock().expect("guest thread table");
        let thread = table.threads.get(&table.id_of(teb)?)?;
        thread.slot.map(|_| Arc::clone(&thread.object))
    }

    pub(super) fn create_thread(
        &self,
        teb: u64,
        memory: &mut GuestMemory,
        request: &ThreadRequest,
    ) -> Result<u64, ExitReason> {
        if request.id_output != 0 && memory.check_write(request.id_output, 4).is_err() {
            return self.fail(teb, ERROR_NOACCESS, 0);
        }
        // Without the reservation flag the size is an initial commitment, and
        // the reservation is at least the default.
        let stack = if request.stack == 0 || !request.reservation {
            request.stack.max(DEFAULT_STACK)
        } else {
            request.stack
        };
        let Some(stack) = stack
            .checked_next_multiple_of(ALLOCATION_GRANULARITY)
            .filter(|&size| size <= MAX_STACK)
        else {
            return self.fail(teb, ERROR_NOT_ENOUGH_MEMORY, 0);
        };
        let mut objects = self.objects.lock().expect("guest object state");
        let mut table = self.threads.lock().expect("guest thread table");
        let handle = objects.next_handle();
        let id = table.last_id.checked_add(4);
        let (Some(handle), Some(id), true) = (handle, id, table.threads.len() < MAX_THREADS) else {
            return self.fail(teb, ERROR_NOT_ENOUGH_MEMORY, 0);
        };
        // A slot the guest has mapped something into is skipped.
        let mut prepared = None;
        for slot in (0..2 * MAX_THREADS as u64).filter(|slot| !table.slots.contains(slot)) {
            let base = THREAD_AREA + slot * THREAD_STRIDE;
            let mut allocations = Vec::new();
            // The start routine is entered as if called: RSP is 8 modulo 16,
            // and above it are the return address and a 32-byte home area.
            let rsp = base + PAGE_SIZE + stack - 40;
            let mapped = map_thread(memory, base, stack, &mut allocations)
                .and_then(|()| memory.write_u64(rsp, THREAD_RETURN));
            if mapped.is_ok() {
                prepared = Some((slot, base, rsp, allocations));
                break;
            }
            for base in allocations {
                memory.release_thread_region(base);
            }
            if !matches!(mapped, Err(MemoryError::OverlappingRegion { .. })) {
                break;
            }
        }
        let Some((slot, base, rsp, allocations)) = prepared else {
            return self.fail(teb, ERROR_NOT_ENOUGH_MEMORY, 0);
        };
        if request.id_output != 0 {
            memory
                .write_u32(request.id_output, id)
                .map_err(ExitReason::MemoryFault)?;
        }
        let mut cpu = CpuState::new(request.start, rsp);
        cpu.gs_base = base + TEB_OFFSET;
        cpu.set(Register::Rcx, request.parameter);
        let object = Arc::new(Mutex::new(Waitable::Thread {
            id,
            exit_code: None,
        }));
        objects.insert_handle(
            handle,
            GuestObject::Waitable {
                state: Arc::clone(&object),
                access: THREAD_ALL_ACCESS,
            },
        );
        table.slots.insert(slot);
        table.last_id = id;
        table.threads.insert(
            id,
            GuestThread {
                teb: base + TEB_OFFSET,
                cpu: Some(cpu),
                run: RunState::Ready,
                suspend: u32::from(request.suspended),
                credit: None,
                object,
                slot: Some(slot),
                allocations,
                exit: None,
                fls_cleanup_started: false,
            },
        );
        table.queue.push_back(id);
        Ok(handle)
    }

    /// Thread object and granted rights behind a handle.
    fn thread_handle(&self, teb: u64, handle: u64) -> Result<(Arc<Mutex<Waitable>>, u32), u32> {
        if handle == CURRENT_THREAD {
            let mut table = self.threads.lock().expect("guest thread table");
            let id = table.id_of(teb).ok_or(ERROR_INVALID_HANDLE)?;
            let thread = table.threads.get_mut(&id).ok_or(ERROR_INVALID_HANDLE)?;
            return Ok((Arc::clone(&thread.object), THREAD_ALL_ACCESS));
        }
        let objects = self.objects.lock().expect("guest object state");
        match objects.handles.get(&handle) {
            Some(GuestObject::Waitable { state, access })
                if matches!(
                    *state.lock().expect("guest waitable state"),
                    Waitable::Thread { .. }
                ) =>
            {
                Ok((Arc::clone(state), *access))
            }
            // Handles to the main thread from OpenThread name no object.
            Some(GuestObject::Thread(_)) => Err(ERROR_NOT_SUPPORTED),
            _ => Err(ERROR_INVALID_HANDLE),
        }
    }

    /// Rights granted by any handle that names a thread, the main thread too.
    fn thread_rights(&self, handle: u64) -> Result<u32, u32> {
        if handle == CURRENT_THREAD {
            return Ok(THREAD_ALL_ACCESS);
        }
        let objects = self.objects.lock().expect("guest object state");
        match objects.handles.get(&handle) {
            Some(GuestObject::Waitable { state, access })
                if matches!(
                    *state.lock().expect("guest waitable state"),
                    Waitable::Thread { .. }
                ) =>
            {
                Ok(*access)
            }
            Some(GuestObject::Thread(access)) => Ok(*access),
            _ => Err(ERROR_INVALID_HANDLE),
        }
    }

    /// Processors of group 0 the guest is shown. Every thread may run on all of
    /// them, and no other affinity is modelled.
    fn processor_mask(&self) -> u64 {
        let processors = self.guest_profile.processors.clamp(1, 64);
        u64::MAX >> (64 - processors)
    }

    fn group_affinity(&self) -> [u8; GROUP_AFFINITY_SIZE] {
        let mut affinity = [0; GROUP_AFFINITY_SIZE];
        affinity[..8].copy_from_slice(&self.processor_mask().to_le_bytes());
        affinity
    }

    fn get_group_affinity(
        &self,
        teb: u64,
        handle: u64,
        output: u64,
        memory: &mut GuestMemory,
    ) -> Result<u64, ExitReason> {
        let access = match self.thread_rights(handle) {
            Ok(access) => access,
            Err(error) => return self.fail(teb, error, 0),
        };
        if access & THREAD_QUERY_RIGHTS == 0 {
            return self.fail(teb, ERROR_ACCESS_DENIED, 0);
        }
        if memory.write_bytes(output, &self.group_affinity()).is_err() {
            return self.fail(teb, ERROR_NOACCESS, 0);
        }
        Ok(1)
    }

    fn set_group_affinity(
        &self,
        teb: u64,
        handle: u64,
        requested: u64,
        previous: u64,
        memory: &mut GuestMemory,
    ) -> Result<u64, ExitReason> {
        let access = match self.thread_rights(handle) {
            Ok(access) => access,
            Err(error) => return self.fail(teb, error, 0),
        };
        let needed = THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION;
        if access & needed != needed {
            return self.fail(teb, ERROR_ACCESS_DENIED, 0);
        }
        let mut affinity = [0; GROUP_AFFINITY_SIZE];
        if memory.read_bytes(requested, &mut affinity).is_err() {
            return self.fail(teb, ERROR_NOACCESS, 0);
        }
        let mask = u64::from_le_bytes(affinity[..8].try_into().expect("eight bytes"));
        // One group exists. The mask must name processors of it, and the
        // reserved words must be zero.
        let group_valid = affinity[8..].iter().all(|&byte| byte == 0);
        if !group_valid || mask == 0 || mask & !self.processor_mask() != 0 {
            return self.fail(teb, ERROR_INVALID_PARAMETER, 0);
        }
        // Restricting a thread to fewer processors has no meaning when guest
        // threads take turns on one host thread, so it is refused, not ignored.
        if mask != self.processor_mask() {
            return self.fail(teb, ERROR_NOT_SUPPORTED, 0);
        }
        if previous != 0
            && memory
                .write_bytes(previous, &self.group_affinity())
                .is_err()
        {
            return self.fail(teb, ERROR_NOACCESS, 0);
        }
        Ok(1)
    }

    /// Change another thread's suspend count and return the previous one.
    fn change_suspend(&self, teb: u64, handle: u64, resume: bool) -> Result<u64, ExitReason> {
        const FAILED: u64 = u32::MAX as u64;
        let (object, access) = match self.thread_handle(teb, handle) {
            Ok(found) => found,
            Err(error) => return self.fail(teb, error, FAILED),
        };
        if access & THREAD_SUSPEND_RESUME == 0 {
            return self.fail(teb, ERROR_ACCESS_DENIED, FAILED);
        }
        let mut table = self.threads.lock().expect("guest thread table");
        let Some(thread) = table.by_object(&object) else {
            return self.fail(teb, ERROR_ACCESS_DENIED, FAILED); // terminated
        };
        let previous = thread.suspend;
        if resume {
            thread.suspend = previous.saturating_sub(1);
        } else if previous >= MAX_SUSPEND {
            return self.fail(teb, ERROR_SIGNAL_REFUSED, FAILED);
        } else {
            thread.suspend = previous + 1;
        }
        drop(table);
        self.hooks.signal();
        Ok(u64::from(previous))
    }

    fn terminate(
        &self,
        teb: u64,
        handle: u64,
        code: u32,
        memory: &mut GuestMemory,
    ) -> Result<u64, ExitReason> {
        let (object, access) = match self.thread_handle(teb, handle) {
            Ok(found) => found,
            Err(error) => return self.fail(teb, error, 0),
        };
        if access & THREAD_TERMINATE == 0 {
            return self.fail(teb, ERROR_ACCESS_DENIED, 0);
        }
        let mut table = self.threads.lock().expect("guest thread table");
        let Some(id) = table
            .threads
            .iter()
            .find(|(_, thread)| Arc::ptr_eq(&thread.object, &object))
            .map(|(&id, _)| id)
        else {
            return self.fail(teb, ERROR_ACCESS_DENIED, 0); // already terminated
        };
        let thread = table.threads.get_mut(&id).expect("thread found above");
        if thread.teb == teb {
            thread.exit = Some(code);
            return Err(ExitReason::GuestThreadExited);
        }
        drop(table);
        self.end_thread(id, code, memory);
        Ok(1)
    }
}

pub(super) fn register(registry: &mut ImportRegistry, state: &Arc<ServicesState>) {
    let s = Arc::clone(state);
    registry.register(KERNEL32, "CreateThread", move |args, cpu, memory| {
        let arg = |index| args.get(index, memory).map_err(ExitReason::MemoryFault);
        let attributes = arg(0)?;
        let flags = arg(4)? as u32;
        let request = ThreadRequest {
            stack: arg(1)?,
            start: arg(2)?,
            parameter: arg(3)?,
            suspended: flags & CREATE_SUSPENDED != 0,
            reservation: flags & STACK_SIZE_PARAM_IS_A_RESERVATION != 0,
            id_output: arg(5)?,
        };
        if !s.hooks.is_attached() || attributes != 0 {
            return s.fail(cpu.gs_base, ERROR_NOT_SUPPORTED, 0);
        }
        if flags & !(CREATE_SUSPENDED | STACK_SIZE_PARAM_IS_A_RESERVATION) != 0 {
            return s.fail(cpu.gs_base, ERROR_INVALID_PARAMETER, 0);
        }
        s.create_thread(cpu.gs_base, memory, &request)
    });

    let s = Arc::clone(state);
    registry.register_callback_task(
        KERNEL32,
        "ExitThread",
        ServiceStatus::Partial,
        move |args, teb, _, _| s.start_thread_exit(teb, args.rcx as u32),
    );

    let s = Arc::clone(state);
    registry.register(KERNEL32, "TerminateThread", move |args, cpu, memory| {
        s.terminate(cpu.gs_base, args.rcx, args.rdx as u32, memory)
    });

    let s = Arc::clone(state);
    registry.register(KERNEL32, "GetExitCodeThread", move |args, cpu, memory| {
        let (object, access) = match s.thread_handle(cpu.gs_base, args.rcx) {
            Ok(found) => found,
            Err(error) => return s.fail(cpu.gs_base, error, 0),
        };
        if access & THREAD_QUERY_RIGHTS == 0 {
            return s.fail(cpu.gs_base, ERROR_ACCESS_DENIED, 0);
        }
        let code = match &*object.lock().expect("guest waitable state") {
            Waitable::Thread { exit_code, .. } => exit_code.unwrap_or(STILL_ACTIVE),
            _ => return s.fail(cpu.gs_base, ERROR_INVALID_HANDLE, 0),
        };
        if memory.write_u32(args.rdx, code).is_err() {
            return s.fail(cpu.gs_base, ERROR_NOACCESS, 0);
        }
        Ok(1)
    });

    let s = Arc::clone(state);
    registry.register_with_status(
        KERNEL32,
        "GetProcessIdOfThread",
        ServiceStatus::Partial,
        move |args, cpu, _| match s.thread_rights(args.rcx) {
            Ok(access) if access & THREAD_QUERY_RIGHTS != 0 => Ok(u64::from(s.process_id)),
            Ok(_) => s.fail(cpu.gs_base, ERROR_ACCESS_DENIED, 0),
            Err(error) => s.fail(cpu.gs_base, error, 0),
        },
    );

    // The bounds of the calling thread's stack, from its TEB: the high limit is
    // StackBase and the low limit is the bottom of the mapped stack, which is
    // also the reservation (stacks are committed whole). It returns nothing, so
    // an output the guest cannot write stops it with a memory fault.
    registry.register(
        KERNEL32,
        "GetCurrentThreadStackLimits",
        move |args, cpu, memory| {
            let high = memory
                .read_u64_bypass(cpu.gs_base + TEB_STACK_BASE)
                .map_err(ExitReason::MemoryFault)?;
            let low = memory
                .read_u64_bypass(cpu.gs_base + TEB_STACK_LIMIT)
                .map_err(ExitReason::MemoryFault)?;
            memory
                .write_u64(args.rcx, low)
                .and_then(|()| memory.write_u64(args.rdx, high))
                .map_err(ExitReason::MemoryFault)?;
            Ok(0)
        },
    );

    let s = Arc::clone(state);
    registry.register(
        KERNEL32,
        "GetThreadGroupAffinity",
        move |args, cpu, memory| s.get_group_affinity(cpu.gs_base, args.rcx, args.rdx, memory),
    );

    let s = Arc::clone(state);
    registry.register(
        KERNEL32,
        "SetThreadGroupAffinity",
        move |args, cpu, memory| {
            s.set_group_affinity(cpu.gs_base, args.rcx, args.rdx, args.r8, memory)
        },
    );

    for (symbol, resume) in [("SuspendThread", false), ("ResumeThread", true)] {
        let s = Arc::clone(state);
        registry.register(KERNEL32, symbol, move |args, cpu, _| {
            s.change_suspend(cpu.gs_base, args.rcx, resume)
        });
    }

    let s = Arc::clone(state);
    registry.register(KERNEL32, "SwitchToThread", move |_, cpu, _| {
        let table = s.threads.lock().expect("guest thread table");
        let current = table.id_of(cpu.gs_base);
        let other = table.threads.iter().any(|(&id, thread)| {
            Some(id) != current && thread.run == RunState::Ready && thread.suspend == 0
        });
        drop(table);
        if other {
            s.hooks.yield_turn();
        }
        Ok(u64::from(other))
    });

    for symbol in [
        "CreateThread",
        "ExitThread",
        "TerminateThread",
        "GetExitCodeThread",
        "SuspendThread",
        "ResumeThread",
        "SwitchToThread",
    ] {
        registry.alias(PROCESS_THREADS_V1, KERNEL32, symbol);
        registry.set_status(KERNEL32, symbol, ServiceStatus::Partial);
    }
    for symbol in [
        "GetCurrentThreadStackLimits",
        "GetThreadGroupAffinity",
        "SetThreadGroupAffinity",
    ] {
        registry.set_status(KERNEL32, symbol, ServiceStatus::Partial);
    }
    registry.alias(
        "api-ms-win-core-processthreads-l1-1-1.dll",
        KERNEL32,
        "GetCurrentThreadStackLimits",
    );
    const _: () = assert!(THREAD_ALL_ACCESS & SYNCHRONIZE != 0);
}
