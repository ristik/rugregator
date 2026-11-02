//! Long-poll on inclusion-proof reads (`waitMs`), arch-long-poll revision 3 (single node, no
//! sharding, no HA) plus the architect's rugregator port findings.
//!
//! A request that carries `waitMs` reads once. If the read is *pending* (every non-included state
//! is known pending) it parks on a monotone publication generation and re-reads when a certified
//! commit, a terminal drop or an expiry bumps it, or when its absolute cutoff passes.
//!
//! * **Budget.** `Gate` is the global active HTTP/RPC budget C, `Pool` the same atomic counter for
//!   the batch and proof slots. A request holds one `ActiveHandle` while it is active; a parked or
//!   queued request holds none. The handle is reference counted and travels with the blocking
//!   worker, so the accounting is released when the worker really finished.
//! * **Atomic headroom.** `Pool::try_acquire(headroom)` is a compare-and-swap that only succeeds
//!   if `headroom` units stay free afterwards: fresh requests use 0, resumed reads 1. A tentative
//!   grant which fails in a later pool is rolled back with `Permit::rollback`, which does *not*
//!   signal "capacity freed", so contention cannot wake itself.
//! * **Admission.** A non-blocking global reservation (parked and resuming requests). A full or
//!   zero cap is never an error: the ordinary immediate read is served, with a zero echo.
//! * **Generation.** `tokio::sync::watch`: the receiver marks the generation it has seen before
//!   each read, so an event during the read makes `changed()` return at once (arm after re-read,
//!   nothing lost, many events coalesce into one re-read). Drain is a durable flag checked after
//!   subscribing and before every park.
//! * **Resume.** Re-reads queue FIFO for a bounded quota `max(1, C/4)`; batch reads are further
//!   limited to `min(B-1, S-1)`. The queue deadline is `min(entry + 2s, request deadline - 6s)`,
//!   never renewed; while waiting for capacity the request sleeps until a real release.
//! * **Parked state.** Before a request parks, the result of its last read (an encoded proof, a
//!   UC) is dropped: a parked request retains only its IDs and a timer.
//! * **Cancel.** Parking lives in the request future: dropping it (client EOF/RST) frees the
//!   reservation and queue entry at once. Work already handed to a worker keeps its accounting
//!   (the `holds`) until the worker acknowledges.

use std::any::Any;
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{watch, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

/// Reserve for resume admission (up to 2 s), the final read (5 s by default) and the response (1 s).
pub const RESUME_RESERVE: Duration = Duration::from_secs(2);
pub const FINAL_READ_RESERVE: Duration = Duration::from_secs(5);
pub const WRITE_RESERVE: Duration = Duration::from_secs(1);
/// Absolute application deadline of one JSON-RPC request, counted from admission. A wait never
/// extends it.
pub const METHOD_BUDGET: Duration = Duration::from_secs(30);

/// Default of `--long-poll-max-wait-ms` (aggregator-go's value).
pub const DEFAULT_MAX_WAIT_MS: u64 = 20_000;
/// Default of `--long-poll-max-waiters` (aggregator-go's value).
pub const DEFAULT_MAX_WAITERS: usize = 1024;
/// Default of `--concurrency-limit` (aggregator-go's `CONCURRENCY_LIMIT`).
pub const DEFAULT_CONCURRENCY: usize = 1000;

/// Default bound on reading one request body.
pub const DEFAULT_BODY_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest accepted `waitMs`: 2^53 - 1, the interoperable safe-integer range.
pub const MAX_WAIT_MS: u64 = 9_007_199_254_740_991;

fn total_reserve(final_read: Duration) -> Duration {
    RESUME_RESERVE + final_read + WRITE_RESERVE
}

/// Startup validation: the longest wait plus the reserve must fit the method budget.
pub fn validate_limits(
    max_wait_ms: u64,
    max_waiters: usize,
    batch_timeout: Duration,
) -> Result<(), String> {
    if max_wait_ms == 0 || max_waiters == 0 {
        return Ok(()); // long-poll admits nothing; every read is immediate
    }
    let final_read = FINAL_READ_RESERVE.max(batch_timeout);
    let reserve = total_reserve(final_read);
    if Duration::from_millis(max_wait_ms) + reserve >= METHOD_BUDGET {
        return Err(format!(
            "--long-poll-max-wait-ms ({max_wait_ms}) plus the {}s response reserve (resume 2s + final read {}s + write 1s) must stay below the {}s request budget",
            reserve.as_secs(),
            final_read.as_secs(),
            METHOD_BUDGET.as_secs()
        ));
    }
    Ok(())
}

// ─── Atomic capacity pools ───────────────────────────────────────────────────

/// "Capacity was really freed" announcements. A release only touches the `Notify` (a lock) when
/// someone is waiting for it, which is the exception: the common request path pays one atomic
/// load. A waiter counts itself in *before* it re-checks capacity, and a release counts down
/// *before* it looks for waiters (both `SeqCst`), so a release is never missed.
#[derive(Default)]
pub struct Freed {
    notify: Notify,
    waiters: AtomicUsize,
}

/// Registers a waiter for [`Freed`] announcements while alive.
pub struct Waiting<'a>(&'a Freed);

impl Freed {
    fn announce(&self) {
        if self.waiters.load(Ordering::SeqCst) > 0 {
            self.notify.notify_waiters();
        }
    }

    fn waiting(&self) -> Waiting<'_> {
        self.waiters.fetch_add(1, Ordering::SeqCst);
        Waiting(self)
    }
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.waiters.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A counted capacity pool (the global budget C, the batch slots, the proof slots).
pub struct Pool {
    limit: AtomicUsize,
    used: AtomicUsize,
    freed: Arc<Freed>,
    /// Successful and failed `try_acquire` calls which asked for headroom (resume admission).
    resume_attempts: AtomicU64,
}

/// The global active-work budget C.
pub type Gate = Pool;

/// One unit of a [`Pool`]; released (and capacity-freed signalled) on drop.
pub struct Permit {
    pool: Arc<Pool>,
    /// A rolled-back tentative grant: the unit goes back without a capacity-freed signal.
    silent: bool,
}

/// A request's unit of the global budget; shared so a worker can outlive the request.
pub type ActiveHandle = Arc<Permit>;

impl Drop for Permit {
    fn drop(&mut self) {
        self.pool.used.fetch_sub(1, Ordering::SeqCst);
        if !self.silent {
            self.pool.freed.announce();
        }
    }
}

impl Permit {
    /// Return a tentatively granted unit without announcing freed capacity: nobody else could
    /// have used it, and waking contenders for it would make them retry against nothing.
    pub fn rollback(mut self) {
        self.silent = true;
        // dropped here: the unit returns and the owning `Arc<Pool>` is released normally
    }
}

impl Pool {
    pub fn new(limit: usize, freed: Arc<Freed>) -> Arc<Self> {
        Arc::new(Self {
            limit: AtomicUsize::new(limit),
            used: AtomicUsize::new(0),
            freed,
            resume_attempts: AtomicU64::new(0),
        })
    }

    /// Take one unit if at least `1 + headroom` are free: a single compare-and-swap, so racing
    /// fresh and resumed requests can never both pass an observation and take the last units.
    pub fn try_acquire(self: &Arc<Self>, headroom: usize) -> Option<Permit> {
        if headroom > 0 {
            self.resume_attempts.fetch_add(1, Ordering::Relaxed);
        }
        let limit = self.limit.load(Ordering::Acquire);
        let mut cur = self.used.load(Ordering::SeqCst);
        loop {
            if cur + 1 + headroom > limit {
                return None;
            }
            match self
                .used
                .compare_exchange_weak(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => {
                    return Some(Permit {
                        pool: Arc::clone(self),
                        silent: false,
                    })
                }
                Err(seen) => cur = seen,
            }
        }
    }

    /// A fresh request's handle, shared by `Arc`.
    pub fn acquire_handle(self: &Arc<Self>) -> Option<ActiveHandle> {
        self.try_acquire(0).map(Arc::new)
    }

    pub fn set_limit(&self, limit: usize) {
        self.limit.store(limit, Ordering::Release);
    }

    pub fn in_use(&self) -> usize {
        self.used.load(Ordering::SeqCst)
    }

    pub fn limit(&self) -> usize {
        self.limit.load(Ordering::Acquire)
    }

    pub fn available(&self) -> usize {
        self.limit().saturating_sub(self.in_use())
    }

    /// Admission attempts which asked for headroom (resumed reads).
    pub fn resume_attempts(&self) -> u64 {
        self.resume_attempts.load(Ordering::Relaxed)
    }

    /// Wait until nothing is held (shutdown join) or the deadline passes.
    pub async fn wait_idle(&self, until: Instant) -> bool {
        loop {
            let _waiting = self.freed.waiting();
            let notified = self.freed.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.in_use() == 0 {
                return true;
            }
            if tokio::time::timeout_at(until, notified).await.is_err() {
                return self.in_use() == 0;
            }
        }
    }
}

/// The active-work handle of one request. The coordinator releases it while the request parks
/// and takes a fresh one for each re-read; the HTTP layer keeps the last one until the response
/// has been written to the transport.
#[derive(Clone, Default)]
pub struct ActiveSlot(Arc<Mutex<Option<ActiveHandle>>>);

impl ActiveSlot {
    pub fn new(handle: Option<ActiveHandle>) -> Self {
        Self(Arc::new(Mutex::new(handle)))
    }
    pub fn get(&self) -> Option<ActiveHandle> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
    pub fn set(&self, handle: Option<ActiveHandle>) {
        *self.0.lock().unwrap_or_else(|p| p.into_inner()) = handle;
    }
    pub fn take(&self) -> Option<ActiveHandle> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).take()
    }
}

// ─── Reads ───────────────────────────────────────────────────────────────────

/// Which kind of resumed read a request is, for the resume quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// `get_inclusion_proof.v2`.
    V2,
    /// `get_inclusion_proofs.v1`.
    Batch,
}

/// One read attempt of a long-pollable method.
pub struct Read<T> {
    /// Waiting may help: every non-included state is known pending.
    pub pending: bool,
    pub value: T,
}

/// Capacity a read was granted; the read consumes it instead of acquiring again and hands it to
/// the blocking worker, which releases it when it has really stopped.
#[derive(Default)]
pub struct ReadPermits {
    pub batch: Option<Permit>,
    pub proof: Option<Permit>,
    /// The request's HTTP budget unit.
    pub keepalive: Option<ActiveHandle>,
    /// Further accounting which must outlive the request future while work runs (the waiter
    /// reservation, the resume quota).
    pub holds: Vec<Box<dyn Any + Send>>,
}

impl ReadPermits {
    /// Give back a tentative grant without a capacity-freed signal.
    pub fn rollback(self) {
        if let Some(p) = self.batch {
            p.rollback();
        }
        if let Some(p) = self.proof {
            p.rollback();
        }
    }
}

/// Non-blocking acquisition of a method's capacity, leaving one unit free in every pool. It must
/// roll back what it took when it fails (without signalling).
pub type TryPools<'a> = &'a (dyn Fn() -> Option<ReadPermits> + Send + Sync);

#[derive(Default)]
struct Counters {
    requests: Mutex<BTreeMap<(&'static str, &'static str), u64>>,
    wakes: Mutex<BTreeMap<&'static str, u64>>,
    rechecks: Mutex<BTreeMap<&'static str, u64>>,
    notifies: AtomicU64,
    wait_ms_sum: AtomicU64,
    wait_count: AtomicU64,
}

/// The waiter registry: reservation cap, publication generation, resume quota, metrics.
pub struct Registry {
    max_wait_ms: AtomicU64,
    capacity: AtomicUsize,
    final_read_ms: AtomicU64,
    budget_ms: AtomicU64,
    body_timeout_ms: AtomicU64,
    reserved: AtomicUsize,
    queued: AtomicUsize,
    running: AtomicUsize,
    draining: AtomicBool,
    generation: watch::Sender<u64>,
    gate: Arc<Gate>,
    /// Signalled whenever a unit of the budget, a batch slot or a proof slot is really released.
    freed: Arc<Freed>,
    /// Serializes the multi-pool resume admission decision, so no resumer ever observes another's
    /// tentative occupancy (a tentative unit would hide capacity from a contender which then
    /// sleeps with nothing left to wake it).
    admit_lock: Mutex<()>,
    quota: Arc<Semaphore>,
    quota_cap: AtomicUsize,
    batch_class: Arc<Semaphore>,
    batch_cap: AtomicUsize,
    counters: Counters,
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    pub fn new() -> Self {
        let freed = Arc::new(Freed::default());
        let r = Self {
            max_wait_ms: AtomicU64::new(DEFAULT_MAX_WAIT_MS),
            capacity: AtomicUsize::new(DEFAULT_MAX_WAITERS),
            final_read_ms: AtomicU64::new(FINAL_READ_RESERVE.as_millis() as u64),
            budget_ms: AtomicU64::new(METHOD_BUDGET.as_millis() as u64),
            body_timeout_ms: AtomicU64::new(DEFAULT_BODY_TIMEOUT.as_millis() as u64),
            reserved: AtomicUsize::new(0),
            queued: AtomicUsize::new(0),
            running: AtomicUsize::new(0),
            draining: AtomicBool::new(false),
            generation: watch::channel(0).0,
            gate: Pool::new(DEFAULT_CONCURRENCY, Arc::clone(&freed)),
            freed,
            admit_lock: Mutex::new(()),
            quota: Arc::new(Semaphore::new(0)),
            quota_cap: AtomicUsize::new(0),
            batch_class: Arc::new(Semaphore::new(0)),
            batch_cap: AtomicUsize::new(0),
            counters: Counters::default(),
        };
        r.set_concurrency(DEFAULT_CONCURRENCY);
        r.set_batch_resume_cap(7);
        r
    }

    /// A pool whose releases wake queued resumptions (the batch and proof slots).
    pub fn new_pool(&self, limit: usize) -> Arc<Pool> {
        Pool::new(limit, Arc::clone(&self.freed))
    }

    /// Startup configuration: `--long-poll-max-wait-ms`, `--long-poll-max-waiters` and the
    /// final-read reserve (the batch execution budget, at least 5 s).
    pub fn configure(&self, max_wait_ms: u64, max_waiters: usize, batch_timeout: Duration) {
        self.max_wait_ms.store(max_wait_ms, Ordering::Release);
        self.capacity.store(max_waiters, Ordering::Release);
        self.final_read_ms.store(
            FINAL_READ_RESERVE.max(batch_timeout).as_millis() as u64,
            Ordering::Release,
        );
    }

    /// The global active-work budget C (`--concurrency-limit`). Startup only.
    pub fn set_concurrency(&self, c: usize) {
        self.gate.set_limit(c);
        // Resumed reads run at most max(1, C/4) at a time.
        let cap = (c / 4).max(1);
        let current = self.quota_cap.swap(cap, Ordering::AcqRel);
        if cap > current {
            self.quota.add_permits(cap - current);
        } else if cap < current {
            let _ = self.quota.forget_permits(current - cap);
        }
    }

    /// Running cap of resumed batch reads: `min(B-1, S-1)` for B batch slots and S shared proof
    /// slots. Zero (fewer than two of either) disables batch parking. Startup only.
    pub fn set_batch_resume_cap(&self, cap: usize) {
        let current = self.batch_cap.swap(cap, Ordering::AcqRel);
        if cap > current {
            self.batch_class.add_permits(cap - current);
        } else if cap < current {
            let _ = self.batch_class.forget_permits(current - cap);
        }
    }

    /// The lock under which every tentative multi-pool transaction (a resumer's HTTP + method
    /// grant, a fresh batch's batch + proof grant) is made, so a silent rollback is never visible
    /// to a competing waiter. Hold it only across synchronous attempts.
    pub fn admission_lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.admit_lock.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn gate(&self) -> &Arc<Gate> {
        &self.gate
    }

    pub fn max_wait(&self) -> Duration {
        Duration::from_millis(self.max_wait_ms.load(Ordering::Acquire))
    }

    pub fn capacity(&self) -> usize {
        self.capacity.load(Ordering::Acquire)
    }

    /// The absolute lifetime of one request (30 s; tests shorten it).
    pub fn budget(&self) -> Duration {
        Duration::from_millis(self.budget_ms.load(Ordering::Acquire))
    }

    pub fn set_budget(&self, d: Duration) {
        self.budget_ms
            .store(d.as_millis() as u64, Ordering::Release);
    }

    /// Bound on reading one request body (a slow body is cut here).
    pub fn body_timeout(&self) -> Duration {
        Duration::from_millis(self.body_timeout_ms.load(Ordering::Acquire))
    }

    pub fn set_body_timeout(&self, d: Duration) {
        self.body_timeout_ms
            .store(d.as_millis() as u64, Ordering::Release);
    }

    fn final_read(&self) -> Duration {
        Duration::from_millis(self.final_read_ms.load(Ordering::Acquire))
    }

    /// Record that something a waiter may care about changed (a certified commit, an expiry, a
    /// terminal drop). Never blocks, runs no proof work; callers hold no lock.
    pub fn notify(&self) {
        self.counters.notifies.fetch_add(1, Ordering::Relaxed);
        self.generation.send_modify(|g| *g += 1);
    }

    pub fn generation(&self) -> u64 {
        *self.generation.borrow()
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.generation.subscribe()
    }

    /// Wake every wait to a final ordinary read and refuse new ones (shutdown).
    pub fn drain(&self) {
        self.draining.store(true, Ordering::Release);
        self.generation.send_modify(|g| *g += 1);
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    /// Admitted waits right now (parked, queued for resumption or resuming).
    pub fn reserved(&self) -> usize {
        self.reserved.load(Ordering::Acquire)
    }

    pub fn resume_queued(&self) -> usize {
        self.queued.load(Ordering::Acquire)
    }

    pub fn resume_running(&self) -> usize {
        self.running.load(Ordering::Acquire)
    }

    fn admit(self: &Arc<Self>) -> Result<Arc<Reservation>, Shed> {
        if self.is_draining() {
            return Err(Shed::Draining);
        }
        let cap = self.capacity();
        let mut cur = self.reserved.load(Ordering::Acquire);
        loop {
            if cur >= cap {
                return Err(Shed::Capacity);
            }
            match self.reserved.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(Arc::new(Reservation(Arc::clone(self)))),
                Err(seen) => cur = seen,
            }
        }
    }

    fn bump<K: Ord>(map: &Mutex<BTreeMap<K, u64>>, key: K) {
        *map.lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(key)
            .or_insert(0) += 1;
    }

    fn outcome(&self, method: &'static str, outcome: &'static str) {
        Self::bump(&self.counters.requests, (method, outcome));
    }

    fn wake(&self, cause: &'static str) {
        Self::bump(&self.counters.wakes, cause);
    }

    /// Prometheus text exposition (bounded labels only; no state-ID, endpoint or client labels).
    pub fn render_metrics(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let gauge = |out: &mut String, name: &str, help: &str, v: usize| {
            let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {v}");
        };
        gauge(
            &mut out,
            "aggregator_longpoll_reservations",
            "Admitted long-poll waits (parked, queued for resumption or resuming) against --long-poll-max-waiters.",
            self.reserved(),
        );
        gauge(
            &mut out,
            "aggregator_longpoll_resume_queued",
            "Long-poll waits queued for resume capacity to re-read.",
            self.resume_queued(),
        );
        gauge(
            &mut out,
            "aggregator_longpoll_resume_running",
            "Resumed long-poll reads currently running (bounded by max(1, C/4)).",
            self.resume_running(),
        );
        gauge(
            &mut out,
            "aggregator_http_active_requests",
            "Requests holding a unit of the global active-work budget (--concurrency-limit).",
            self.gate.in_use(),
        );
        let _ = writeln!(
            out,
            "# HELP aggregator_longpoll_requests_total Requests carrying waitMs by outcome.\n\
             # TYPE aggregator_longpoll_requests_total counter"
        );
        for ((method, outcome), n) in self
            .counters
            .requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
        {
            let _ = writeln!(
                out,
                "aggregator_longpoll_requests_total{{method=\"{method}\",outcome=\"{outcome}\"}} {n}"
            );
        }
        let _ = writeln!(
            out,
            "# HELP aggregator_longpoll_wakes_total Wake causes of parked long-poll waits.\n\
             # TYPE aggregator_longpoll_wakes_total counter"
        );
        for (cause, n) in self
            .counters
            .wakes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
        {
            let _ = writeln!(
                out,
                "aggregator_longpoll_wakes_total{{cause=\"{cause}\"}} {n}"
            );
        }
        let _ = writeln!(
            out,
            "# HELP aggregator_longpoll_rechecks_total Re-reads performed by long-poll waits after a wake.\n\
             # TYPE aggregator_longpoll_rechecks_total counter"
        );
        for (method, n) in self
            .counters
            .rechecks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
        {
            let _ = writeln!(
                out,
                "aggregator_longpoll_rechecks_total{{method=\"{method}\"}} {n}"
            );
        }
        let _ = writeln!(
            out,
            "# HELP aggregator_longpoll_notifies_total Wake-up events raised by commits, expiries and terminal drops.\n\
             # TYPE aggregator_longpoll_notifies_total counter\n\
             aggregator_longpoll_notifies_total {}",
            self.counters.notifies.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "# HELP aggregator_longpoll_wait_seconds Cumulative time requests spent waiting (the waitedMs echo).\n\
             # TYPE aggregator_longpoll_wait_seconds summary\n\
             aggregator_longpoll_wait_seconds_sum {}\n\
             aggregator_longpoll_wait_seconds_count {}",
            self.counters.wait_ms_sum.load(Ordering::Relaxed) as f64 / 1000.0,
            self.counters.wait_count.load(Ordering::Relaxed)
        );
        out
    }

    /// Per-outcome request counts, for tests and the PR's hardware-independent counts.
    pub fn request_count(&self, method: &str, outcome: &str) -> u64 {
        self.counters
            .requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|((m, o), _)| *m == method && *o == outcome)
            .map(|(_, n)| *n)
            .sum()
    }

    /// Re-reads performed after a wake.
    pub fn recheck_count(&self, method: &str) -> u64 {
        self.counters
            .rechecks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(method)
            .copied()
            .unwrap_or(0)
    }

    pub fn wake_count(&self, cause: &str) -> u64 {
        self.counters
            .wakes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(cause)
            .copied()
            .unwrap_or(0)
    }

    pub fn notify_count(&self) -> u64 {
        self.counters.notifies.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shed {
    Capacity,
    Draining,
}

/// One admitted wait; released when the last holder (the request future or a worker which still
/// runs its read) lets go.
pub struct Reservation(Arc<Registry>);

impl Drop for Reservation {
    fn drop(&mut self) {
        self.0.reserved.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Counts the request as cancelled if its future is dropped before it finished.
struct CancelGuard {
    reg: Arc<Registry>,
    method: &'static str,
    done: bool,
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        if !self.done {
            self.reg.wake("cancel");
            self.reg.outcome(self.method, "cancelled");
        }
    }
}

struct Gauge<'a>(&'a AtomicUsize);

impl<'a> Gauge<'a> {
    fn up(counter: &'a AtomicUsize) -> Self {
        counter.fetch_add(1, Ordering::AcqRel);
        Self(counter)
    }
}

impl Drop for Gauge<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn ceil_ms(d: Duration) -> u64 {
    (d.as_nanos().div_ceil(1_000_000)).min(u64::MAX as u128) as u64
}

/// The effective wait: `min(requested, configured max, time left in the request budget - reserve)`.
/// The conversion happens after clamping, so a huge `waitMs` never overflows a `Duration`.
pub fn effective_wait(
    requested: u64,
    max_wait: Duration,
    reserve: Duration,
    budget: Duration,
    started: Instant,
    now: Instant,
) -> Duration {
    if requested == 0 || max_wait.is_zero() {
        return Duration::ZERO;
    }
    let mut wait = max_wait;
    let max_ms = u64::try_from(max_wait.as_millis()).unwrap_or(u64::MAX);
    if requested < max_ms {
        wait = Duration::from_millis(requested);
    }
    let left = (started + budget).saturating_duration_since(now);
    wait.min(left.saturating_sub(reserve))
}

/// Serve a request which carried a valid `waitMs = requested`.
///
/// `eval` is one complete, normal read: it receives the capacity granted to it and must hand it
/// to whatever work it starts. A pending result parks the request (after its value has been
/// dropped); the final result and the cumulative wait in milliseconds (the `waitedMs` echo, the
/// ceiling of the condition-wait time, excluding reads and resume queueing) are returned.
/// A zero wait, no remaining budget, zero/full capacity, `C < 2` or a drain return the ordinary
/// immediate read with a zero echo; a timeout is a final ordinary read. If a resumed read cannot
/// get capacity before its deadline, `busy` supplies the retryable busy/deadline answer.
#[allow(clippy::too_many_arguments)]
pub async fn run<T, F, Fut>(
    reg: &Arc<Registry>,
    method: &'static str,
    class: Class,
    started: Instant,
    requested: u64,
    slot: &ActiveSlot,
    try_pools: TryPools<'_>,
    busy: impl FnOnce() -> T,
    mut eval: F,
) -> (T, u64)
where
    F: FnMut(ReadPermits) -> Fut,
    Fut: Future<Output = Read<T>>,
{
    let begin = Instant::now();
    let reserve = total_reserve(reg.final_read());
    let wait = effective_wait(
        requested,
        reg.max_wait(),
        reserve,
        reg.budget(),
        started,
        begin,
    );
    let first = |res: Option<&Arc<Reservation>>| ReadPermits {
        keepalive: slot.get(),
        holds: res
            .map(|r| vec![Box::new(Arc::clone(r)) as Box<dyn Any + Send>])
            .unwrap_or_default(),
        ..Default::default()
    };

    let c_ok =
        reg.gate.limit() >= 2 && (class == Class::V2 || reg.batch_cap.load(Ordering::Acquire) > 0);
    if requested == 0 {
        reg.outcome(method, "immediate_zero");
        return (eval(first(None)).await.value, 0);
    }
    if wait.is_zero() || !c_ok {
        reg.outcome(
            method,
            if c_ok {
                "immediate_no_budget"
            } else {
                "shed_capacity"
            },
        );
        return (eval(first(None)).await.value, 0);
    }
    let reservation = match reg.admit() {
        Ok(r) => r,
        Err(shed) => {
            reg.outcome(
                method,
                match shed {
                    Shed::Capacity => "shed_capacity",
                    Shed::Draining => "shed_draining",
                },
            );
            return (eval(first(None)).await.value, 0);
        }
    };
    let mut guard = CancelGuard {
        reg: Arc::clone(reg),
        method,
        done: false,
    };

    let cutoff = begin + wait;
    let hard = started + reg.budget();
    let post_resume = reserve - RESUME_RESERVE; // final read + response write after the resume
    let mut rx = reg.subscribe();
    let mut waited = Duration::ZERO;
    let mut parked = false;
    let mut resumed = false;
    let mut final_read = false;
    let mut outcome = "completed";
    let mut grant: Option<(ReadPermits, Arc<Vec<OwnedSemaphorePermit>>)> = None;

    let (value, outcome) = loop {
        // Mark the generation this read starts from: an event during the read makes `changed()`
        // return at once, so the wake-up cannot be lost.
        rx.borrow_and_update();
        let read = match grant.take() {
            None => eval(first(Some(&reservation))).await,
            Some((permits, _quota)) => {
                // The quota is also kept here, so it covers the whole read even if the read
                // does not hand its permits on; a worker which outlives us keeps its own clone.
                let _running = Gauge::up(&reg.running);
                eval(permits).await
            }
        };
        if resumed {
            Registry::bump(&reg.counters.rechecks, method);
        }
        let Read { pending, value } = read;
        if !pending || final_read {
            if !pending && !parked {
                outcome = "immediate_final";
            }
            break (value, outcome);
        }
        if Instant::now() >= cutoff {
            break (value, "timeout");
        }
        // A parked request retains only its IDs and a timer: the encoded proof, the UC and
        // every other part of this read are released before it suspends.
        drop(value);

        // Drain is a durable flag, checked after subscribing and before every park, so a drain
        // which raced admission or the evaluation cannot be missed.
        let draining = reg.is_draining();
        // Park: the request holds no HTTP, batch or proof capacity.
        slot.set(None);
        parked = true;
        let cause = if draining {
            "drain"
        } else {
            let t0 = Instant::now();
            let cause = if rx.has_changed().unwrap_or(false) {
                "changed"
            } else {
                tokio::select! {
                    r = rx.changed() => if r.is_ok() { "signal" } else { "drain" },
                    _ = tokio::time::sleep_until(cutoff) => "timeout",
                }
            };
            waited += t0.elapsed();
            cause
        };
        reg.wake(cause);
        if cause == "timeout" {
            final_read = true;
            outcome = "timeout";
        } else if cause == "drain" || reg.is_draining() {
            final_read = true;
            outcome = "drained";
        }

        // Resume: one shared deadline, never renewed: min(entry + 2s, request deadline - 6s).
        let entry = Instant::now();
        let until = (entry + RESUME_RESERVE).min(hard.checked_sub(post_resume).unwrap_or(hard));
        let queued = Gauge::up(&reg.queued);
        let granted = resume_grant(reg, class, slot, try_pools, until).await;
        drop(queued);
        match granted {
            Some((mut permits, quota)) => {
                permits.holds.push(Box::new(Arc::clone(&reservation)));
                grant = Some((permits, quota));
            }
            None => break (busy(), "busy_admission_deadline"),
        }
        resumed = true;
    };

    drop(reservation);
    guard.done = true;
    let ms = ceil_ms(waited);
    reg.outcome(method, outcome);
    if outcome != "immediate_final" {
        reg.counters.wait_ms_sum.fetch_add(ms, Ordering::Relaxed);
        reg.counters.wait_count.fetch_add(1, Ordering::Relaxed);
    }
    (value, ms)
}

/// FIFO resume admission: the running quota (and the batch class cap), then HTTP + method
/// capacity together without blocking, with the headroom kept atomic in every pool and the
/// tentative grant rolled back (silently) when a later pool refuses. After a refusal the request
/// sleeps until a unit is really released or the deadline passes: there is no polling tick, so
/// contention cannot spin. On success the HTTP unit is in `slot`, the quota permits ride along in
/// `holds`.
async fn resume_grant(
    reg: &Arc<Registry>,
    class: Class,
    slot: &ActiveSlot,
    try_pools: TryPools<'_>,
    until: Instant,
) -> Option<(ReadPermits, Arc<Vec<OwnedSemaphorePermit>>)> {
    let mut held: Vec<OwnedSemaphorePermit> = Vec::new();
    if class == Class::Batch {
        held.push(
            tokio::time::timeout_at(until, Arc::clone(&reg.batch_class).acquire_owned())
                .await
                .ok()?
                .ok()?,
        );
    }
    held.push(
        tokio::time::timeout_at(until, Arc::clone(&reg.quota).acquire_owned())
            .await
            .ok()?
            .ok()?,
    );
    loop {
        // Counted in before the capacity is re-checked: a release after the check announces.
        let _waiting = reg.freed.waiting();
        let notified = reg.freed.notify.notified();
        tokio::pin!(notified);
        {
            // The whole decision is made under one lock: HTTP unit, then the method pools, with a
            // silent rollback on refusal. Registered for the wake-up before the attempt (still
            // under the lock), so a real release between the attempt and the sleep is not lost.
            let _decision = reg.admission_lock();
            notified.as_mut().enable();
            if let Some(active) = reg.gate.try_acquire(1) {
                if let Some(mut permits) = try_pools() {
                    let active = Arc::new(active);
                    permits.keepalive = Some(Arc::clone(&active));
                    let quota = Arc::new(held);
                    permits.holds.push(Box::new(Arc::clone(&quota)));
                    slot.set(Some(active));
                    return Some((permits, quota));
                }
                active.rollback();
            }
        }
        if tokio::time::timeout_at(until, notified).await.is_err() {
            return None;
        }
    }
}

// ─── Request parameter scan ──────────────────────────────────────────────────

/// The result of scanning a params object for a top-level `waitMs` member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitScan {
    /// No `waitMs` member (or params that are not an object): legacy behaviour, legacy bytes.
    Absent,
    /// A valid wait. Zero is valid and distinct from absence.
    Valid(u64),
    /// Present but not a plain integer token in `[0, 2^53-1]`, or duplicated: not a wait.
    Invalid,
}

/// `waitMs` is a bare JSON integer token: ASCII digits only, so null, booleans, strings,
/// containers, signs (`-0` included), fractions and exponents are all rejected, as is anything
/// above [`MAX_WAIT_MS`] (including overflow).
pub fn parse_wait_ms(token: &str) -> Option<u64> {
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    token.parse::<u64>().ok().filter(|v| *v <= MAX_WAIT_MS)
}

/// Find and validate `waitMs` among the top-level members of raw params text, independently of
/// member order and of any other member. Keys are matched after JSON unescaping, duplicates (also
/// via an escaped spelling) are invalid. Text that is not an object has no wait.
pub fn scan_wait_ms(raw: &str) -> WaitScan {
    use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};
    if !raw.contains("waitMs") && !raw.contains("\\u") {
        return WaitScan::Absent;
    }
    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = WaitScan;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a params object")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<WaitScan, A::Error> {
            let mut found = WaitScan::Absent;
            while let Some(key) = map.next_key::<std::borrow::Cow<str>>()? {
                if key == "waitMs" {
                    let tok: &serde_json::value::RawValue = map.next_value()?;
                    found = match (found, parse_wait_ms(tok.get())) {
                        (WaitScan::Absent, Some(v)) => WaitScan::Valid(v),
                        _ => WaitScan::Invalid,
                    };
                } else {
                    map.next_value::<IgnoredAny>()?;
                }
            }
            Ok(found)
        }
    }
    serde_json::Deserializer::from_str(raw)
        .deserialize_map(V)
        .unwrap_or(WaitScan::Absent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    fn none() -> Option<ReadPermits> {
        Some(ReadPermits::default())
    }

    /// A synthetic read: pending until `ready` is set, then final with the number of reads.
    async fn wait_for<'a>(
        reg: &'a Arc<Registry>,
        ready: &'a AtomicBool,
        reads: &'a AtomicUsize,
        requested: u64,
        slot: &'a ActiveSlot,
    ) -> (&'static str, u64) {
        run(
            reg,
            "t",
            Class::V2,
            Instant::now(),
            requested,
            slot,
            &none,
            || "busy",
            |_p| async {
                reads.fetch_add(1, Ordering::SeqCst);
                if ready.load(Ordering::SeqCst) {
                    Read {
                        pending: false,
                        value: "done",
                    }
                } else {
                    Read {
                        pending: true,
                        value: "pending",
                    }
                }
            },
        )
        .await
    }

    async fn until(mut f: impl FnMut() -> bool) {
        for _ in 0..400 {
            if f() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("condition not reached");
    }

    #[tokio::test]
    async fn parks_wakes_on_a_notification_and_releases_everything() {
        let reg = Arc::new(Registry::new());
        let (ready, reads) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicUsize::new(0)),
        );
        let (r2, rd2, rs2) = (Arc::clone(&reg), Arc::clone(&ready), Arc::clone(&reads));
        let t =
            tokio::spawn(
                async move { wait_for(&r2, &rd2, &rs2, 10_000, &ActiveSlot::default()).await },
            );
        until(|| reg.reserved() == 1).await;
        assert_eq!(reads.load(Ordering::SeqCst), 1, "one read, then parked");
        // An unrelated notification re-reads but does not finish or extend the wait.
        reg.notify();
        until(|| reads.load(Ordering::SeqCst) == 2).await;
        assert_eq!(reg.reserved(), 1);
        ready.store(true, Ordering::SeqCst);
        reg.notify();
        let (v, waited) = t.await.unwrap();
        assert_eq!(v, "done");
        assert!(waited < 10_000);
        assert_eq!(
            (reg.reserved(), reg.resume_queued(), reg.resume_running()),
            (0, 0, 0)
        );
        assert_eq!(reg.recheck_count("t"), 2);
        assert_eq!(reg.request_count("t", "completed"), 1);
    }

    #[tokio::test]
    async fn an_event_during_the_read_is_never_lost() {
        let reg = Arc::new(Registry::new());
        let ready = AtomicBool::new(false);
        let reg2 = Arc::clone(&reg);
        // The first read observes "pending", then the commit lands before the request parks.
        let (v, _) = run(
            &reg,
            "t",
            Class::V2,
            Instant::now(),
            5_000,
            &ActiveSlot::default(),
            &none,
            || "busy",
            |_p| {
                let first = !ready.swap(true, Ordering::SeqCst);
                if first {
                    reg2.notify(); // between the read's snapshot and the arm
                }
                async move {
                    Read {
                        pending: first,
                        value: if first { "pending" } else { "done" },
                    }
                }
            },
        )
        .await;
        assert_eq!(
            v, "done",
            "a notify during the read forces an immediate re-read, not a 5 s sleep"
        );
    }

    #[tokio::test]
    async fn timeout_is_a_final_ordinary_read_with_the_echo() {
        let reg = Arc::new(Registry::new());
        let (ready, reads) = (AtomicBool::new(false), AtomicUsize::new(0));
        let (v, waited) = wait_for(&reg, &ready, &reads, 120, &ActiveSlot::default()).await;
        assert_eq!(v, "pending");
        assert!((120..400).contains(&waited), "{waited}");
        assert_eq!(
            reads.load(Ordering::SeqCst),
            2,
            "first read and the final read"
        );
        assert_eq!(reg.request_count("t", "timeout"), 1);
        assert_eq!(reg.reserved(), 0);
    }

    #[tokio::test]
    async fn zero_and_capped_requests_are_immediate_with_a_zero_echo() {
        let reg = Arc::new(Registry::new());
        let (ready, reads) = (AtomicBool::new(false), AtomicUsize::new(0));
        let (v, w) = wait_for(&reg, &ready, &reads, 0, &ActiveSlot::default()).await;
        assert_eq!((v, w, reads.load(Ordering::SeqCst)), ("pending", 0, 1));
        assert_eq!(reg.request_count("t", "immediate_zero"), 1);
        // cap zero, C < 2, max wait zero: shed, never an error
        for configure in [0usize, 1, 2] {
            let reg = Arc::new(Registry::new());
            match configure {
                0 => reg.configure(20_000, 0, FINAL_READ_RESERVE),
                1 => reg.set_concurrency(1),
                _ => reg.configure(0, 1024, FINAL_READ_RESERVE),
            }
            let reads = AtomicUsize::new(0);
            let (v, w) = wait_for(&reg, &ready, &reads, 5_000, &ActiveSlot::default()).await;
            assert_eq!(
                (v, w, reads.load(Ordering::SeqCst)),
                ("pending", 0, 1),
                "case {configure}"
            );
        }
    }

    #[tokio::test]
    async fn the_cap_bounds_admitted_waits_and_the_rest_are_served_immediately() {
        let reg = Arc::new(Registry::new());
        reg.configure(20_000, 2, FINAL_READ_RESERVE);
        let ready = Arc::new(AtomicBool::new(false));
        let mut parked = vec![];
        for _ in 0..2 {
            let (r, rd) = (Arc::clone(&reg), Arc::clone(&ready));
            parked.push(tokio::spawn(async move {
                wait_for(
                    &r,
                    &rd,
                    &AtomicUsize::new(0),
                    10_000,
                    &ActiveSlot::default(),
                )
                .await
            }));
        }
        until(|| reg.reserved() == 2).await;
        let reads = AtomicUsize::new(0);
        let (v, w) = wait_for(&reg, &ready, &reads, 10_000, &ActiveSlot::default()).await;
        assert_eq!((v, w), ("pending", 0), "over the cap: immediate, zero echo");
        assert_eq!(reg.request_count("t", "shed_capacity"), 1);
        assert_eq!(reg.reserved(), 2, "the cap holds");
        ready.store(true, Ordering::SeqCst);
        reg.notify();
        for p in parked {
            assert_eq!(p.await.unwrap().0, "done");
        }
        assert_eq!(reg.reserved(), 0);
    }

    #[tokio::test]
    async fn a_dropped_request_frees_its_slot_at_once() {
        let reg = Arc::new(Registry::new());
        let ready = Arc::new(AtomicBool::new(false));
        let (r, rd) = (Arc::clone(&reg), Arc::clone(&ready));
        let t = tokio::spawn(async move {
            wait_for(
                &r,
                &rd,
                &AtomicUsize::new(0),
                10_000,
                &ActiveSlot::default(),
            )
            .await
        });
        until(|| reg.reserved() == 1).await;
        t.abort();
        until(|| reg.reserved() == 0).await;
        assert_eq!(reg.request_count("t", "cancelled"), 1);
        assert_eq!(reg.resume_queued(), 0);
    }

    #[tokio::test]
    async fn a_parked_request_holds_no_active_budget() {
        let reg = Arc::new(Registry::new());
        let handle = reg.gate().acquire_handle().unwrap();
        let slot = ActiveSlot::new(Some(handle));
        assert_eq!(reg.gate().in_use(), 1);
        let ready = Arc::new(AtomicBool::new(false));
        let (r, rd, sl) = (Arc::clone(&reg), Arc::clone(&ready), slot.clone());
        let t =
            tokio::spawn(async move { wait_for(&r, &rd, &AtomicUsize::new(0), 10_000, &sl).await });
        until(|| reg.reserved() == 1).await;
        assert_eq!(reg.gate().in_use(), 0, "parked: nothing held");
        ready.store(true, Ordering::SeqCst);
        reg.notify();
        t.await.unwrap();
        assert_eq!(
            reg.gate().in_use(),
            1,
            "the resumed read's unit stays with the request until the response is written"
        );
        drop(slot.take());
        assert_eq!(reg.gate().in_use(), 0);
    }

    #[tokio::test]
    async fn a_drain_ends_every_wait_with_a_final_read() {
        let reg = Arc::new(Registry::new());
        let ready = Arc::new(AtomicBool::new(false));
        let (r, rd) = (Arc::clone(&reg), Arc::clone(&ready));
        let t = tokio::spawn(async move {
            wait_for(
                &r,
                &rd,
                &AtomicUsize::new(0),
                10_000,
                &ActiveSlot::default(),
            )
            .await
        });
        until(|| reg.reserved() == 1).await;
        reg.drain();
        let (v, _) = t.await.unwrap();
        assert_eq!(v, "pending", "the then-current ordinary result");
        assert_eq!(reg.request_count("t", "drained"), 1);
        // new waits are refused: immediate, zero echo
        let reads = AtomicUsize::new(0);
        assert_eq!(
            wait_for(&reg, &ready, &reads, 10_000, &ActiveSlot::default()).await,
            ("pending", 0)
        );
        assert_eq!(reg.request_count("t", "shed_draining"), 1);
    }

    #[tokio::test]
    async fn resumed_reads_run_at_most_the_quota_at_a_time() {
        let reg = Arc::new(Registry::new());
        reg.set_concurrency(8); // quota max(1, 8/4) = 2
        let ready = Arc::new(AtomicBool::new(false));
        let (cur, max) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let mut tasks = vec![];
        for _ in 0..12 {
            let (r, rd, c, m) = (
                Arc::clone(&reg),
                Arc::clone(&ready),
                Arc::clone(&cur),
                Arc::clone(&max),
            );
            tasks.push(tokio::spawn(async move {
                run(
                    &r,
                    "t",
                    Class::V2,
                    Instant::now(),
                    10_000,
                    &ActiveSlot::default(),
                    &none,
                    || "busy",
                    |_p| {
                        let (rd, c, m) = (Arc::clone(&rd), Arc::clone(&c), Arc::clone(&m));
                        async move {
                            if !rd.load(Ordering::SeqCst) {
                                return Read {
                                    pending: true,
                                    value: "pending",
                                };
                            }
                            let now = c.fetch_add(1, Ordering::SeqCst) + 1;
                            m.fetch_max(now, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(20)).await;
                            c.fetch_sub(1, Ordering::SeqCst);
                            Read {
                                pending: false,
                                value: "done",
                            }
                        }
                    },
                )
                .await
            }));
        }
        until(|| reg.reserved() == 12).await;
        ready.store(true, Ordering::SeqCst);
        reg.notify();
        for t in tasks {
            assert_eq!(t.await.unwrap().0, "done");
        }
        assert!(
            max.load(Ordering::SeqCst) <= 2,
            "max concurrent resumed reads {}",
            max.load(Ordering::SeqCst)
        );
        assert_eq!(reg.recheck_count("t"), 12);
        assert_eq!(
            (reg.reserved(), reg.resume_queued(), reg.resume_running()),
            (0, 0, 0)
        );
    }

    #[tokio::test]
    async fn a_resumption_leaves_headroom_and_waits_for_a_freed_unit() {
        let reg = Arc::new(Registry::new());
        reg.set_concurrency(2);
        let hold = reg.gate().acquire_handle().unwrap(); // a fresh request is active
        let ready = Arc::new(AtomicBool::new(false));
        let (r, rd) = (Arc::clone(&reg), Arc::clone(&ready));
        let t = tokio::spawn(async move {
            wait_for(
                &r,
                &rd,
                &AtomicUsize::new(0),
                10_000,
                &ActiveSlot::default(),
            )
            .await
        });
        until(|| reg.reserved() == 1).await;
        ready.store(true, Ordering::SeqCst);
        reg.notify();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            reg.resume_queued(),
            1,
            "used 1 + the resumption + 1 headroom exceeds C = 2: queued"
        );
        assert!(!t.is_finished());
        drop(hold);
        assert_eq!(t.await.unwrap().0, "done");
    }

    #[tokio::test]
    async fn an_unserved_resumption_gets_the_busy_answer_at_its_deadline() {
        let reg = Arc::new(Registry::new());
        reg.set_concurrency(2);
        let _hold = reg.gate().acquire_handle().unwrap();
        let ready = Arc::new(AtomicBool::new(false));
        let (r, rd) = (Arc::clone(&reg), Arc::clone(&ready));
        let t = tokio::spawn(async move {
            wait_for(
                &r,
                &rd,
                &AtomicUsize::new(0),
                10_000,
                &ActiveSlot::default(),
            )
            .await
        });
        until(|| reg.reserved() == 1).await;
        let t0 = Instant::now();
        reg.notify();
        let (v, _) = t.await.unwrap();
        assert_eq!(v, "busy");
        let dt = t0.elapsed();
        assert!(
            dt >= Duration::from_millis(1900) && dt < Duration::from_millis(3000),
            "{dt:?}: entry + 2 s"
        );
        assert_eq!(reg.request_count("t", "busy_admission_deadline"), 1);
        assert_eq!(reg.reserved(), 0);
    }

    #[test]
    fn wait_is_clamped_before_conversion_and_to_the_remaining_budget() {
        let now = Instant::now();
        let reserve = total_reserve(FINAL_READ_RESERVE);
        let max = Duration::from_secs(20);
        assert_eq!(
            effective_wait(0, max, reserve, METHOD_BUDGET, now, now),
            Duration::ZERO
        );
        assert_eq!(
            effective_wait(5, max, reserve, METHOD_BUDGET, now, now),
            Duration::from_millis(5)
        );
        assert_eq!(
            effective_wait(MAX_WAIT_MS, max, reserve, METHOD_BUDGET, now, now),
            max
        );
        assert_eq!(
            effective_wait(u64::MAX, max, reserve, METHOD_BUDGET, now, now),
            max
        );
        // 12 s into the 30 s budget: 18 - 8 = 10 s may be waited; at 22 s nothing is left
        assert_eq!(
            effective_wait(
                20_000,
                max,
                reserve,
                METHOD_BUDGET,
                now - Duration::from_secs(12),
                now
            ),
            Duration::from_secs(10)
        );
        assert_eq!(
            effective_wait(
                20_000,
                max,
                reserve,
                METHOD_BUDGET,
                now - Duration::from_secs(22),
                now
            ),
            Duration::ZERO
        );
        assert!(validate_limits(20_000, 1024, Duration::from_secs(5)).is_ok());
        assert!(validate_limits(22_000, 1024, Duration::from_secs(5)).is_err());
        assert!(
            validate_limits(20_000, 1024, Duration::from_secs(8)).is_err(),
            "a longer batch timeout shrinks the room"
        );
        assert!(
            validate_limits(1_000_000, 0, Duration::from_secs(5)).is_ok(),
            "zero waiters: nothing parks"
        );
    }

    #[test]
    fn scan_finds_a_valid_wait_whatever_else_the_params_hold() {
        use WaitScan::*;
        let ids = r#""stateIds":["ab"]"#;
        for (raw, want) in [
            (format!("{{{ids}}}"), Absent),
            (format!("{{{ids},\"waitMs\":0}}"), Valid(0)),
            (format!("{{\"waitMs\":7,{ids}}}"), Valid(7)),
            (
                format!("{{{ids},\"waitMs\":9007199254740991}}"),
                Valid(MAX_WAIT_MS),
            ),
            (format!("{{{ids},\"waitMs\":9007199254740992}}"), Invalid),
            (format!("{{{ids},\"waitMs\":-0}}"), Invalid),
            (format!("{{{ids},\"waitMs\":2.0}}"), Invalid),
            (format!("{{{ids},\"waitMs\":2e0}}"), Invalid),
            (format!("{{{ids},\"waitMs\":null}}"), Invalid),
            (format!("{{{ids},\"waitMs\":\"2\"}}"), Invalid),
            (format!("{{{ids},\"waitMs\":2,\"waitMs\":2}}"), Invalid),
            (
                format!("{{{ids},\"wait\\u004Ds\":2,\"waitMs\":2}}"),
                Invalid,
            ),
            (format!("{{{ids},\"waitms\":2}}"), Absent),
            ("[1,2]".to_owned(), Absent),
            ("\"waitMs\"".to_owned(), Absent),
        ] {
            assert_eq!(scan_wait_ms(&raw), want, "{raw}");
        }
    }

    /// Resumed reads keep one unit free in every pool, whatever the interleaving: a compare-and-
    /// swap, not an observation followed by a take.
    #[test]
    fn headroom_holds_under_racing_threads() {
        let reg = Registry::new();
        let pool = reg.new_pool(8);
        let max_used = Arc::new(AtomicUsize::new(0));
        let mut threads = vec![];
        for _ in 0..16 {
            let (pool, max_used) = (Arc::clone(&pool), Arc::clone(&max_used));
            threads.push(std::thread::spawn(move || {
                let mut got = 0u32;
                for _ in 0..20_000 {
                    if let Some(p) = pool.try_acquire(1) {
                        max_used.fetch_max(pool.in_use(), Ordering::SeqCst);
                        got += 1;
                        drop(p);
                    }
                }
                got
            }));
        }
        let got: u32 = threads.into_iter().map(|t| t.join().unwrap()).sum();
        assert!(got > 0);
        assert!(
            max_used.load(Ordering::SeqCst) <= 7,
            "resumed reads reached {} of 8 units",
            max_used.load(Ordering::SeqCst)
        );
        assert_eq!(pool.in_use(), 0);
        // With the resumed holders at their ceiling a fresh request still gets the last unit,
        // and two fresh requests racing for it cannot both win.
        let held: Vec<_> = (0..7).map(|_| pool.try_acquire(1).unwrap()).collect();
        assert!(pool.try_acquire(1).is_none());
        let winners: usize = (0..8)
            .map(|_| {
                let pool = Arc::clone(&pool);
                std::thread::spawn(move || pool.try_acquire(0).map(std::mem::forget).is_some())
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|t| t.join().unwrap() as usize)
            .sum();
        assert_eq!(winners, 1);
        drop(held);
    }

    /// A refusal by the batch/proof pools makes the resumption sleep until a real release: the
    /// attempts stay bounded while capacity is saturated, and fresh traffic continues.
    #[tokio::test]
    async fn saturated_pools_do_not_make_the_resumption_spin() {
        let reg = Arc::new(Registry::new());
        let batch = reg.new_pool(8);
        let proof = reg.new_pool(16);
        let (b2, p2) = (Arc::clone(&batch), Arc::clone(&proof));
        let try_pools = move || {
            let b = b2.try_acquire(1)?;
            let Some(p) = p2.try_acquire(1) else {
                b.rollback();
                return None;
            };
            Some(ReadPermits {
                batch: Some(b),
                proof: Some(p),
                ..Default::default()
            })
        };
        // Fresh batch reads hold 7 of 8 slots: a resumption needs two free.
        let held: Vec<_> = (0..7).map(|_| batch.try_acquire(0).unwrap()).collect();
        let ready = Arc::new(AtomicBool::new(false));
        let (r2, rd2) = (Arc::clone(&reg), Arc::clone(&ready));
        let t = tokio::spawn(async move {
            run(
                &r2,
                "t",
                Class::Batch,
                Instant::now(),
                10_000,
                &ActiveSlot::default(),
                &try_pools,
                || "busy",
                |p| {
                    let rd2 = Arc::clone(&rd2);
                    async move {
                        drop(p);
                        if rd2.load(Ordering::SeqCst) {
                            Read {
                                pending: false,
                                value: "done",
                            }
                        } else {
                            Read {
                                pending: true,
                                value: "pending",
                            }
                        }
                    }
                },
            )
            .await
        });
        until(|| reg.reserved() == 1).await;
        ready.store(true, Ordering::SeqCst);
        reg.notify();
        until(|| reg.resume_queued() == 1).await;
        let before = reg.gate().resume_attempts();
        tokio::time::sleep(Duration::from_millis(400)).await;
        let attempts = reg.gate().resume_attempts() - before;
        assert!(
            attempts <= 1,
            "{attempts} admission attempts while saturated: it spins"
        );
        // Fresh traffic continues: the last slot is still available to a fresh batch.
        let fresh = batch
            .try_acquire(0)
            .expect("a fresh request still gets the last slot");
        drop(fresh);
        // A real release wakes it exactly once more and it is granted.
        drop(held);
        assert_eq!(t.await.unwrap().0, "done");
        assert!(reg.gate().resume_attempts() - before <= 3);
        assert_eq!((batch.in_use(), proof.in_use()), (0, 0));
    }

    struct Tracked(Arc<AtomicUsize>);

    impl Drop for Tracked {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// The last read's value (an encoded proof, a UC) is dropped before the request suspends.
    #[tokio::test]
    async fn the_read_value_is_dropped_before_the_request_parks() {
        let reg = Arc::new(Registry::new());
        let dropped = Arc::new(AtomicUsize::new(0));
        let ready = Arc::new(AtomicBool::new(false));
        let (r2, d2, rd2) = (Arc::clone(&reg), Arc::clone(&dropped), Arc::clone(&ready));
        let t = tokio::spawn(async move {
            run(
                &r2,
                "t",
                Class::V2,
                Instant::now(),
                10_000,
                &ActiveSlot::default(),
                &none,
                || Tracked(Arc::new(AtomicUsize::new(0))),
                |_p| {
                    let (d, rd) = (Arc::clone(&d2), Arc::clone(&rd2));
                    async move {
                        Read {
                            pending: !rd.load(Ordering::SeqCst),
                            value: Tracked(d),
                        }
                    }
                },
            )
            .await
            .1
        });
        until(|| reg.reserved() == 1).await;
        assert_eq!(
            dropped.load(Ordering::SeqCst),
            1,
            "the first read's value is gone while parked"
        );
        ready.store(true, Ordering::SeqCst);
        reg.notify();
        t.await.unwrap();
    }

    /// A drain which lands between admission and the first park (here: during the first read) is
    /// not consumed as the receiver's initial generation: the request finishes at once.
    #[tokio::test]
    async fn a_drain_during_the_first_read_does_not_park_the_request() {
        let reg = Arc::new(Registry::new());
        let t0 = Instant::now();
        let r2 = Arc::clone(&reg);
        let (v, _) = run(
            &reg,
            "t",
            Class::V2,
            Instant::now(),
            10_000,
            &ActiveSlot::default(),
            &none,
            || "busy",
            |_p| {
                r2.drain();
                async {
                    Read {
                        pending: true,
                        value: "pending",
                    }
                }
            },
        )
        .await;
        assert_eq!(v, "pending");
        assert!(t0.elapsed() < Duration::from_secs(1), "{:?}", t0.elapsed());
        assert_eq!(reg.request_count("t", "drained"), 1);
        assert_eq!(reg.reserved(), 0);
    }

    /// A batch resumer which tentatively takes an HTTP unit and then fails its method pool must
    /// not hide that unit from a concurrent v2 resumer: with two units free the v2 read is
    /// granted, every time, instead of sleeping until its deadline.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_failing_batch_resumer_does_not_starve_a_v2_resumer() {
        for round in 0..40 {
            let reg = Arc::new(Registry::new());
            reg.set_concurrency(8);
            let batch = reg.new_pool(8);
            let proof = reg.new_pool(16);
            let _fresh: Vec<_> = (0..6)
                .map(|_| reg.gate().acquire_handle().unwrap())
                .collect();
            let _batch_full: Vec<_> = (0..8).map(|_| batch.try_acquire(0).unwrap()).collect();
            let (b2, p2) = (Arc::clone(&batch), Arc::clone(&proof));
            let try_pools = Arc::new(move || {
                let b = b2.try_acquire(1)?;
                let Some(p) = p2.try_acquire(1) else {
                    b.rollback();
                    return None;
                };
                Some(ReadPermits {
                    batch: Some(b),
                    proof: Some(p),
                    ..Default::default()
                })
            });
            let ready = Arc::new(AtomicBool::new(false));
            let mk = |class: Class, pools: bool| {
                let (reg, ready, tp) =
                    (Arc::clone(&reg), Arc::clone(&ready), Arc::clone(&try_pools));
                tokio::spawn(async move {
                    let none_pools = || Some(ReadPermits::default());
                    let tp2 = move || tp();
                    let pools_fn: &(dyn Fn() -> Option<ReadPermits> + Send + Sync) =
                        if pools { &tp2 } else { &none_pools };
                    run(
                        &reg,
                        "t",
                        class,
                        Instant::now(),
                        10_000,
                        &ActiveSlot::default(),
                        pools_fn,
                        || "busy",
                        |p| {
                            let ready = Arc::clone(&ready);
                            async move {
                                drop(p);
                                if ready.load(Ordering::SeqCst) {
                                    Read {
                                        pending: false,
                                        value: "done",
                                    }
                                } else {
                                    Read {
                                        pending: true,
                                        value: "pending",
                                    }
                                }
                            }
                        },
                    )
                    .await
                    .0
                })
            };
            let b_task = mk(Class::Batch, true);
            let v_task = mk(Class::V2, false);
            until(|| reg.reserved() == 2).await;
            ready.store(true, Ordering::SeqCst);
            reg.notify();
            let v = tokio::time::timeout(Duration::from_millis(1500), v_task)
                .await
                .unwrap_or_else(|_| panic!("round {round}: the v2 resumer starved"))
                .unwrap();
            assert_eq!(v, "done", "round {round}");
            b_task.abort();
        }
    }
}
