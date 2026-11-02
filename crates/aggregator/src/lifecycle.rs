//! Ordered shutdown with explicit failure paths.
//!
//! The order is the dependency order: refuse new waits and wake the parked ones, let in-flight
//! requests finish for the grace period and then abort and join the remaining connections, wait
//! until every proof worker has acknowledged its work (it drops its accounting when it stops),
//! and only then stop and join the round manager (which persists the SMT). A step which does not
//! complete is **not** a clean shutdown: the failure is returned and the later steps are skipped,
//! so storage is never torn down beneath work that has not acknowledged completion. The caller
//! exits non-zero without closing storage; the WAL recovers the state on the next start.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{info, warn};

use crate::api::transport::Server;
use crate::storage::AggregatorState;

/// Time allowed to each step.
#[derive(Debug, Clone, Copy)]
pub struct ShutdownLimits {
    /// In-flight requests finish within this; afterwards connections are cut.
    pub grace: Duration,
    /// Proof workers acknowledge their work within this, after the connections are gone.
    pub workers: Duration,
    /// The round manager persists and stops within this.
    pub round_manager: Duration,
}

impl Default for ShutdownLimits {
    fn default() -> Self {
        Self {
            grace: Duration::from_secs(30),
            workers: Duration::from_secs(30),
            round_manager: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ShutdownError {
    /// Work handed to the proof workers (or a request's budget unit) was not acknowledged in
    /// time. The round manager was *not* stopped: storage stays up.
    WorkersBusy {
        requests: usize,
        batches: usize,
        proofs: usize,
    },
    /// The round manager did not stop (and persist) in time. Its task is still running.
    RoundManagerStuck,
    /// The round manager task ended abnormally.
    RoundManagerFailed(String),
}

impl std::fmt::Display for ShutdownError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WorkersBusy {
                requests,
                batches,
                proofs,
            } => write!(
                f,
                "proof work did not acknowledge completion ({requests} requests, {batches} batch slots, {proofs} proof slots held); storage left open"
            ),
            Self::RoundManagerStuck => f.write_str("the round manager did not stop in time"),
            Self::RoundManagerFailed(e) => write!(f, "the round manager task failed: {e}"),
        }
    }
}

impl std::error::Error for ShutdownError {}

/// Drain the HTTP side: wake waits, grace, then cut and join connections, then wait for the
/// workers. Returns the number of connections which had to be cut.
pub async fn drain_http(
    server: Server,
    state: &Arc<AggregatorState>,
    limits: ShutdownLimits,
) -> Result<usize, ShutdownError> {
    state.longpoll().drain();
    let cut = server.shutdown(limits.grace).await;
    if cut > 0 {
        warn!(
            connections = cut,
            "drain deadline reached: connections cancelled and joined"
        );
    } else {
        info!("HTTP server drained");
    }
    if !state
        .wait_workers_idle(Instant::now() + limits.workers)
        .await
    {
        return Err(ShutdownError::WorkersBusy {
            requests: state.longpoll().gate().in_use(),
            batches: state.batch_pool().in_use(),
            proofs: state.proof_pool().in_use(),
        });
    }
    Ok(cut)
}

/// Stop the round manager and join it. On a timeout the task keeps running and its handle stays
/// with the caller.
pub async fn stop_round_manager(
    stop: &Notify,
    task: &mut JoinHandle<()>,
    limit: Duration,
) -> Result<(), ShutdownError> {
    stop.notify_one();
    match tokio::time::timeout(limit, task).await {
        Ok(Ok(())) => {
            info!("round manager stopped");
            Ok(())
        }
        Ok(Err(e)) => Err(ShutdownError::RoundManagerFailed(e.to_string())),
        Err(_) => Err(ShutdownError::RoundManagerStuck),
    }
}

/// The whole sequence.
pub async fn shutdown(
    server: Server,
    state: &Arc<AggregatorState>,
    round_manager_stop: &Notify,
    round_manager: &mut JoinHandle<()>,
    limits: ShutdownLimits,
) -> Result<(), ShutdownError> {
    drain_http(server, state, limits).await?;
    stop_round_manager(round_manager_stop, round_manager, limits.round_manager).await
}
