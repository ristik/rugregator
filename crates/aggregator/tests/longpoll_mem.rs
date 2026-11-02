//! Retained heap of parked long-poll requests at the reservation cap.
//!
//! Own test binary: it installs a counting allocator, so nothing else may run in this process.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;
use tokio::sync::{mpsc, watch, Semaphore};

use uni_aggregator::api::server::dispatch;
use uni_aggregator::config::{ConsistencyProofMode, RoundConfig};
use uni_aggregator::round::{BftCommitter, BftCommitterStub, RoundManager};
use uni_aggregator::storage::AggregatorState;
use uni_aggregator::validation::ValidatedRequest;

struct Counting;
static LIVE: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size() as isize, Ordering::Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size() as isize, Ordering::Relaxed);
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        LIVE.fetch_add(n as isize - l.size() as isize, Ordering::Relaxed);
        System.realloc(p, l, n)
    }
}

#[global_allocator]
static A: Counting = Counting;

struct Gated {
    inner: BftCommitterStub,
    permits: Semaphore,
    commits: AtomicUsize,
}

#[async_trait]
impl BftCommitter for Gated {
    async fn commit_block(
        &self,
        n: u64,
        root: Option<[u8; 32]>,
        prev: Option<[u8; 32]>,
        zk: Option<Vec<u8>>,
        rt: u64,
        bs: u64,
        ss: u64,
    ) -> anyhow::Result<()> {
        self.commits.fetch_add(1, Ordering::SeqCst);
        self.inner.commit_block(n, root, prev, zk, rt, bs, ss).await
    }
    async fn wait_for_uc(&self, n: u64) -> anyhow::Result<Vec<u8>> {
        self.permits.acquire().await.unwrap().forget();
        self.inner.wait_for_uc(n).await
    }
    fn reference_time(&self) -> u64 {
        self.inner.reference_time()
    }
    fn subscribe_reference_time(&self) -> watch::Receiver<u64> {
        self.inner.subscribe_reference_time()
    }
}

fn request(id: u32) -> ValidatedRequest {
    let mut sid = [0u8; 32];
    sid[..4].copy_from_slice(&id.to_be_bytes());
    ValidatedRequest {
        state_id_hex: hex::encode(sid),
        state_id: sid.to_vec(),
        predicate_cbor: vec![0xd9, 0x98, 0x78, 0x83, 0x01, 0x41, 0x01, 0x41, 0x01],
        source_state_hash: vec![2; 32],
        transaction_hash: vec![7; uni_aggregator::smt::AGGREGATION_TREE_VALUE_SIZE],
        expires_at: None,
        effective_timeout: u64::MAX / 2,
        witness: vec![4; 65],
        public_key: vec![5; 33],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn parked_waiters_at_the_cap_retain_only_their_ids() {
    const CAP: usize = 1024;
    let (tx, rx) = mpsc::channel(10_000);
    let state = AggregatorState::new(tx, None);
    let bft = Arc::new(Gated {
        inner: BftCommitterStub::new(),
        permits: Semaphore::new(0),
        commits: AtomicUsize::new(0),
    });
    tokio::spawn(
        RoundManager::new(
            RoundConfig {
                round_duration_ms: 100,
                batch_limit: 100,
                proof_mode: ConsistencyProofMode::Off,
                zk_proof_kind: "core".into(),
            },
            rx,
            Arc::clone(&state),
            Arc::clone(&bft) as Arc<dyn BftCommitter>,
        )
        .run(),
    );
    state.submit_request(request(0)).await.unwrap();
    bft.permits.add_permits(1); // block 1; later rounds never get their UC: everything stays pending
    for _ in 0..300 {
        if state.latest_finalized_block().await.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(state.latest_finalized_block().await.is_some());
    state
        .longpoll()
        .configure(20_000, CAP, Duration::from_secs(5));
    for i in 1..=(2 * CAP as u32) {
        state.submit_request(request(i)).await.unwrap();
    }
    let reg = Arc::clone(state.longpoll());
    let bodies: Vec<String> = (1..=CAP as u32)
        .map(|i| {
            let mut sid = [0u8; 32];
            sid[..4].copy_from_slice(&i.to_be_bytes());
            json!({"jsonrpc":"2.0","id":1,"method":"get_inclusion_proof.v2",
                   "params":{"stateId": hex::encode(sid), "waitMs": 20000, "includeStatus": true}})
            .to_string()
        })
        .collect();
    let body_bytes: usize = bodies.iter().map(|b| b.len()).sum();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let before = LIVE.load(Ordering::Relaxed);
    let mut tasks = vec![];
    for b in bodies {
        let s = Arc::clone(&state);
        tasks.push(tokio::spawn(async move { dispatch(s, b.as_bytes()).await }));
    }
    for _ in 0..600 {
        if reg.reserved() == CAP {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(reg.reserved(), CAP, "the cap is reached");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let after = LIVE.load(Ordering::Relaxed);
    let per = (after - before) as f64 / CAP as f64;
    eprintln!(
        "RETAINED: {CAP} parked v2 waiters hold {:.0} bytes each ({} KiB total, of which request bodies {} bytes)",
        per,
        (after - before) / 1024,
        body_bytes
    );
    // No encoded proof or UC survives parking: an empty-proof response is several hundred bytes
    // of hex plus the UC (about 1.5 KiB), so a retained copy would show here.
    assert!(per < 4096.0, "{per} bytes per parked waiter");
    for t in &tasks {
        t.abort();
    }
    for t in tasks {
        let _ = t.await;
    }
    assert_eq!(reg.reserved(), 0);
}
