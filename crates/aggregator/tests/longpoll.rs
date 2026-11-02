//! End-to-end long-poll behaviour: a real RoundManager with a controllable certifier, and the
//! real HTTP router over TCP (disconnects, the 503 budget answer, drain).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, Semaphore};

use uni_aggregator::api::build_router;
use uni_aggregator::api::server::dispatch;
use uni_aggregator::config::{ConsistencyProofMode, RoundConfig};
use uni_aggregator::round::{BftCommitter, BftCommitterStub, RoundManager};
use uni_aggregator::storage::AggregatorState;
use uni_aggregator::validation::ValidatedRequest;

/// A certifier whose UC the test releases (or fails) by hand.
struct Gated {
    inner: BftCommitterStub,
    permits: Semaphore,
    fail_next: AtomicUsize,
    commits: AtomicUsize,
}

impl Gated {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: BftCommitterStub::new(),
            permits: Semaphore::new(0),
            fail_next: AtomicUsize::new(0),
            commits: AtomicUsize::new(0),
        })
    }
}

#[async_trait]
impl BftCommitter for Gated {
    async fn commit_block(
        &self,
        block_number: u64,
        new_root: Option<[u8; 32]>,
        prev_root: Option<[u8; 32]>,
        zk_proof: Option<Vec<u8>>,
        reference_time: u64,
        block_size: u64,
        state_size: u64,
    ) -> anyhow::Result<()> {
        self.commits.fetch_add(1, Ordering::SeqCst);
        self.inner
            .commit_block(
                block_number,
                new_root,
                prev_root,
                zk_proof,
                reference_time,
                block_size,
                state_size,
            )
            .await
    }
    async fn wait_for_uc(&self, block_number: u64) -> anyhow::Result<Vec<u8>> {
        self.permits.acquire().await.unwrap().forget();
        if self
            .fail_next
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n: usize| {
                n.checked_sub(1)
            })
            .is_ok()
        {
            anyhow::bail!("transient certification failure");
        }
        self.inner.wait_for_uc(block_number).await
    }
    fn reference_time(&self) -> u64 {
        self.inner.reference_time()
    }
    fn subscribe_reference_time(&self) -> watch::Receiver<u64> {
        self.inner.subscribe_reference_time()
    }
}

fn request(seed: u8) -> ValidatedRequest {
    ValidatedRequest {
        state_id_hex: hex::encode([seed; 32]),
        state_id: vec![seed; 32],
        predicate_cbor: vec![0xd9, 0x98, 0x78, 0x83, 0x01, 0x41, 0x01, 0x41, 0x01],
        source_state_hash: vec![2; 32],
        transaction_hash: vec![seed; uni_aggregator::smt::AGGREGATION_TREE_VALUE_SIZE],
        expires_at: None,
        effective_timeout: u64::MAX / 2,
        witness: vec![4; 65],
        public_key: vec![5; 33],
    }
}

fn request_t(seed: u8, timeout: u64) -> ValidatedRequest {
    ValidatedRequest {
        effective_timeout: timeout,
        ..request(seed)
    }
}

struct Net {
    state: Arc<AggregatorState>,
    bft: Arc<Gated>,
}

/// A running round manager over an in-memory SMT; the first block is already certified.
async fn net() -> Net {
    net_with(50).await
}

async fn net_with(round_ms: u64) -> Net {
    let (tx, rx) = mpsc::channel(100);
    let state = AggregatorState::new(tx, None);
    let bft = Gated::new();
    let rm = RoundManager::new(
        RoundConfig {
            round_duration_ms: round_ms,
            batch_limit: 100,
            proof_mode: ConsistencyProofMode::Off,
            zk_proof_kind: "core".into(),
        },
        rx,
        Arc::clone(&state),
        Arc::clone(&bft) as Arc<dyn BftCommitter>,
    );
    tokio::spawn(rm.run());
    state.submit_request(request(0x01)).await.unwrap();
    bft.permits.add_permits(1);
    until(|| state.longpoll().notify_count() >= 1).await;
    Net { state, bft }
}

async fn until(mut f: impl FnMut() -> bool) {
    for _ in 0..600 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition not reached");
}

fn v2_body(seed: u8, extra: Value) -> String {
    let mut p = json!({"stateId": hex::encode([seed; 32])});
    p.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    json!({"jsonrpc":"2.0","id":1,"method":"get_inclusion_proof.v2","params":p}).to_string()
}

fn batch_body(seeds: &[u8], extra: Value) -> String {
    let ids: Vec<_> = seeds.iter().map(|s| hex::encode([*s; 32])).collect();
    let mut p = json!({"stateIds": ids});
    p.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    json!({"jsonrpc":"2.0","id":2,"method":"get_inclusion_proofs.v1","params":p}).to_string()
}

#[tokio::test]
async fn a_certified_commit_wakes_v2_and_batch_waiters_only_after_the_uc_and_failures_keep_them_parked(
) {
    let n = net().await;
    let reg = Arc::clone(n.state.longpoll());
    let base = reg.notify_count();
    let (b1, b2) = (0x11u8, 0x12u8);
    n.state.submit_request(request(b1)).await.unwrap();
    n.state.submit_request(request(b2)).await.unwrap();
    // 0x01 is included, 0x11 and 0x12 are pending; one v2 waiter, one batch waiter on [0x01, 0x11, 0x12]
    let s = Arc::clone(&n.state);
    let v2 = tokio::spawn(async move {
        dispatch(
            s,
            v2_body(b1, json!({"waitMs": 15000, "includeStatus": true})).as_bytes(),
        )
        .await
    });
    let s = Arc::clone(&n.state);
    let bt = tokio::spawn(async move {
        dispatch(
            s,
            batch_body(&[0x01, b1, b2], json!({"waitMs": 15000})).as_bytes(),
        )
        .await
    });
    until(|| reg.reserved() == 2).await;
    // Proposal, speculative insertion and the BFT submission are not certification: no wake,
    // and the waiters hold no budget, batch slot or proof permit while parked.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(reg.notify_count(), base, "nothing certified yet");
    assert_eq!(reg.reserved(), 2);
    assert!(!v2.is_finished() && !bt.is_finished());
    assert_eq!(reg.gate().in_use(), 0);

    // A failed certification re-queues the requests: still pending, still parked, no wake.
    n.bft.fail_next.store(1, Ordering::SeqCst);
    n.bft.permits.add_permits(1);
    until(|| n.bft.commits.load(Ordering::SeqCst) >= 3).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        reg.notify_count(),
        base,
        "a UC failure is not a terminal change"
    );
    assert_eq!(reg.reserved(), 2);
    assert!(!v2.is_finished() && !bt.is_finished());

    // The certified commit wakes them: both read their proofs at one new view.
    n.bft.permits.add_permits(3);
    let (_, text) = v2.await.unwrap();
    let r: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(r["result"]["status"], json!("included"), "{text}");
    assert!(r["result"]["waitedMs"].as_u64().unwrap() > 300);
    let (_, text) = bt.await.unwrap();
    let r: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(r["result"]["proofs"].as_array().unwrap().len(), 3, "{text}");
    assert!(r["result"]["waitedMs"].as_u64().unwrap() > 300);
    assert_eq!(reg.reserved(), 0);
    assert!(reg.recheck_count("get_inclusion_proof.v2") >= 1);
    assert!(reg.notify_count() > base);
}

#[tokio::test]
async fn a_batch_waits_for_all_entries_and_any_expired_or_unknown_entry_ends_it_at_once() {
    let n = net().await;
    let reg = Arc::clone(n.state.longpoll());
    n.state.submit_request(request(0x21)).await.unwrap();
    n.state.submit_request(request(0x22)).await.unwrap();
    // (1) a never-seen id ends the wait on the first read, pending siblings notwithstanding
    let t0 = std::time::Instant::now();
    let (_, text) = dispatch(
        Arc::clone(&n.state),
        batch_body(&[0x21, 0x77], json!({"waitMs": 15000})).as_bytes(),
    )
    .await;
    let r: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(r["error"]["data"]["detail"], json!("state_unknown"));
    assert_eq!(r["error"]["data"]["waitedMs"], json!(0));
    assert!(t0.elapsed() < Duration::from_secs(2));
    // (2) two pending entries park; one expiring ends the wait while the other is still pending
    let s = Arc::clone(&n.state);
    let t = tokio::spawn(async move {
        dispatch(
            s,
            batch_body(&[0x21, 0x22], json!({"waitMs": 15000})).as_bytes(),
        )
        .await
    });
    until(|| reg.reserved() == 1).await;
    n.state.drop_expired_requests(&[request(0x22)]);
    let (_, text) = t.await.unwrap();
    let r: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        r["error"]["data"]["detail"],
        json!("state_expired"),
        "{text}"
    );
    assert_eq!(
        r["error"]["data"]["indexes"],
        json!({"pending": [0], "expired": [1]})
    );
    assert!(r["error"]["data"]["waitedMs"].as_u64().unwrap() < 5000);
    assert_eq!(reg.reserved(), 0);
}

#[tokio::test]
async fn timeout_returns_the_ordinary_pending_answer_with_the_echo() {
    let n = net().await;
    n.state.submit_request(request(0x31)).await.unwrap();
    let (_, text) = dispatch(
        Arc::clone(&n.state),
        batch_body(&[0x31], json!({"waitMs": 200})).as_bytes(),
    )
    .await;
    let r: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(r["error"]["code"], json!(-32008));
    assert_eq!(r["error"]["data"]["detail"], json!("state_pending"));
    let w = r["error"]["data"]["waitedMs"].as_u64().unwrap();
    assert!((200..800).contains(&w), "{w}");
    let (_, text) = dispatch(
        Arc::clone(&n.state),
        v2_body(0x31, json!({"waitMs": 200, "includeStatus": true})).as_bytes(),
    )
    .await;
    let r: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(r["result"]["status"], json!("pending"));
    assert!(r["result"]["waitedMs"].as_u64().unwrap() >= 200);
    // the same state without a wait: bare string, no echo
    let (_, text) = dispatch(Arc::clone(&n.state), v2_body(0x31, json!({})).as_bytes()).await;
    assert!(serde_json::from_str::<Value>(&text).unwrap()["result"].is_string());
}

// ─── HTTP over TCP ───────────────────────────────────────────────────────────

async fn serve(
    state: Arc<AggregatorState>,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = uni_aggregator::api::transport::spawn(listener, build_router(state));
    let addr = server.local_addr;
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let h = tokio::spawn(async move {
        let _ = rx.await;
        server.shutdown(Duration::from_secs(5)).await;
    });
    (addr, tx, h)
}

async fn send(addr: std::net::SocketAddr, body: &str) -> TcpStream {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    s
}

async fn read_response(mut s: TcpStream) -> (u16, String, String) {
    let mut buf = Vec::new();
    // Content-Length framing: read until the body is complete.
    loop {
        let mut chunk = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(20), s.read(&mut chunk))
            .await
            .unwrap()
            .unwrap();
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf).to_string();
        if let Some(i) = text.find("\r\n\r\n") {
            let head = text[..i].to_lowercase();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .map(|v| v.trim().parse().unwrap())
                .unwrap_or(0);
            if text.len() >= i + 4 + len {
                break;
            }
        }
    }
    let text = String::from_utf8(buf).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, head.to_owned(), body.to_owned())
}

#[tokio::test]
async fn a_client_disconnect_frees_the_reservation_and_holds_no_budget_meanwhile() {
    let n = net().await;
    let reg = Arc::clone(n.state.longpoll());
    n.state.submit_request(request(0x41)).await.unwrap();
    let (addr, stop, server) = serve(Arc::clone(&n.state)).await;
    // EOF
    let s = send(addr, &v2_body(0x41, json!({"waitMs": 15000}))).await;
    until(|| reg.reserved() == 1).await;
    assert_eq!(
        reg.gate().in_use(),
        0,
        "a parked request holds no unit of the budget"
    );
    drop(s);
    until(|| reg.reserved() == 0).await;
    assert_eq!(reg.request_count("get_inclusion_proof.v2", "cancelled"), 1);
    // RST (linger 0) while a batch waits
    let s = send(addr, &batch_body(&[0x41], json!({"waitMs": 15000}))).await;
    until(|| reg.reserved() == 1).await;
    socket2::SockRef::from(&s)
        .set_linger(Some(Duration::ZERO))
        .unwrap();
    drop(s);
    until(|| reg.reserved() == 0).await;
    // pipelined bytes behind the request: hyper does not probe EOF while the next request is
    // buffered (hyper http1 behaviour), so this case is only reported, not asserted.
    assert_eq!(reg.gate().in_use(), 0);
    assert_eq!(n.state.longpoll().resume_queued(), 0);
    let _ = stop.send(());
    server.await.unwrap();
}

#[tokio::test]
async fn an_exhausted_budget_answers_503_with_retry_after_and_parked_requests_do_not_count() {
    let n = net().await;
    let reg = Arc::clone(n.state.longpoll());
    reg.set_concurrency(2);
    n.state.submit_request(request(0x51)).await.unwrap();
    let (addr, stop, server) = serve(Arc::clone(&n.state)).await;
    // Park two waiters: with C = 2 they still leave the whole budget to everyone else.
    let a = send(addr, &v2_body(0x51, json!({"waitMs": 15000}))).await;
    let b = send(addr, &batch_body(&[0x51], json!({"waitMs": 15000}))).await;
    until(|| reg.reserved() == 2).await;
    let (st, _, body) = read_response(
        send(
            addr,
            r#"{"jsonrpc":"2.0","id":9,"method":"get_block_height","params":{}}"#,
        )
        .await,
    )
    .await;
    assert_eq!(st, 200, "{body}");
    // Fill the budget: the next request is refused before it is parsed.
    let h1 = reg.gate().acquire_handle().unwrap();
    let h2 = reg.gate().acquire_handle().unwrap();
    let (st, head, body) = read_response(
        send(
            addr,
            r#"{"jsonrpc":"2.0","id":9,"method":"get_block_height","params":{}}"#,
        )
        .await,
    )
    .await;
    assert_eq!(st, 503);
    assert!(head.to_lowercase().contains("retry-after: 1"), "{head}");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        (v["error"]["code"].clone(), v["id"].clone()),
        (json!(-32006), Value::Null)
    );
    assert_eq!(v["error"]["data"]["retryable"], json!(true));
    drop((h1, h2));
    let (st, _, _) = read_response(
        send(
            addr,
            r#"{"jsonrpc":"2.0","id":9,"method":"get_block_height","params":{}}"#,
        )
        .await,
    )
    .await;
    assert_eq!(st, 200);
    drop((a, b));
    until(|| reg.reserved() == 0).await;
    let _ = stop.send(());
    server.await.unwrap();
}

#[tokio::test]
async fn a_drain_answers_parked_requests_with_a_final_read_and_the_server_joins() {
    let n = net().await;
    let reg = Arc::clone(n.state.longpoll());
    n.state.submit_request(request(0x61)).await.unwrap();
    let (addr, stop, server) = serve(Arc::clone(&n.state)).await;
    let a = send(
        addr,
        &v2_body(0x61, json!({"waitMs": 15000, "includeStatus": true})),
    )
    .await;
    until(|| reg.reserved() == 1).await;
    reg.drain();
    let _ = stop.send(());
    let (st, _, body) = read_response(a).await;
    assert_eq!(st, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["result"]["status"], json!("pending"));
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .unwrap()
        .unwrap();
    assert!(
        reg.gate()
            .wait_idle(tokio::time::Instant::now() + Duration::from_secs(5))
            .await
    );
    assert_eq!(reg.reserved(), 0);
}

// ─── queued expiry, shutdown, transport ──────────────────────────────────────

#[tokio::test]
async fn queued_requests_expire_while_a_round_is_stalled_and_in_round_ones_are_exempt() {
    let n = net_with(300).await;
    let reg = Arc::clone(n.state.longpoll());
    let r = n.state.reference_time();
    assert!(r > 0);
    // A is admitted into a round whose UC the test withholds; its deadline is the reference time
    // the stub publishes as soon as that round has been submitted (r + 1).
    n.state
        .submit_request(request_t(0x71, r + 1))
        .await
        .unwrap();
    until(|| n.bft.commits.load(Ordering::SeqCst) >= 2).await;
    until(|| n.state.reference_time() > r).await;
    // B is only queued (a round is in flight) and its deadline has already been reached by the
    // consensus reference time; nothing else will ever touch it: no new request, no UC.
    n.state
        .submit_request(request_t(0x72, r + 1))
        .await
        .unwrap();
    let s = Arc::clone(&n.state);
    let waiter = tokio::spawn(async move {
        dispatch(
            s,
            v2_body(0x72, json!({"waitMs": 15000, "includeStatus": true})).as_bytes(),
        )
        .await
    });
    let (_, text) = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("the queued expiry wakes the waiter without a UC or another request")
        .unwrap();
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["result"]["status"], json!("expired"), "{text}");
    assert_eq!(n.state.proof_status_hint(&[0x72; 32]), "expired");
    // The in-round request with the very same deadline is untouched and completes with its UC.
    assert_eq!(n.state.proof_status_hint(&[0x71; 32]), "pending");
    n.bft.permits.add_permits(2);
    until(|| n.state.proof_status_hint(&[0x71; 32]) == "included").await;
    assert_eq!(reg.reserved(), 0);
}

#[tokio::test]
async fn a_stuck_connection_is_cancelled_and_joined_at_the_grace_deadline() {
    let n = net().await;
    let reg = Arc::clone(n.state.longpoll());
    n.state.submit_request(request(0x81)).await.unwrap();
    let state = Arc::clone(&n.state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = uni_aggregator::api::transport::spawn(listener, build_router(state));
    let addr = server.local_addr;
    // A parked wait, and a client which never finishes its request body.
    let parked = send(addr, &v2_body(0x81, json!({"waitMs": 15000}))).await;
    let mut slow = TcpStream::connect(addr).await.unwrap();
    slow.write_all(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n{")
        .await
        .unwrap();
    until(|| reg.reserved() == 1).await;
    // Grace 0 with the drain flag not set: the parked wait cannot finish by itself within the
    // grace, so the connections are cut and joined for real.
    let t0 = std::time::Instant::now();
    let cut = server.shutdown(Duration::from_millis(300)).await;
    assert!(cut >= 1, "cut {cut}");
    assert!(t0.elapsed() < Duration::from_secs(3));
    until(|| reg.reserved() == 0).await;
    assert_eq!(reg.gate().in_use(), 0);
    drop((parked, slow));
}

#[tokio::test]
async fn a_pipelined_disconnect_cancels_the_buffered_request_and_its_queue_entry() {
    let n = net().await;
    let reg = Arc::clone(n.state.longpoll());
    n.state.submit_request(request(0x91)).await.unwrap();
    let (addr, stop, server) = serve(Arc::clone(&n.state)).await;
    // Two requests in one write: the second is buffered in hyper while the first one parks, so
    // hyper itself would never notice the client going away.
    let mut s = TcpStream::connect(addr).await.unwrap();
    let one = v2_body(0x91, json!({"waitMs": 15000}));
    let two = batch_body(&[0x91], json!({"waitMs": 15000}));
    let mut wire = String::new();
    for b in [&one, &two] {
        wire.push_str(&format!(
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{b}",
            b.len()
        ));
    }
    s.write_all(wire.as_bytes()).await.unwrap();
    until(|| reg.reserved() == 1).await;
    drop(s);
    until(|| reg.reserved() == 0).await;
    assert_eq!(reg.gate().in_use(), 0);
    assert_eq!(reg.resume_queued(), 0);
    assert_eq!(reg.request_count("get_inclusion_proof.v2", "cancelled"), 1);
    let _ = stop.send(());
    server.await.unwrap();
}

#[tokio::test]
async fn a_slow_body_is_cut_and_its_budget_unit_returned() {
    let n = net().await;
    let reg = Arc::clone(n.state.longpoll());
    reg.set_body_timeout(Duration::from_millis(300));
    let (addr, stop, server) = serve(Arc::clone(&n.state)).await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 500\r\n\r\n{\"jsonrpc\"")
        .await
        .unwrap();
    // admitted (and holding its unit) before the body is read
    until(|| reg.gate().in_use() == 1).await;
    let (status, head, body) = read_response(s).await;
    assert_eq!(status, 408, "{body}");
    assert!(head.to_lowercase().contains("cache-control: no-store"));
    assert_eq!(
        reg.gate().in_use(),
        0,
        "the slow body held its unit only until the body deadline"
    );
    let _ = stop.send(());
    server.await.unwrap();
}

#[tokio::test]
async fn a_slow_reader_cannot_hold_the_budget_past_the_write_deadline() {
    let n = net().await;
    let reg = Arc::clone(n.state.longpoll());
    reg.set_budget(Duration::from_millis(1500));
    // a large answer: many included ids in one batch so the response exceeds the socket buffers
    let (addr, stop, server) = serve(Arc::clone(&n.state)).await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    // 256 batches of the one included id would not be bigger; use a big error body instead: an
    // oversized-but-valid request is answered with a small body, so shrink the buffers.
    socket2::SockRef::from(&s)
        .set_recv_buffer_size(1024)
        .unwrap();
    let big = json!({"jsonrpc":"2.0","id":1,"method":"get_block_height","params":{}}).to_string();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{big}",
        big.len()
    );
    // pipeline many requests and never read: the responses back up in the kernel buffers
    let mut all = String::new();
    for _ in 0..4000 {
        all.push_str(&req);
    }
    let _ = tokio::time::timeout(Duration::from_millis(500), s.write_all(all.as_bytes())).await;
    // a unit is held by the response that cannot be written; it is released by the deadline
    let t0 = std::time::Instant::now();
    until(|| reg.gate().in_use() >= 1).await;
    until(|| reg.gate().in_use() == 0).await;
    assert!(t0.elapsed() < Duration::from_secs(10));
    drop(s);
    let _ = stop.send(());
    server.await.unwrap();
}

/// No-wait batch busy keeps its legacy HTTP 200; the overload 503 is for the global budget and
/// for wait-bearing requests only.
#[tokio::test]
async fn legacy_batch_busy_stays_200_and_a_wait_bearing_one_is_503() {
    let n = net().await;
    let reg = Arc::clone(n.state.longpoll());
    let (addr, stop, server) = serve(Arc::clone(&n.state)).await;
    let held: Vec<_> = (0..n.state.batch_pool().limit())
        .map(|_| n.state.batch_pool().try_acquire(0).unwrap())
        .collect();
    let (st, head, body) = read_response(send(addr, &batch_body(&[0x01], json!({}))).await).await;
    assert_eq!(st, 200, "{body}");
    assert!(!head.to_lowercase().contains("\r\nretry-after:"), "{head}");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["error"]["code"], json!(-32006));
    assert!(v["error"]["data"].get("waitedMs").is_none());
    let (st, head, body) =
        read_response(send(addr, &batch_body(&[0x01], json!({"waitMs": 1000}))).await).await;
    assert_eq!(st, 503, "{body}");
    assert!(head.to_lowercase().contains("retry-after: 1"));
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["error"]["code"], json!(-32006));
    assert_eq!(v["error"]["data"]["waitedMs"], json!(0));
    // and the global budget: headers on every error path
    drop(held);
    let h: Vec<_> = (0..reg.gate().limit())
        .map(|_| reg.gate().acquire_handle().unwrap())
        .collect();
    let (st, head, _) = read_response(send(addr, &v2_body(0x01, json!({}))).await).await;
    assert_eq!(st, 503);
    let head = head.to_lowercase();
    for want in [
        "retry-after: 1",
        "cache-control: no-store",
        "access-control-allow-origin: *",
        "content-length:",
    ] {
        assert!(head.contains(want), "{want} in {head}");
    }
    drop(h);
    let _ = stop.send(());
    server.await.unwrap();
}
