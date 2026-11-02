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
    rm_stop: Arc<tokio::sync::Notify>,
    rm: Option<tokio::task::JoinHandle<()>>,
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
    let rm_stop = rm.shutdown_notify();
    let rm = tokio::spawn(rm.run());
    state.submit_request(request(0x01)).await.unwrap();
    bft.permits.add_permits(1);
    until(|| state.longpoll().notify_count() >= 1).await;
    Net {
        state,
        bft,
        rm_stop,
        rm: Some(rm),
    }
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

fn tuned_listener(rcv: usize, snd: usize) -> tokio::net::TcpListener {
    use socket2::{Domain, Socket, Type};
    let sock = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    sock.set_recv_buffer_size(rcv).unwrap();
    sock.set_send_buffer_size(snd).unwrap();
    sock.bind(
        &"127.0.0.1:0"
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into(),
    )
    .unwrap();
    sock.listen(128).unwrap();
    sock.set_nonblocking(true).unwrap();
    tokio::net::TcpListener::from_std(sock.into()).unwrap()
}

async fn serve(
    state: Arc<AggregatorState>,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    serve_on(listener, state).await
}

async fn serve_on(
    listener: tokio::net::TcpListener,
    state: Arc<AggregatorState>,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let server = uni_aggregator::api::transport::spawn(listener, state);
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
    let server = uni_aggregator::api::transport::spawn(listener, state);
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
    // Pipelined small replies to a reader that never reads: with a small send buffer on the
    // server and a small receive window on the client they back up in the kernel on any OS.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = uni_aggregator::api::transport::spawn_with(
        listener,
        Arc::clone(&n.state),
        uni_aggregator::api::transport::TransportConfig {
            send_buffer: Some(4096),
            ..Default::default()
        },
    );
    let addr = server.local_addr;
    let (stop, rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let _ = rx.await;
        server.shutdown(Duration::from_secs(5)).await;
    });
    let mut s = client_socket(addr, 1024).connect(addr).await.unwrap();
    let big = json!({"jsonrpc":"2.0","id":1,"method":"get_block_height","params":{}}).to_string();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{big}",
        big.len()
    );
    // pipeline many requests and never read: the responses back up in the kernel buffers
    let mut all = String::new();
    for _ in 0..20_000 {
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

// ─── response write deadline, pipelined close, transport bounds, shutdown failure paths ────────

fn fd_count() -> usize {
    std::fs::read_dir(if cfg!(target_os = "linux") {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    })
    .map(|d| d.count())
    .unwrap_or(0)
}

fn request16(i: u16) -> ValidatedRequest {
    let mut r = request(0);
    let mut sid = [0u8; 32];
    sid[..2].copy_from_slice(&i.to_be_bytes());
    sid[2] = 0xee;
    r.state_id = sid.to_vec();
    r.state_id_hex = hex::encode(sid);
    r
}

/// Certify many states with 2-byte ids: a deeper tree, so larger proofs.
async fn certify16(n: &Net, count: u16) {
    for i in 0..count {
        n.state.submit_request(request16(i)).await.unwrap();
    }
    n.bft.permits.add_permits(64);
    for i in 0..count {
        let id = hex::decode(request16(i).state_id_hex).unwrap();
        until(|| n.state.proof_status_hint(&id) == "included").await;
    }
}

fn batch_body16(count: u16) -> String {
    let ids: Vec<String> = (0..count).map(|i| request16(i).state_id_hex).collect();
    json!({"jsonrpc":"2.0","id":2,"method":"get_inclusion_proofs.v1","params":{"stateIds": ids}})
        .to_string()
}

/// Certify `seeds` (many at once) so a batch response can be large.
async fn certify(n: &Net, seeds: &[u8]) {
    for &s in seeds {
        n.state.submit_request(request(s)).await.unwrap();
    }
    n.bft.permits.add_permits(32);
    for &s in seeds {
        let id = [s; 32];
        until(|| n.state.proof_status_hint(&id) == "included").await;
    }
}

fn client_socket(addr: std::net::SocketAddr, rcvbuf: usize) -> tokio::net::TcpSocket {
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.set_recv_buffer_size(rcvbuf as u32).unwrap();
    let _ = addr;
    sock
}

#[tokio::test]
async fn a_large_response_to_a_slow_reader_is_cut_at_its_write_deadline() {
    let n = net().await;
    let reg = Arc::clone(n.state.longpoll());
    certify16(&n, 600).await;
    let (_, probe) = dispatch(Arc::clone(&n.state), batch_body16(256).as_bytes()).await;
    // one body chunk larger than hyper's 417,792-byte write-buffer threshold
    assert!(
        probe.len() > 417_792,
        "the answer must exceed hyper's write buffer: {} bytes: {}",
        probe.len(),
        &probe[..probe.len().min(200)]
    );
    reg.set_budget(Duration::from_millis(1500));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = uni_aggregator::api::transport::spawn_with(
        listener,
        Arc::clone(&n.state),
        uni_aggregator::api::transport::TransportConfig {
            send_buffer: Some(4096),
            ..Default::default()
        },
    );
    let addr = server.local_addr;
    let (stop, rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let _ = rx.await;
        server.shutdown(Duration::from_secs(5)).await;
    });
    // A reader which never reads, with a tiny receive window and a 4 KiB send buffer: the answer
    // (one body chunk above hyper's write-buffer threshold) blocks in socket backpressure before
    // the body is ever dropped. The write deadline was armed when the response was built.
    let mut s = client_socket(addr, 1024).connect(addr).await.unwrap();
    let body = batch_body16(256);
    let req = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let t0 = std::time::Instant::now();
    until(|| reg.gate().in_use() == 1).await;
    until(|| reg.gate().in_use() == 0).await;
    let held = t0.elapsed();
    assert!(
        held >= Duration::from_millis(800) && held < Duration::from_secs(6),
        "the unit is held through the blocked write and released at the deadline: {held:?}"
    );
    // The connection was closed by the server: reading ends before the whole answer arrived.
    let mut total = 0usize;
    let mut buf = vec![0u8; 65536];
    while let Ok(Ok(k)) = tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf)).await {
        if k == 0 {
            break;
        }
        total += k;
    }
    assert!(total < probe.len(), "{total} of {} bytes", probe.len());
    let _ = stop.send(());
    server.await.unwrap();
}

#[tokio::test]
async fn pipelined_data_beyond_a_read_buffer_does_not_hide_a_fin_or_an_rst() {
    for rst in [false, true] {
        let n = net().await;
        let reg = Arc::clone(n.state.longpoll());
        n.state.submit_request(request(0xa1)).await.unwrap();
        // The server's receive buffer (inherited by accepted sockets) holds everything the client
        // sends, so the FIN really reaches the server behind bytes it has not read: TCP delivers
        // a FIN only after the data before it, and a full window would keep it on the client.
        let (addr, stop, server) =
            serve_on(tuned_listener(4 << 20, 1 << 16), Arc::clone(&n.state)).await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        let one = v2_body(0xa1, json!({"waitMs": 15000}));
        let one = format!(
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{one}",
            one.len()
        );
        s.write_all(one.as_bytes()).await.unwrap();
        until(|| reg.reserved() == 1).await;
        // Far more pipelined requests than hyper buffers (about 400 KiB) or the socket holds.
        // Hyper reads one buffer ahead while a request is in flight; the rest of the pipelined
        // data stays in the kernel's receive queue, in front of the FIN. (Linux caps SO_RCVBUF at
        // rmem_max, so the total is smaller there than on macOS: all of it must be delivered for
        // the FIN behind it to reach the server.)
        let count = if cfg!(target_os = "linux") {
            700
        } else {
            4_000
        };
        let more = (0..count).map(|_| one.as_str()).collect::<String>();
        assert!(more.len() > 100_000, "{}", more.len());
        tokio::time::timeout(Duration::from_secs(5), s.write_all(more.as_bytes()))
            .await
            .expect("the data fits the server's receive buffer")
            .unwrap();
        if rst {
            socket2::SockRef::from(&s)
                .set_linger(Some(Duration::ZERO))
                .unwrap();
            drop(s);
        } else {
            // FIN behind unread bytes; the socket stays open
            socket2::SockRef::from(&s)
                .shutdown(std::net::Shutdown::Write)
                .unwrap();
        }
        until(|| reg.reserved() == 0).await;
        assert_eq!(reg.gate().in_use(), 0, "rst={rst}");
        let _ = stop.send(());
        server.await.unwrap();
    }
}

#[tokio::test]
async fn transport_returns_descriptors_keeps_alive_and_bounds_connections() {
    let n = net().await;
    let reg = Arc::clone(n.state.longpoll());
    let base = fd_count();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = uni_aggregator::api::transport::spawn_with(
        listener,
        Arc::clone(&n.state),
        uni_aggregator::api::transport::TransportConfig {
            header_read_timeout: Duration::from_millis(1500),
            max_connections: 3,
            send_buffer: None,
        },
    );
    let addr = server.local_addr;
    let height = r#"{"jsonrpc":"2.0","id":9,"method":"get_block_height","params":{}}"#;
    let post = |body: &str| {
        format!(
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    };

    // sequential keep-alive on one connection
    let mut s = TcpStream::connect(addr).await.unwrap();
    for _ in 0..3 {
        s.write_all(post(height).as_bytes()).await.unwrap();
        let (st, body) = read_one(&mut s).await;
        assert_eq!(st, 200, "{body}");
    }
    // early rejection (global budget exhausted: refused before its body is read), then reuse
    let h: Vec<_> = (0..reg.gate().limit())
        .map(|_| reg.gate().acquire_handle().unwrap())
        .collect();
    s.write_all(post(height).as_bytes()).await.unwrap();
    assert_eq!(read_one(&mut s).await.0, 503);
    drop(h);
    s.write_all(post(height).as_bytes()).await.unwrap();
    assert_eq!(
        read_one(&mut s).await.0,
        200,
        "the connection is reusable after an early rejection"
    );

    // the connection bound: with 3 slots taken (s and two idle ones), a fourth waits in the backlog
    let idle = TcpStream::connect(addr).await.unwrap();
    let idle2 = TcpStream::connect(addr).await.unwrap();
    until(|| true).await;
    let mut fourth = TcpStream::connect(addr).await.unwrap();
    fourth.write_all(post(height).as_bytes()).await.unwrap();
    let waited = tokio::time::timeout(Duration::from_millis(400), read_one(&mut fourth)).await;
    assert!(waited.is_err(), "not served while the bound is reached");
    drop(idle);
    let (st, _) = tokio::time::timeout(Duration::from_secs(5), read_one(&mut fourth))
        .await
        .expect("served once a slot is free");
    assert_eq!(st, 200);
    drop((idle2, s, fourth));

    // slow headers are cut by the header timeout
    let mut slow = TcpStream::connect(addr).await.unwrap();
    slow.write_all(b"POST / HTTP/1.1\r\nHost:").await.unwrap();
    let mut buf = [0u8; 64];
    let r = tokio::time::timeout(Duration::from_secs(5), slow.read(&mut buf)).await;
    assert!(
        matches!(r, Ok(Ok(_)) | Ok(Err(_))),
        "closed or answered, not hanging: {r:?}"
    );
    drop(slow);

    // descriptors come back on close, and the listener's on shutdown
    server.shutdown(Duration::from_secs(2)).await;
    let mut back = false;
    for _ in 0..100 {
        if fd_count() <= base + 2 {
            back = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(back, "descriptors {} vs baseline {base}", fd_count());
}

async fn read_one(s: &mut TcpStream) -> (u16, String) {
    let mut buf = Vec::new();
    loop {
        let mut chunk = [0u8; 4096];
        let k = s.read(&mut chunk).await.unwrap();
        if k == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..k]);
        let text = String::from_utf8_lossy(&buf).to_string();
        if let Some(i) = text.find("\r\n\r\n") {
            let len: usize = text[..i]
                .to_lowercase()
                .lines()
                .find_map(|l| {
                    l.strip_prefix("content-length:")
                        .map(|v| v.trim().parse().unwrap())
                })
                .unwrap_or(0);
            if text.len() >= i + 4 + len {
                let status = text.split_whitespace().nth(1).unwrap().parse().unwrap();
                return (status, text[i + 4..].to_string());
            }
        }
    }
    panic!("connection closed before a full response");
}

#[tokio::test]
async fn shutdown_failure_paths_do_not_claim_success_or_close_storage_under_work() {
    use uni_aggregator::lifecycle::{
        drain_http, stop_round_manager, ShutdownError, ShutdownLimits,
    };
    let mut n = net().await;
    let limits = ShutdownLimits {
        grace: Duration::from_millis(200),
        workers: Duration::from_millis(300),
        round_manager: Duration::from_millis(300),
    };
    // Work which has not acknowledged completion: a batch slot is still held when the grace
    // has passed. The sequence fails and the round manager is left running (storage stays up).
    let held = n.state.batch_pool().try_acquire(0).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = uni_aggregator::api::transport::spawn(listener, Arc::clone(&n.state));
    let err = drain_http(server, &n.state, limits).await.unwrap_err();
    assert!(
        matches!(err, ShutdownError::WorkersBusy { batches: 1, .. }),
        "{err:?}"
    );
    assert!(
        !n.rm.as_ref().unwrap().is_finished(),
        "the round manager is not stopped under busy workers"
    );
    // ... and completes once the work acknowledges.
    drop(held);
    assert!(
        n.state
            .wait_workers_idle(tokio::time::Instant::now() + Duration::from_secs(1))
            .await
    );

    // A round manager which does not stop: a timeout is an error, the task stays with the caller.
    let mut stuck = tokio::spawn(std::future::pending::<()>());
    let err = stop_round_manager(&n.rm_stop, &mut stuck, Duration::from_millis(200))
        .await
        .unwrap_err();
    assert_eq!(err, ShutdownError::RoundManagerStuck);
    assert!(!stuck.is_finished());
    stuck.abort();
    // The real one stops and persists.
    let mut rm = n.rm.take().unwrap();
    stop_round_manager(&n.rm_stop, &mut rm, Duration::from_secs(5))
        .await
        .unwrap();
}
