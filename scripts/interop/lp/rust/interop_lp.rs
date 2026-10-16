//! Long-poll interop driver, Rust SDK client (arch-long-poll.md T3/T8/T10/T11, brief-lp-interop.md).
//!
//! Copied by `scripts/interop/lp/run.sh` into a state-transition-sdk-rust checkout as
//! `tests/interop_lp.rs` and run with
//! `cargo test --features http --test interop_lp -- --ignored --nocapture`.
//! Prints one JSON line per check:
//!   {"client":"rust","server":"s2lp","scenario":"L2","name":"...","status":"PASS|FAIL|N-A","evidence":"..."}
//! and `L1` raw-response lines {"scenario":"L1","kind":..,"http":..,"body":<normalized>} that
//! `report.py` compares between two servers.
//!
//! Environment: IX_URL, IX_TRUSTBASE, IX_SERVER (s2lp|s2base|s1lp|s2cap0), IX_SCEN (comma list of
//! L1,L2,L3,L4,L5,L6,L7; default depends on the server), IX_ROUND_MS (default 1000), IX_CASES
//! (envelope_cases.json), L7: IX_N (states per variant, default 200), IX_RATE (open-loop arrivals/s, default 10).
#![cfg(feature = "http")]
#![allow(clippy::result_large_err)]

use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use unicity_token::api::bft::RootTrustBase;
use unicity_token::api::{InclusionProofResponse, StateId};
use unicity_token::client::{
    certification_data_for, get_latest_negotiating_wait, AggregatorClient, BatchAggregatorClient,
    BatchFailure, BatchRequest, HttpAggregatorClient, HttpError, RequestOptions, StateRoot,
    WaitOptions, WaitRequest,
};
use unicity_token::crypto::signer::{Secp256k1Signer, Signer};
use unicity_token::predicate::builtin::SignaturePredicate;
use unicity_token::predicate::EncodedPredicate;
use unicity_token::transaction::ids::{TokenSalt, TokenType};
use unicity_token::transaction::{
    CertifiedMintTransaction, MintTransaction, Minter, Token, Transaction,
};

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_default()
}

struct Ctx {
    url: String,
    server: String,
    trust_base: RootTrustBase,
    round_ms: u64,
}

impl Ctx {
    fn emit(&self, scn: &str, name: &str, status: &str, evidence: &str) {
        println!(
            "{}",
            json!({"client":"rust","server":self.server,"scenario":scn,"name":name,"status":status,"evidence":evidence})
        );
    }
    fn check(&self, scn: &str, name: &str, ok: bool, evidence: String) {
        self.emit(scn, name, if ok { "PASS" } else { "FAIL" }, &evidence);
    }
    fn http(&self, interval_ms: u64) -> HttpAggregatorClient {
        HttpAggregatorClient::new_insecure_http(self.url.clone())
            .with_polling(Duration::from_millis(interval_ms), 600)
            .with_unknown_grace(5)
    }
}

struct Minted {
    state_id: StateId,
    tx: MintTransaction,
    data: unicity_token::api::CertificationData,
}

fn new_mint(network: unicity_token::api::NetworkId) -> Minted {
    let owner = Secp256k1Signer::generate().unwrap();
    let tx = MintTransaction::create(
        network,
        EncodedPredicate::from_predicate(&SignaturePredicate::new(owner.public_key())),
        TokenType::random().unwrap(),
        TokenSalt::random().unwrap(),
        None,
        None,
        None,
    )
    .unwrap();
    let signer = Minter::signer(tx.token_id()).unwrap();
    let data = certification_data_for(&tx, &signer);
    let state_id = StateId::derive(tx.lock_script(), tx.source_state_hash());
    Minted { state_id, tx, data }
}

fn verify(ctx: &Ctx, m: &Minted, p: &unicity_token::api::InclusionProof) -> Result<(), String> {
    p.verify_for(&m.state_id, p.reference_time, &ctx.trust_base)
        .map_err(|e| format!("proof verify: {e}"))?;
    let token = Token::new(CertifiedMintTransaction::new(m.tx.clone(), p.clone()), Vec::new());
    token
        .verify(&ctx.trust_base)
        .map_err(|e| format!("token verify: {e}"))
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

fn rpc_detail(f: &BatchFailure) -> String {
    match f {
        BatchFailure::Rpc {
            code,
            detail,
            indexes,
            ..
        } => format!("code={code} detail={} indexes={indexes:?}", detail.clone().unwrap_or_default()),
        other => format!("{other}"),
    }
}

fn post_raw(url: &str, body: &str) -> Result<(u16, String), String> {
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(30)).build();
    let resp = match agent.post(url).set("Content-Type", "application/json").send_string(body) {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => return Err(e.to_string()),
    };
    let status = resp.status();
    Ok((status, resp.into_string().map_err(|e| e.to_string())?))
}

/// Replace every run of 64+ hex digits by `<hex>` so that instance-specific proof bytes do not
/// hide the structure; everything else (member order, whitespace, codes, text) is kept.
fn normalize(body: &str) -> String {
    let b = body.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        let mut j = i;
        while j < b.len() && (b[j].is_ascii_digit() || (b'a'..=b'f').contains(&b[j]) || (b'A'..=b'F').contains(&b[j])) {
            j += 1;
        }
        if j - i >= 64 {
            out.push_str("<hex>");
            i = j;
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    out
}

/// A round number "now": the root round of the certificate any lookup carries.
fn current_round(ctx: &Ctx) -> Option<u64> {
    let agg = ctx.http(1000);
    let probe = new_mint(ctx.trust_base.network_id);
    match agg.lookup_inclusion_proof(&probe.state_id) {
        Ok((InclusionProofResponse::NotCertified { unicity_certificate, .. }, _)) => {
            Some(unicity_certificate.unicity_seal.root_chain_round_number)
        }
        _ => None,
    }
}

fn scrape(url: &str) -> Vec<(String, f64)> {
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(5)).build();
    let Ok(r) = agent.get(&format!("{url}/metrics")).call() else { return vec![] };
    let Ok(t) = r.into_string() else { return vec![] };
    t.lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let (k, v) = l.rsplit_once(' ')?;
            Some((k.to_string(), v.parse().ok()?))
        })
        .collect()
}

fn metric_sum(m: &[(String, f64)], prefix: &str) -> f64 {
    m.iter().filter(|(k, _)| k.starts_with(prefix)).map(|(_, v)| *v).sum()
}

// ------------------------------------------------------------------ L1

fn l1(ctx: &Ctx) {
    let url = ctx.url.clone();
    let emit = |kind: &str, status: u16, body: &str| {
        println!(
            "{}",
            json!({"client":"rust","server":ctx.server,"scenario":"L1","kind":kind,"http":status,"body":normalize(body)})
        );
    };
    let call = |kind: &str, body: String| match post_raw(&url, &body) {
        Ok((s, t)) => emit(kind, s, &t),
        Err(e) => emit(kind, 0, &format!("transport: {e}")),
    };
    let rpc = |id: &str, method: &str, params: &str| {
        format!(r#"{{"jsonrpc":"2.0","id":"{id}","method":"{method}","params":{params}}}"#)
    };
    // state-independent requests: byte-comparable
    let zero = "00".repeat(32);
    call("v2_bad_state_id_short", rpc("k1", "get_inclusion_proof.v2", r#"{"stateId":"00ff"}"#));
    call("v2_missing_params", rpc("k2", "get_inclusion_proof.v2", "{}"));
    call("v2_bad_hex", rpc("k3", "get_inclusion_proof.v2", r#"{"stateId":"zz"}"#));
    call("unknown_method", rpc("k4", "no_such_method", "{}"));
    call("garbage_body", "{not json".to_string());
    call(
        "batch_unknown_state",
        rpc("k5", "get_inclusion_proofs.v1", &format!(r#"{{"stateIds":["{zero}"],"stateRoot":"latest"}}"#)),
    );
    call(
        "v2_unknown_status",
        rpc("k6", "get_inclusion_proof.v2", &format!(r#"{{"stateId":"{zero}","includeStatus":true}}"#)),
    );
    call(
        "v2_unknown_bare",
        rpc("k7", "get_inclusion_proof.v2", &format!(r#"{{"stateId":"{zero}"}}"#)),
    );
    // the matrix envelope cases
    if let Ok(text) = std::fs::read_to_string(env("IX_CASES")) {
        let cases: Value = serde_json::from_str(&text).unwrap();
        for c in cases["cases"].as_array().unwrap() {
            let name = c["name"].as_str().unwrap();
            let method = c["method"].as_str().unwrap_or("get_inclusion_proofs.v1");
            let params = match c["gen"].as_str() {
                Some("ids257") => {
                    let ids: Vec<String> = (0..257u32)
                        .map(|i| format!("{}{}", hex::encode(i.to_be_bytes()), "00".repeat(28)))
                        .collect();
                    json!({"stateIds": ids, "stateRoot": "latest"}).to_string()
                }
                Some("oversize") => {
                    json!({"stateIds": [zero], "stateRoot": "latest", "pad": "a".repeat(70_000)}).to_string()
                }
                _ => c["params"].to_string().replace("{ID}", &zero),
            };
            call(&format!("env_{name}"), rpc("e", method, &params));
        }
    }
    // state-dependent shapes (an included, a pending and an unknown id)
    let agg = ctx.http(200);
    let m = new_mint(ctx.trust_base.network_id);
    agg.submit_certification_request(&m.data).unwrap();
    let id = hex::encode(m.state_id.bytes());
    call("batch_pending", rpc("p1", "get_inclusion_proofs.v1", &format!(r#"{{"stateIds":["{id}"],"stateRoot":"latest"}}"#)));
    call("v2_pending_status", rpc("p2", "get_inclusion_proof.v2", &format!(r#"{{"stateId":"{id}","includeStatus":true}}"#)));
    let proof = agg.wait_for_inclusion_proof(&m.state_id, &WaitOptions::new(Duration::from_secs(60)).with_long_poll(false).with_poll_interval(Duration::from_millis(200)));
    if proof.is_err() {
        ctx.emit("L1", "included state shapes", "FAIL", &format!("{proof:?}"));
        return;
    }
    call("v2_included_bare", rpc("i1", "get_inclusion_proof.v2", &format!(r#"{{"stateId":"{id}"}}"#)));
    call("v2_included_status", rpc("i2", "get_inclusion_proof.v2", &format!(r#"{{"stateId":"{id}","includeStatus":true}}"#)));
    call("batch_included", rpc("i3", "get_inclusion_proofs.v1", &format!(r#"{{"stateIds":["{id}"],"stateRoot":"latest"}}"#)));
    call("batch_mixed_unknown", rpc("i4", "get_inclusion_proofs.v1", &format!(r#"{{"stateIds":["{id}","{zero}"],"stateRoot":"latest"}}"#)));
}

// ------------------------------------------------------------------ L2

fn l2(ctx: &Ctx) {
    let agg = ctx.http(1000);
    let n = 5;
    let mut worst_requests = 0u32;
    let mut times = Vec::new();
    let mut lp_requests = 0u32;
    for _ in 0..n {
        let m = new_mint(ctx.trust_base.network_id);
        agg.submit_certification_request(&m.data).unwrap();
        let t0 = Instant::now();
        let out = agg.wait_for_inclusion_proof_with_stats(&m.state_id, &WaitOptions::new(Duration::from_secs(60)));
        let took = t0.elapsed();
        match out.result {
            Ok(p) => {
                if let Err(e) = verify(ctx, &m, &p) {
                    ctx.emit("L2", "waited read returns included", "FAIL", &e);
                    return;
                }
            }
            Err(e) => {
                ctx.emit("L2", "waited read returns included", "FAIL", &format!("{e}"));
                return;
            }
        }
        worst_requests = worst_requests.max(out.stats.requests);
        lp_requests += out.stats.long_poll_requests;
        times.push(ms(took));
    }
    // "within about one round after publication": the submit-to-proof time must stay within the
    // admission wait (a round or two plus the root round); a poll interval of 1 s is not added.
    let bound = ctx.round_ms * 4 + 2000;
    let ok = worst_requests == 1 && lp_requests as usize == n && times.iter().all(|t| *t <= bound);
    ctx.check(
        "L2",
        "waited read returns included in one proof request per state",
        ok,
        format!("states={n} max_proof_requests={worst_requests} long_poll_requests={lp_requests} submit_to_proof_ms={times:?} bound_ms={bound} (fully verified)"),
    );
}

// ------------------------------------------------------------------ L3

fn l3(ctx: &Ctx) {
    let agg = ctx.http(200);
    // (a) one-shot waited lookup with a short wait on a just-submitted (pending) state
    let mut seen = None;
    for _ in 0..6 {
        let m = new_mint(ctx.trust_base.network_id);
        agg.submit_certification_request(&m.data).unwrap();
        let t0 = Instant::now();
        let got = agg.lookup_inclusion_proof_with_wait(&m.state_id, &WaitRequest::new(300).with_margin_ms(0), Duration::from_secs(5));
        let took = ms(t0.elapsed());
        if let Ok(w) = &got {
            if matches!(w.response, InclusionProofResponse::NotCertified { .. }) {
                seen = Some((w.waited_ms, w.status, took));
                break;
            }
        }
        // included within the wait: let the round settle and try a new state
        std::thread::sleep(Duration::from_millis(ctx.round_ms));
    }
    match seen {
        Some((waited, status, took)) => {
            let w = waited.unwrap_or(0);
            ctx.check(
                "L3",
                "short waitMs on a pending state: normal pending, waitedMs about the wait",
                (250..=400).contains(&w) && took >= 280 && took < 1500,
                format!("waitMs=300 waitedMs={waited:?} status={status:?} call_ms={took}"),
            );
        }
        None => ctx.emit("L3", "short waitMs on a pending state", "FAIL", "no pending answer in 6 tries"),
    }
    // (b) the total deadline is respected by the wait helper
    let m = new_mint(ctx.trust_base.network_id);
    agg.submit_certification_request(&m.data).unwrap();
    let t0 = Instant::now();
    let total = Duration::from_millis(ctx.round_ms / 2);
    let out = agg.wait_for_inclusion_proof_with_stats(&m.state_id, &WaitOptions::new(total).with_margin(Duration::from_millis(50)));
    let took = ms(t0.elapsed());
    let res = match &out.result {
        Err(HttpError::Timeout) => "Timeout".to_string(),
        Ok(_) => "included-before-deadline".to_string(),
        Err(e) => format!("{e}"),
    };
    ctx.check(
        "L3",
        "total deadline respected by the wait helper",
        (res == "Timeout" && took >= ms(total) - 20 && took < ms(total) + 700) || res == "included-before-deadline",
        format!("total_ms={} result={res} elapsed_ms={took} requests={} long_poll_requests={}", ms(total), out.stats.requests, out.stats.long_poll_requests),
    );
}

// ------------------------------------------------------------------ L4

fn l4(ctx: &Ctx) {
    let agg = ctx.http(200);
    let ms3: Vec<Minted> = (0..3).map(|_| new_mint(ctx.trust_base.network_id)).collect();
    for m in &ms3 {
        agg.submit_certification_request(&m.data).unwrap();
    }
    let ids: Vec<StateId> = ms3.iter().map(|m| m.state_id.clone()).collect();
    let t0 = Instant::now();
    let r = agg.get_inclusion_proofs_with_wait(
        &BatchRequest { state_ids: &ids, state_root: StateRoot::Latest },
        &RequestOptions { timeout_ms: 20_000 },
        &WaitRequest::new(10_000).with_margin_ms(2_000),
    );
    let took = ms(t0.elapsed());
    match r {
        Ok(w) => {
            let mut bad = String::new();
            for (m, p) in ms3.iter().zip(&w.batch.proofs) {
                if let Err(e) = p.proof.verify_for(&m.state_id, p.proof.reference_time, &ctx.trust_base) {
                    bad = format!("verify: {e}");
                }
            }
            ctx.check(
                "L4",
                "wait-all batch over pending ids succeeds with result.waitedMs",
                bad.is_empty() && w.waited_ms.is_some() && w.batch.proofs.len() == 3,
                format!("proofs={} waitedMs={:?} sent_wait_ms={:?} call_ms={took} {bad}", w.batch.proofs.len(), w.waited_ms, w.sent_wait_ms),
            );
        }
        Err(e) => ctx.emit("L4", "wait-all batch over pending ids", "FAIL", &format!("{} waited={:?}", rpc_detail(&e.failure), e.waited_ms)),
    }
    // one unknown id among included ones ends at once, with the echo in the error
    let unknown = new_mint(ctx.trust_base.network_id).state_id;
    let mixed = vec![ids[0].clone(), unknown];
    let t0 = Instant::now();
    let r = agg.get_inclusion_proofs_with_wait(
        &BatchRequest { state_ids: &mixed, state_root: StateRoot::Latest },
        &RequestOptions { timeout_ms: 20_000 },
        &WaitRequest::new(10_000).with_margin_ms(2_000),
    );
    let took = ms(t0.elapsed());
    match r {
        Err(e) => ctx.check(
            "L4",
            "batch with an unknown id answers immediately with data.waitedMs",
            matches!(&e.failure, BatchFailure::Rpc { detail: Some(d), .. } if d == "state_unknown") && e.waited_ms.is_some() && took < 2000,
            format!("{} waitedMs={:?} call_ms={took}", rpc_detail(&e.failure), e.waited_ms),
        ),
        Ok(_) => ctx.emit("L4", "batch with an unknown id", "FAIL", "unexpected success"),
    }
}

// ------------------------------------------------------------------ L5

fn l5(ctx: &Ctx) {
    let agg = ctx.http(200);
    // (a) v2 wait helper falls back to paced polling
    let m = new_mint(ctx.trust_base.network_id);
    agg.submit_certification_request(&m.data).unwrap();
    let t0 = Instant::now();
    let out = agg.wait_for_inclusion_proof_with_stats(&m.state_id, &WaitOptions::new(Duration::from_secs(60)).with_poll_interval(Duration::from_millis(200)));
    let took = ms(t0.elapsed());
    let verified = match &out.result {
        Ok(p) => verify(ctx, &m, p).map_or_else(|e| e, |_| "verified".into()),
        Err(e) => format!("{e}"),
    };
    let paced = (out.stats.requests as u64) <= took / 160 + 2;
    ctx.check(
        "L5",
        "v2 wait falls back to paced polling (no echo)",
        verified == "verified" && paced,
        format!(
            "result={verified} elapsed_ms={took} proof_requests={} long_poll_requests={} wait_dropped_for_missing_echo={} pending={} (limit {} for 200 ms pacing)",
            out.stats.requests, out.stats.long_poll_requests, out.stats.wait_dropped_for_missing_echo, out.stats.pending, took / 160 + 2
        ),
    );
    // (b) the batch parser negotiation: one retry, counted
    let m = new_mint(ctx.trust_base.network_id);
    agg.submit_certification_request(&m.data).unwrap();
    let ids = vec![m.state_id.clone()];
    let t0 = Instant::now();
    let neg = get_latest_negotiating_wait(&agg, &ids, &RequestOptions { timeout_ms: 20_000 }, &WaitRequest::new(5_000).with_margin_ms(2_000), &|| ms(t0.elapsed()));
    let shape = match &neg.result {
        Ok(w) => format!("ok proofs={} waitedMs={:?}", w.batch.proofs.len(), w.waited_ms),
        Err(e) => format!("{} waitedMs={:?}", rpc_detail(&e.failure), e.waited_ms),
    };
    let echo = match &neg.result {
        Ok(w) => w.waited_ms,
        Err(e) => e.waited_ms,
    };
    let expect_retry = ctx.server == "s2base";
    ctx.check(
        "L5",
        if expect_retry { "strict batch parser: exactly one retry without waitMs" } else { "reservation-only batch parser accepts waitMs, no echo, no retry" },
        neg.retried_without_wait == expect_retry && neg.requests == if expect_retry { 2 } else { 1 } && echo.is_none(),
        format!("requests={} retried_without_wait={} {shape}", neg.requests, neg.retried_without_wait),
    );
}

// ------------------------------------------------------------------ L6

fn l6(ctx: &Ctx) {
    let agg = ctx.http(200);
    let m = new_mint(ctx.trust_base.network_id);
    agg.submit_certification_request(&m.data).unwrap();
    let t0 = Instant::now();
    let got = agg.lookup_inclusion_proof_with_wait(&m.state_id, &WaitRequest::new(5_000), Duration::from_secs(10));
    let took = ms(t0.elapsed());
    match got {
        Ok(w) => ctx.check(
            "L6",
            "cap 0: waitMs answered at once with waitedMs 0",
            w.waited_ms == Some(0) && took < 1500,
            format!("waitedMs={:?} status={:?} call_ms={took}", w.waited_ms, w.status),
        ),
        Err(e) => ctx.emit("L6", "cap 0 waited lookup", "FAIL", &format!("{e}")),
    }
    let t0 = Instant::now();
    let out = agg.wait_for_inclusion_proof_with_stats(&m.state_id, &WaitOptions::new(Duration::from_secs(60)).with_poll_interval(Duration::from_millis(200)));
    let took = ms(t0.elapsed());
    let verified = match &out.result {
        Ok(p) => verify(ctx, &m, p).map_or_else(|e| e, |_| "verified".into()),
        Err(e) => format!("{e}"),
    };
    let paced = (out.stats.requests as u64) <= took / 160 + 2;
    ctx.check(
        "L6",
        "cap 0: wait helper polls with pacing, no tight loop",
        verified == "verified" && paced && out.stats.immediate_rechecks == 0,
        format!("result={verified} elapsed_ms={took} proof_requests={} immediate_rechecks={} wait_dropped={}", out.stats.requests, out.stats.immediate_rechecks, out.stats.wait_dropped_for_missing_echo),
    );
    // batch at cap 0
    let m2 = new_mint(ctx.trust_base.network_id);
    agg.submit_certification_request(&m2.data).unwrap();
    let ids = vec![m2.state_id.clone()];
    let t0 = Instant::now();
    let r = agg.get_inclusion_proofs_with_wait(&BatchRequest { state_ids: &ids, state_root: StateRoot::Latest }, &RequestOptions { timeout_ms: 20_000 }, &WaitRequest::new(5_000));
    let took = ms(t0.elapsed());
    match r {
        Err(e) => ctx.check(
            "L6",
            "cap 0: batch pending answers at once with data.waitedMs 0",
            e.waited_ms == Some(0) && took < 1500,
            format!("{} waitedMs={:?} call_ms={took}", rpc_detail(&e.failure), e.waited_ms),
        ),
        Ok(w) => ctx.emit("L6", "cap 0 batch", "N-A", &format!("already included (waitedMs={:?}) before the read", w.waited_ms)),
    }
}

// ------------------------------------------------------------------ L7

fn pct(v: &mut [u64], p: f64) -> u64 {
    v.sort_unstable();
    if v.is_empty() {
        return 0;
    }
    v[(((v.len() - 1) as f64) * p).round() as usize]
}

fn l7_variant(ctx: &Ctx, label: &str, n: usize, rate: f64, opts: impl Fn() -> WaitOptions + Sync) {
    let before = scrape(&ctx.url);
    let rec: Mutex<Vec<(u64, u32, u64, bool)>> = Mutex::new(Vec::new());
    let stop = std::sync::atomic::AtomicBool::new(false);
    let peak: Mutex<(f64, f64, f64)> = Mutex::new((0.0, 0.0, 0.0)); // reservations, rss, heap
    let t_start = Instant::now();
    std::thread::scope(|s| {
        s.spawn(|| {
            while !stop.load(Ordering::SeqCst) {
                let m = scrape(&ctx.url);
                let r = metric_sum(&m, "aggregator_longpoll_reservations");
                let rss = metric_sum(&m, "process_resident_memory_bytes");
                let heap = metric_sum(&m, "go_memstats_heap_alloc_bytes");
                let mut p = peak.lock().unwrap();
                p.0 = p.0.max(r);
                p.1 = p.1.max(rss);
                p.2 = p.2.max(heap);
                drop(p);
                std::thread::sleep(Duration::from_millis(150));
            }
        });
        // Open loop: state i arrives at i / rate seconds, whatever the server's speed, so every
        // variant sees the identical arrival schedule. Failures are recorded, not dropped.
        let workers: Vec<_> = (0..n)
            .map(|i| {
                let (opts, rec) = (&opts, &rec);
                s.spawn(move || {
                    let due = t_start + Duration::from_micros((i as f64 / rate * 1e6) as u64);
                    if let Some(wait) = due.checked_duration_since(Instant::now()) {
                        std::thread::sleep(wait);
                    }
                    let agg = ctx.http(200);
                    let m = new_mint(ctx.trust_base.network_id);
                    let r0 = current_round(ctx);
                    let t0 = Instant::now();
                    let submitted = agg.submit_certification_request(&m.data).is_ok();
                    if !submitted {
                        rec.lock().unwrap().push((ms(t0.elapsed()), 0, 0, false));
                        return;
                    }
                    let out = agg.wait_for_inclusion_proof_with_stats(&m.state_id, &opts());
                    let took = ms(t0.elapsed());
                    let ok = match &out.result {
                        Ok(p) => verify(ctx, &m, p).is_ok(),
                        Err(_) => false,
                    };
                    let rounds = match (&out.result, r0) {
                        (Ok(p), Some(r0)) => p.unicity_certificate.unicity_seal.root_chain_round_number.saturating_sub(r0),
                        _ => 0,
                    };
                    rec.lock().unwrap().push((took, out.stats.requests, rounds, ok));
                })
            })
            .collect();
        for w in workers {
            let _ = w.join();
        }
        stop.store(true, Ordering::SeqCst);
    });
    let total_ms = ms(t_start.elapsed());
    let after = scrape(&ctx.url);
    let rec = rec.into_inner().unwrap();
    let verified = rec.iter().filter(|r| r.3).count();
    let requests: u64 = rec.iter().map(|r| u64::from(r.1)).sum();
    let failed = rec.len() - verified;
    // percentiles over the verified states only; failures are counted separately
    let mut lat: Vec<u64> = rec.iter().filter(|r| r.3).map(|r| r.0).collect();
    let mut rounds: Vec<u64> = rec.iter().filter(|r| r.3).map(|r| r.2).collect();
    let (pk_res, pk_rss, pk_heap) = *peak.lock().unwrap();
    let delta = |name: &str| metric_sum(&after, name) - metric_sum(&before, name);
    let p2r_sum = delta("aggregator_longpoll_publication_to_response_seconds_sum");
    let p2r_cnt = delta("aggregator_longpoll_publication_to_response_seconds_count");
    let base_rss = metric_sum(&before, "process_resident_memory_bytes");
    let base_heap = metric_sum(&before, "go_memstats_heap_alloc_bytes");
    println!(
        "{}",
        json!({"client":"rust","server":ctx.server,"scenario":"L7","variant":label,"states":n,"arrival_rate_per_s":rate,
               "verified":verified,"failed":failed,"total_ms":total_ms,
               "proof_requests":requests,"proof_requests_per_state": requests as f64 / n as f64,
               "latency_ms":{"p50":pct(&mut lat,0.5),"p90":pct(&mut lat,0.9),"p99":pct(&mut lat,0.99),"max":pct(&mut lat,1.0)},
               "root_rounds_admission_to_proof":{"p50":pct(&mut rounds,0.5),"p90":pct(&mut rounds,0.9),"max":pct(&mut rounds,1.0)},
               "server":{"peak_reservations":pk_res,"rss_baseline_bytes":base_rss,"rss_peak_bytes":pk_rss,
                         "heap_baseline_bytes":base_heap,"heap_peak_bytes":pk_heap,
                         "pub_to_response_mean_s": if p2r_cnt > 0.0 { p2r_sum / p2r_cnt } else { f64::NAN },
                         "pub_to_response_count":p2r_cnt,
                         "wakes":delta("aggregator_longpoll_wakes_total"),
                         "rechecks":delta("aggregator_longpoll_rechecks_total"),
                         "lp_requests":delta("aggregator_longpoll_requests_total")}})
    );
    ctx.check("L7", &format!("variant {label}: all states verified"), verified == n, format!("{verified}/{n} verified, {failed} failed, open-loop {rate}/s, {total_ms} ms"));
}

fn l7(ctx: &Ctx) {
    let n: usize = env("IX_N").parse().unwrap_or(200);
    let rate: f64 = env("IX_RATE").parse().unwrap_or(10.0);
    let total = Duration::from_secs(120);
    l7_variant(ctx, "poll-200ms", n, rate, || WaitOptions::new(total).with_long_poll(false).with_poll_interval(Duration::from_millis(200)));
    l7_variant(ctx, "poll-1s", n, rate, || WaitOptions::new(total).with_long_poll(false).with_poll_interval(Duration::from_millis(1000)));
    l7_variant(ctx, "long-poll", n, rate, || WaitOptions::new(total).with_poll_interval(Duration::from_millis(1000)));
}

#[test]
#[ignore = "needs a running aggregator (see scripts/interop/lp/run.sh)"]
fn interop_lp() {
    let ctx = Ctx {
        url: env("IX_URL"),
        server: env("IX_SERVER"),
        trust_base: RootTrustBase::from_json(&std::fs::read_to_string(env("IX_TRUSTBASE")).expect("read trust base")).expect("parse trust base"),
        round_ms: env("IX_ROUND_MS").parse().unwrap_or(1000),
    };
    let default = match ctx.server.as_str() {
        "s2lp" => "L1,L2,L3,L4",
        "s2base" => "L1,L5",
        "s1lp" => "L5",
        "s2cap0" => "L6",
        other => panic!("unknown IX_SERVER {other}"),
    };
    let scen = if env("IX_SCEN").is_empty() { default.to_string() } else { env("IX_SCEN") };
    for s in scen.split(',') {
        match s.trim() {
            "L1" => l1(&ctx),
            "L2" => l2(&ctx),
            "L3" => l3(&ctx),
            "L4" => l4(&ctx),
            "L5" => l5(&ctx),
            "L6" => l6(&ctx),
            "L7" => l7(&ctx),
            other => panic!("unknown scenario {other}"),
        }
    }
}
