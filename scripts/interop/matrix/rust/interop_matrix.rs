//! Interop matrix driver, Rust SDK client (C2).
//!
//! Copied by run.sh into a state-transition-sdk-rust checkout as tests/interop_matrix.rs and run
//! against one server with `cargo test --features http --test interop_matrix -- --ignored --nocapture`.
//! Prints one JSON line per scenario:
//!   {"client":"rust","scenario":"2","name":"...","status":"PASS|FAIL|N-A","evidence":"..."}
//!
//! Environment: IX_URL, IX_TRUSTBASE (RootTrustBase JSON), IX_PARTITION, IX_N (default 6),
//! IX_CASES (envelope_cases.json), IX_RETAINED (views the server retains; 0 = unknown),
//! IX_ROUND_MS (server round duration).
#![cfg(feature = "http")]
#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::{json, Value};
use unicity_token::api::bft::{RootTrustBase, ShardId};
use unicity_token::api::{NonInclusionProof, StateId};
use unicity_token::cbor::Decoder;
use unicity_token::client::{
    certification_data_for, AggregatorClient, BatchAggregatorClient, BatchFailure, BatchRequest,
    BundleOutcome, ConsolidateOptions, HttpAggregatorClient, HttpError, MembershipStatus,
    NonInclusionAggregatorClient, ProofClient, ProofClientConfig, ProofItem, RequestOptions,
    StateRoot,
};
use unicity_token::consolidation::PartitionTopology;
use unicity_token::crypto::signer::{Secp256k1Signer, Signer};
use unicity_token::predicate::builtin::SignaturePredicate;
use unicity_token::predicate::EncodedPredicate;
use unicity_token::transaction::ids::{TokenSalt, TokenType};
use unicity_token::transaction::{
    CertifiedMintTransaction, MintTransaction, Minter, Token, Transaction,
};
use unicity_token::verify::NonInclusionContext;

fn emit(scn: &str, name: &str, status: &str, evidence: &str) {
    println!(
        "{}",
        json!({"client":"rust","scenario":scn,"name":name,"status":status,"evidence":evidence})
    );
}

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_default()
}

struct Minted {
    state_id: StateId,
    tx: MintTransaction,
    data: unicity_token::api::CertificationData,
}

fn new_mint(network: unicity_token::api::NetworkId) -> Minted {
    new_mint_exp(network, None)
}

fn new_mint_exp(network: unicity_token::api::NetworkId, expires_at: Option<u64>) -> Minted {
    let owner = Secp256k1Signer::generate().unwrap();
    let tx = MintTransaction::create(
        network,
        EncodedPredicate::from_predicate(&SignaturePredicate::new(owner.public_key())),
        TokenType::random().unwrap(),
        TokenSalt::random().unwrap(),
        None,
        None,
        expires_at,
    )
    .unwrap();
    let signer = Minter::signer(tx.token_id()).unwrap();
    let data = certification_data_for(&tx, &signer);
    let state_id = StateId::derive(tx.lock_script(), tx.source_state_hash());
    Minted { state_id, tx, data }
}

fn rpc_detail(f: &BatchFailure) -> String {
    match f {
        BatchFailure::Rpc {
            code,
            reason,
            detail,
            retryable,
            indexes,
            ..
        } => format!(
            "code={code} reason={} detail={} retryable={retryable:?} indexes={indexes:?}",
            reason.clone().unwrap_or_default(),
            detail.clone().unwrap_or_default()
        ),
        other => format!("{other}"),
    }
}

fn opts() -> RequestOptions {
    RequestOptions { timeout_ms: 20_000 }
}

fn http_post(url: &str, body: &str) -> Result<(u16, Value), String> {
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(30)).build();
    let resp = match agent
        .post(url)
        .set("Content-Type", "application/json")
        .send_string(body)
    {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => return Err(e.to_string()),
    };
    let status = resp.status();
    let text = resp.into_string().map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(&text).map_err(|e| format!("non-JSON ({status}): {e}"))?;
    Ok((status, v))
}

#[test]
#[ignore = "needs a running aggregator (see scripts/interop/matrix/run.sh)"]
fn interop_matrix() {
    let url = env("IX_URL");
    let trust_base = RootTrustBase::from_json(
        &std::fs::read_to_string(env("IX_TRUSTBASE")).expect("read trust base"),
    )
    .expect("parse trust base");
    let partition: u32 = env("IX_PARTITION").parse().expect("IX_PARTITION");
    let n: usize = env("IX_N").parse().unwrap_or(6);
    let retained: usize = env("IX_RETAINED").parse().unwrap_or(0);
    let round_ms: u64 = env("IX_ROUND_MS").parse().unwrap_or(1000);
    let attempts = ((round_ms * 20 + 30_000) / 200) as u32;

    let http = || {
        HttpAggregatorClient::new_insecure_http(url.clone())
            .with_polling(Duration::from_millis(200), attempts)
            .with_unknown_grace(5)
    };
    let agg = http();

    // ---- scenario 1: submit N, wait with status hints, verify each
    let mut minted: Vec<Minted> = (0..n).map(|_| new_mint(trust_base.network_id)).collect();
    let mut failure: Option<String> = None;
    let mut proofs = Vec::new();
    // three waves, each fetched right after its inclusion: the originals carry different seals
    let wave = n.div_ceil(3).max(1);
    for chunk in minted.chunks(wave) {
        for m in chunk {
            if let Err(e) = agg.submit_certification_request(&m.data) {
                failure = Some(format!("submit: {e}"));
                break;
            }
        }
        if failure.is_some() {
            break;
        }
        for m in chunk {
            match agg.get_inclusion_proof(&m.state_id) {
                Ok(p) => proofs.push(p),
                Err(e) => {
                    failure = Some(format!("wait: {e}"));
                    break;
                }
            }
        }
        if failure.is_some() {
            break;
        }
    }
    if failure.is_none() {
        for (m, p) in minted.iter().zip(&proofs) {
            // full verification of the proof and of the whole minted token
            if let Err(e) = p.verify_for(&m.state_id, p.reference_time, &trust_base) {
                failure = Some(format!("proof verify: {e}"));
                break;
            }
            let token = Token::new(
                CertifiedMintTransaction::new(
                    m.tx.clone(),
                    p.clone(),
                ),
                Vec::new(),
            );
            if let Err(e) = token.verify(&trust_base) {
                failure = Some(format!("token verify: {e}"));
                break;
            }
        }
    }
    if let Some(f) = failure {
        emit("1", "submit and wait", "FAIL", &f);
        return;
    }
    emit(
        "1",
        "submit and wait",
        "PASS",
        &format!("{n} requests included (client polls with includeStatus), proofs and tokens fully verified"),
    );

    // ---- scenario 1b: the SDK's request encoding has no count field (reserved slot is always 0)
    emit("1b", "reference-tool request (aggregateRequestCount=1)", "N-A", "the Rust SDK never writes a non-zero reserved slot");

    // ---- scenario 2: consolidate latest, direct unsharded path
    let client = ProofClient::with_host_defaults(
        ProofClientConfig {
            partition_id: partition,
            topology: PartitionTopology::new(Vec::new()),
        },
        vec![(ShardId::root(), http())],
        trust_base.clone(),
        4,
    )
    .expect("proof client");
    let items: Vec<ProofItem> = minted
        .iter()
        .zip(&proofs)
        .map(|(m, p)| ProofItem {
            state_id: m.state_id.clone(),
            proof: p.clone(),
        })
        .collect();
    let mut master_root: Option<Vec<u8>> = None;
    match client.consolidate_proofs(&items, &ConsolidateOptions::default()) {
        Ok(BundleOutcome::Consolidated(bundle)) => {
            let s = &bundle.summary;
            master_root = Some(bundle.proofs[0].unicity_certificate.input_record.hash.clone());
            // every replacement proof is independently re-verified
            let mut bad = String::new();
            for (m, p) in minted.iter().zip(&bundle.proofs) {
                if let Err(e) = p.verify_for(&m.state_id, p.reference_time, &trust_base) {
                    bad = format!("replacement proof does not verify: {e}");
                    break;
                }
            }
            let evidence_rounds: Vec<u64> = proofs
                .iter()
                .map(|p| p.unicity_certificate.unicity_seal.root_chain_round_number)
                .collect();
            let ok = bad.is_empty()
                && s.requests == 1
                && s.shards == 1
                && s.outer_seals_after == 1
                && s.certificates_derived == 0 // direct path: nothing is derived from a view
                && s.consolidation_quorum_checks <= s.outer_seals_before as u64 + 1;
            emit(
                "2",
                "consolidate latest (direct unsharded)",
                if ok { "PASS" } else { "FAIL" },
                &format!(
                    "requests={} shards={} sealsBefore={} sealsAfter={} consolidationQuorumChecks={} certificatesDerived={} masterRound={:?} evidenceRootRounds={evidence_rounds:?} {bad}",
                    s.requests, s.shards, s.outer_seals_before, s.outer_seals_after,
                    s.consolidation_quorum_checks, s.certificates_derived, s.master_round
                ),
            );
        }
        Ok(BundleOutcome::Unavailable { reason, retryable }) => emit(
            "2",
            "consolidate latest (direct unsharded)",
            "FAIL",
            &format!("unavailable: {reason:?} retryable={retryable}"),
        ),
        Err(e) => emit("2", "consolidate latest (direct unsharded)", "FAIL", &format!("{e}")),
    }

    let ids: Vec<StateId> = minted.iter().map(|m| m.state_id.clone()).collect();
    let wait = |m: &Minted| -> Result<(), String> {
        agg.get_inclusion_proof(&m.state_id)
            .map(|_| ())
            .map_err(|e| e.to_string())
    };

    // ---- scenario 3: exact root
    match master_root {
        None => emit("3", "exact root", "FAIL", "no latest root known (scenario 2 failed)"),
        Some(root) => {
            let root32: [u8; 32] = root.clone().try_into().expect("32-byte root");
            let mut ev = Vec::new();
            let mut failed = false;
            match agg.get_inclusion_proofs(
                &BatchRequest {
                    state_ids: &ids,
                    state_root: StateRoot::Exact(root32),
                },
                &opts(),
            ) {
                Ok(b) => {
                    ev.push(format!(
                        "retained root: {} proofs, partitionView={}",
                        b.proofs.len(),
                        b.partition_view.is_some()
                    ));
                    if b.proofs.len() != n || b.partition_view.is_some() {
                        failed = true;
                    }
                }
                Err(e) => {
                    failed = true;
                    ev.push(format!("retained root: {}", rpc_detail(&e)));
                }
            }
            // a second wave moves the latest root; the first root stays retained, but does not hold the new state
            let extra = new_mint(trust_base.network_id);
            agg.submit_certification_request(&extra.data).unwrap();
            wait(&extra).unwrap();
            let mut with_extra = ids.clone();
            with_extra.push(extra.state_id.clone());
            match agg.get_inclusion_proofs(
                &BatchRequest {
                    state_ids: &with_extra,
                    state_root: StateRoot::Exact(root32),
                },
                &opts(),
            ) {
                Ok(_) => {
                    failed = true;
                    ev.push("old root unexpectedly contains the new state".into());
                }
                Err(f) => {
                    ev.push(format!("old root + new state: {}", rpc_detail(&f)));
                    match &f {
                        BatchFailure::Rpc {
                            code: -32008,
                            detail: Some(d),
                            indexes,
                            ..
                        } if d == "state_not_in_root"
                            && indexes.get("not_in_root") == Some(&vec![n]) => {}
                        _ => failed = true,
                    }
                }
            }
            let mut unknown_root = [0u8; 32];
            unknown_root[0] = 0xde;
            unknown_root[31] = 0xad;
            match agg.get_inclusion_proofs(
                &BatchRequest {
                    state_ids: &ids,
                    state_root: StateRoot::Exact(unknown_root),
                },
                &opts(),
            ) {
                Ok(_) => {
                    failed = true;
                    ev.push("unknown root unexpectedly served".into());
                }
                Err(f) => {
                    ev.push(format!("unknown root: {}", rpc_detail(&f)));
                    if !matches!(&f, BatchFailure::Rpc { code: -32008, detail: Some(d), .. } if d == "view_not_retained")
                    {
                        failed = true;
                    }
                }
            }
            emit(
                "3",
                "exact root (retained, other-state, unknown)",
                if failed { "FAIL" } else { "PASS" },
                &ev.join("; "),
            );
            if retained > 0 && retained <= 40 {
                for _ in 0..retained + 1 {
                    let m = new_mint(trust_base.network_id);
                    agg.submit_certification_request(&m.data).unwrap();
                    wait(&m).unwrap();
                }
                match agg.get_inclusion_proofs(
                    &BatchRequest {
                        state_ids: &ids,
                        state_root: StateRoot::Exact(root32),
                    },
                    &opts(),
                ) {
                    Ok(_) => emit("3b", "evicted root", "FAIL", "evicted root still served"),
                    Err(f) => {
                        let ok = matches!(&f, BatchFailure::Rpc { code: -32008, detail: Some(d), .. } if d == "view_not_retained");
                        emit("3b", "evicted root", if ok { "PASS" } else { "FAIL" }, &rpc_detail(&f));
                    }
                }
            } else {
                emit(
                    "3b",
                    "evicted root",
                    "N-A",
                    &format!("server retention not small enough to evict cheaply (IX_RETAINED={retained})"),
                );
            }
        }
    }

    // ---- scenario 4: status hints and batch details
    {
        let mut ev = Vec::new();
        let mut failed = false;
        let mut got_pending = false;
        for _ in 0..3 {
            if got_pending {
                break;
            }
            let pend = new_mint(trust_base.network_id);
            agg.submit_certification_request(&pend.data).unwrap();
            let one = [pend.state_id.clone()];
            match agg.get_inclusion_proofs(
                &BatchRequest {
                    state_ids: &one,
                    state_root: StateRoot::Latest,
                },
                &opts(),
            ) {
                Err(f) => {
                    ev.push(format!("pending: {}", rpc_detail(&f)));
                    if matches!(&f, BatchFailure::Rpc { code: -32008, detail: Some(d), indexes, retryable: Some(true), .. }
                        if d == "state_pending" && indexes.get("pending") == Some(&vec![0]))
                    {
                        got_pending = true;
                    }
                }
                Ok(_) => ev.push("batch served the state before the round closed (race)".into()),
            }
            wait(&pend).unwrap();
        }
        if !got_pending {
            failed = true;
            ev.push("pending not reproduced".into());
        }
        let unk = new_mint(trust_base.network_id); // never submitted
        let mixed = [ids[0].clone(), unk.state_id.clone(), ids[1].clone()];
        match agg.get_inclusion_proofs(
            &BatchRequest {
                state_ids: &mixed,
                state_root: StateRoot::Latest,
            },
            &opts(),
        ) {
            Ok(_) => {
                failed = true;
                ev.push("unknown state served".into());
            }
            Err(f) => {
                ev.push(format!("unknown: {}", rpc_detail(&f)));
                let ok: bool = matches!(&f, BatchFailure::Rpc { code: -32008, detail: Some(d), indexes, .. }
                    if d == "state_unknown" && indexes.get("unknown") == Some(&vec![1]));
                if !ok {
                    failed = true;
                }
            }
        }
        // the polling client reports an unknown state through the status hint
        match http().with_unknown_grace(0).get_inclusion_proof(&unk.state_id) {
            Err(HttpError::StateUnknown) => ev.push("v2 hint unknown -> StateUnknown".into()),
            // rugregator's legacy v2 answers -32020, which the SDK maps to StateNotFound
            Err(HttpError::StateNotFound) => ev.push("v2 unknown -> StateNotFound (rpc -32020, no status object)".into()),
            other => {
                failed = true;
                ev.push(format!("v2 hint unknown -> {other:?}"));
            }
        }
        emit(
            "4",
            "status hints (pending/unknown) and data.indexes",
            if failed { "FAIL" } else { "PASS" },
            &ev.join("; "),
        );
        // expired: a deadline one second after the latest seal time lands in a later round when the request
        // arrives while a round waits for its certificate; scan the round period
        let (mut expired, mut notes) = (false, Vec::<String>::new());
        for off in 0..24u64 {
            if expired {
                break;
            }
            std::thread::sleep(Duration::from_millis(off * 60));
            let one = [ids[0].clone()];
            let ts = match agg.get_inclusion_proofs(
                &BatchRequest { state_ids: &one, state_root: StateRoot::Latest },
                &opts(),
            ) {
                Ok(b) => b.proofs[0].proof.unicity_certificate.unicity_seal.timestamp,
                Err(f) => {
                    notes.push(format!("latest seal time: {}", rpc_detail(&f)));
                    break;
                }
            };
            let m = new_mint_exp(trust_base.network_id, Some(ts + 1));
            if let Err(e) = agg.submit_certification_request(&m.data) {
                notes.push(format!("attempt {off}: rejected at admission: {e}"));
                continue;
            }
            let one = [m.state_id.clone()];
            loop {
                match agg.get_inclusion_proofs(
                    &BatchRequest { state_ids: &one, state_root: StateRoot::Latest },
                    &opts(),
                ) {
                    Ok(_) => {
                        notes.push(format!("attempt {off}: included"));
                        break;
                    }
                    Err(BatchFailure::Rpc { detail: Some(d), .. }) if d == "state_pending" => {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(f) => {
                        notes.push(format!("attempt {off}: batch {}", rpc_detail(&f)));
                        if matches!(&f, BatchFailure::Rpc { detail: Some(d), indexes, .. } if d == "state_expired" && indexes.get("expired") == Some(&vec![0])) {
                            // the polling client maps the same hint to its typed error
                            let r = http().with_unknown_grace(0).get_inclusion_proof(&m.state_id);
                            notes.push(format!("v2 includeStatus -> {}", match &r {
                                Err(HttpError::StateExpired) => "StateExpired".to_string(),
                                other => format!("{other:?}"),
                            }));
                            expired = matches!(r, Err(HttpError::StateExpired));
                        }
                        break;
                    }
                }
            }
        }
        if notes.len() > 5 {
            let tail = notes.split_off(notes.len() - 3);
            notes.truncate(2);
            notes.push("...".into());
            notes.extend(tail);
        }
        emit("4b", "expired hint", if expired { "PASS" } else { "N-A" }, &if expired { notes.join("; ") } else { format!("not reproduced: {}", notes.join("; ")) });
    }

    // ---- scenario 5: non-inclusion
    {
        let mut ev = Vec::new();
        let mut failed = false;
        let ctx = NonInclusionContext::new(partition);
        let absent = new_mint(trust_base.network_id).state_id;
        let mut encoded: Vec<u8> = Vec::new();
        match agg.get_non_inclusion_proof(&absent) {
            Ok(proof) => match proof.verify_in_context(&trust_base, &ctx) {
                Ok(()) => {
                    encoded = proof.to_cbor();
                    ev.push("absence verified".to_string());
                }
                Err(e) => {
                    failed = true;
                    ev.push(format!("verify: {e}"));
                }
            },
            Err(e) => {
                failed = true;
                ev.push(format!("absent id: {e}"));
            }
        }
        match agg.get_non_inclusion_proof(&ids[0]) {
            Err(HttpError::StateIncluded) => ev.push("present id: StateIncluded".into()),
            other => {
                failed = true;
                ev.push(format!("present id: {other:?}"));
            }
        }
        match agg.membership_status(&ids[0]) {
            Ok(MembershipStatus::Included(p)) => {
                match p.verify_for(&ids[0], p.reference_time, &trust_base) {
                    Ok(()) => ev.push("membership_status(present) -> Included, verified".into()),
                    Err(e) => {
                        failed = true;
                        ev.push(format!("membership_status inclusion proof: {e}"));
                    }
                }
            }
            other => {
                failed = true;
                ev.push(format!("membership_status(present) -> {other:?}"));
            }
        }
        // tampering: flip one bit of every byte in turn
        let (mut accepted, mut total) = (Vec::new(), 0usize);
        for i in 0..encoded.len() {
            let mut m = encoded.clone();
            m[i] ^= 1;
            total += 1;
            let d = Decoder::new(&m);
            let Ok(p) = NonInclusionProof::from_cbor(d) else { continue };
            let Ok(p) = p.for_state(&absent) else { continue };
            if p.verify_in_context(&trust_base, &ctx).is_ok() {
                accepted.push(i);
            }
        }
        if encoded.is_empty() {
            failed = true;
        } else if accepted.is_empty() {
            ev.push(format!("tamper: all {total} single-bit flips rejected"));
        } else {
            // strict single-pass recovery: the final byte (recovery id) must be rejected too. The block number
            // (unauthenticated metadata, after the array header) is the only non-binding field.
            let head = match encoded.get(1) { Some(0x18) => 2, Some(0x19) => 3, Some(0x1a) => 5, Some(0x1b) => 9, _ => 1 };
            let binding: Vec<usize> = accepted.iter().copied().filter(|o| !(1..1 + head).contains(o)).collect();
            ev.push(format!(
                "tamper: {} of {total} single-bit flips still verified at offsets {accepted:?} (non-binding: block number only; binding offsets accepted: {binding:?})",
                accepted.len()
            ));
            failed = failed || !binding.is_empty();
        }
        emit(
            "5",
            "non-inclusion (absent, present, tampered)",
            if failed { "FAIL" } else { "PASS" },
            &ev.join("; "),
        );
    }

    // ---- scenario 6: error envelope
    {
        let cases: Value =
            serde_json::from_str(&std::fs::read_to_string(env("IX_CASES")).expect("cases")).unwrap();
        let id0 = hex::encode(ids[0].bytes());
        let mut bad = Vec::new();
        let list = cases["cases"].as_array().unwrap();
        for c in list {
            let method = c["method"].as_str().unwrap_or("get_inclusion_proofs.v1");
            let params: Value = match c["gen"].as_str() {
                Some("ids257") => {
                    let l: Vec<String> = (1..=257).map(|i| format!("{i:064x}")).collect();
                    json!({"stateIds": l, "stateRoot": "latest"})
                }
                Some("oversize") => json!({"stateIds": [id0], "stateRoot": "latest", "pad": "a".repeat(70 * 1024)}),
                _ => serde_json::from_str(&c["params"].to_string().replace("{ID}", &id0)).unwrap(),
            };
            let body = json!({"jsonrpc":"2.0","id":7,"method":method,"params":params}).to_string();
            let name = c["name"].as_str().unwrap();
            match http_post(&url, &body) {
                Err(e) => bad.push(format!("{name}: {e}")),
                Ok((status, v)) => {
                    let Some(e) = v.get("error") else {
                        bad.push(format!("{name}: no error"));
                        continue;
                    };
                    let mut diffs = String::new();
                    if u64::from(status) != c["http"].as_u64().unwrap() {
                        diffs += &format!(" http={status}(want {})", c["http"]);
                    }
                    if e["code"] != c["code"] {
                        diffs += &format!(" code={}(want {})", e["code"], c["code"]);
                    }
                    if !c["reason"].is_null() && e["data"]["reason"] != c["reason"] {
                        diffs += &format!(" reason={}(want {})", e["data"]["reason"], c["reason"]);
                    }
                    if !c["detail"].is_null() && e["data"]["detail"] != c["detail"] {
                        diffs += &format!(" detail={}(want {})", e["data"]["detail"], c["detail"]);
                    }
                    if !diffs.is_empty() {
                        bad.push(format!("{name}:{diffs}"));
                    }
                }
            }
        }
        // the typed client mapping of a limit error: the SDK refuses 257 ids before sending
        let many: Vec<StateId> = (0..257).map(|_| new_mint(trust_base.network_id).state_id).collect();
        let typed = agg.get_inclusion_proofs(
            &BatchRequest {
                state_ids: &many,
                state_root: StateRoot::Latest,
            },
            &opts(),
        );
        let local = format!("client-side 257 ids: {}", typed.map(|_| "sent".to_string()).unwrap_or_else(|f| rpc_detail(&f)));
        if bad.is_empty() {
            emit(
                "6",
                "error envelope (limits, malformed params)",
                "PASS",
                &format!("{} cases match the reference envelope; {local}", list.len()),
            );
        } else {
            emit("6", "error envelope (limits, malformed params)", "FAIL", &format!("{}; {local}", bad.join("; ")));
        }
    }
    let _: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    minted.clear();
}
