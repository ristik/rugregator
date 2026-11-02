//! Live BFT Core committer using libp2p.

use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};

use async_trait::async_trait;
use futures::prelude::*;
use libp2p::{
    core::upgrade,
    identify, identity,
    request_response::{self, Codec, ProtocolSupport},
    swarm::{NetworkBehaviour, Swarm, SwarmEvent},
    Multiaddr, PeerId, StreamProtocol, Transport,
};
use secp256k1::{Message, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, error, info, warn};

use super::{BftCommitter, CertRejection, CertStatus};
use crate::api::cbor::{validate_unicity_certificate_value, INPUT_RECORD_TAG};

// ─── Wire types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde_tuple::Serialize_tuple, serde_tuple::Deserialize_tuple)]
struct InputRecord {
    version: u32,
    round_number: u64,
    epoch: u64,
    #[serde(with = "opt_bytes")]
    previous_hash: Option<Vec<u8>>,
    #[serde(with = "opt_bytes")]
    hash: Option<Vec<u8>>,
    #[serde(with = "opt_bytes")]
    summary_value: Option<Vec<u8>>,
    timestamp: u64,
    #[serde(with = "opt_bytes")]
    block_hash: Option<Vec<u8>>,
    sum_of_earned_fees: u64,
    #[serde(with = "opt_bytes")]
    et_hash: Option<Vec<u8>>,
}

#[derive(Debug, Clone, serde_tuple::Serialize_tuple, serde_tuple::Deserialize_tuple)]
struct BlockCertReq {
    partition_id: u32,
    #[serde(with = "serde_bytes")]
    shard_id: Vec<u8>,
    node_id: String,
    input_record: InputRecord,
    #[serde(with = "opt_bytes")]
    zk_proof: Option<Vec<u8>>,
    block_size: u64,
    state_size: u64,
    #[serde(with = "opt_bytes")]
    signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, serde_tuple::Serialize_tuple, serde_tuple::Deserialize_tuple)]
struct Handshake {
    partition_id: u32,
    #[serde(with = "serde_bytes")]
    shard_id: Vec<u8>,
    node_id: String,
}

mod opt_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match v {
            Some(b) => serde_bytes::serialize(b.as_slice(), s),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D>(d: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct H(#[serde(with = "serde_bytes")] Vec<u8>);
        let opt: Option<H> = Option::deserialize(d)?;
        Ok(opt.map(|H(v)| v))
    }
}

// ─── Round state ──────────────────────────────────────────────────────────

/// Authoritative reference from the last valid UC.
/// Updated from EVERY valid UC (sync, cert response, repeat).
#[derive(Debug, Clone)]
struct LastUc {
    /// TechnicalRecord.Round — the round number to use in the next cert request.
    next_round: u64,
    epoch: u64,
    /// InputRecord.Hash — the certified state hash (becomes previous_hash in next request).
    prev_hash: Option<Vec<u8>>,
    /// UnicitySeal.Timestamp — must be echoed verbatim in the next cert request.
    timestamp: u64,
}

// ─── Shared state between the committer and the network task ──────────────────

/// Result delivered to the round manager via the per-block oneshot channel.
/// `Ok(uc_cbor)` = accepted. `Err(rejection)` = BFT Core refused with a typed
/// status; the round manager branches on `rejection.status`.
type UcOutcome = Result<Vec<u8>, CertRejection>;

struct Shared {
    /// block_number → oneshot receiver (set in commit_block, awaited in wait_for_uc)
    blk_receivers: Mutex<HashMap<u64, oneshot::Receiver<UcOutcome>>>,
    /// UnicitySeal.Timestamp of the last valid UC: the reference time the next
    /// round pins and echoes as `InputRecord.timestamp`.
    reference_time: AtomicU64,
    reference_time_tx: watch::Sender<u64>,
}

// ─── Parsed UC event ─────────────────────────────────────────────────────────

struct UcEvent {
    /// CertificationResponse.Partition / .Shard as sent; `None` when the field is missing or not of
    /// the expected type (the intake treats that as a rejection).
    wrapper_partition: Option<u64>,
    wrapper_shard: Option<Vec<u8>>,
    /// The certificate's own partition (UnicityTreeCertificate) and shard (ShardTreeCertificate).
    uc_partition: Option<u64>,
    uc_shard: Option<Vec<u8>>,
    /// What the sequence rules need.
    facts: UcFacts,
    /// IR.round_number — 0 for sync (proactive) UCs.
    uc_round: u64,
    /// TechnicalRecord.round — the round number for the next cert request.
    next_round: u64,
    epoch: u64,
    prev_hash: Option<Vec<u8>>,
    /// InputRecord.Timestamp, the reference time used to build this root.
    input_record_timestamp: u64,
    /// UnicitySeal.Timestamp — must be echoed verbatim in our cert request.
    timestamp: u64,
    uc_cbor: Vec<u8>,
    /// Outer transport status (0 = accepted). Non-zero → the request that
    /// triggered this response was rejected; `message` explains why and the
    /// wrapped UC is the last-good certificate.
    status: u32,
    message: String,
}

// ─── Pending cert request (held by network loop during certification) ─────────

struct PendingCert {
    new_hash: Vec<u8>,
    /// Aggregator's actual previous SMT root (for re-deriving prev_hash_ir on re-send).
    prev_hash: Vec<u8>,
    zk_proof: Option<Vec<u8>>,
    block_size: u64,
    state_size: u64,
    /// Reference time used to derive every leaf in `new_hash`.
    reference_time: u64,
    uc_tx: oneshot::Sender<UcOutcome>,
    /// Round used when this cert request was (last) sent.
    round_used: u64,
}

// ─── libp2p plumbing ─────────────────────────────────────────────────────────

const PROTO_CERT: &str = "/ab/block-certification/0.0.1";
const PROTO_UC: &str = "/ab/certificates/0.0.1";
const PROTO_HS: &str = "/ab/handshake/0.0.1";

/// Data for a cert request, sans round/epoch (filled in at transmission time).
struct CertReqData {
    new_hash: Vec<u8>,
    /// Aggregator's actual previous SMT root (34-byte imprint).
    prev_hash: Vec<u8>,
    zk_proof: Option<Vec<u8>>,
    block_size: u64,
    state_size: u64,
    /// Reference time used to derive every leaf in `new_hash`.
    reference_time: u64,
    /// Deliver the UC outcome (accepted CBOR or typed rejection) once it arrives.
    uc_tx: oneshot::Sender<UcOutcome>,
}

enum NetCmd {
    Submit(CertReqData),
}

#[derive(Debug, Clone, Default)]
struct BftCodec {
    /// Set on the inbound UC protocol only: decides before any byte is read whether a stream is
    /// served.
    guard: Option<Arc<ReadGuard>>,
}

#[async_trait::async_trait]
impl Codec for BftCodec {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;
    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> std::io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        // Requests are only ever read on the inbound UC protocol (the other two are outbound
        // only). The quota and the concurrency bound are enforced BEFORE the length prefix or any
        // payload is read, and a stalled body is cut at the deadline; a certification response is
        // a few KiB, so the frame itself is bounded tightly too.
        let Some(guard) = self.guard.clone() else {
            return read_uvi_limited(io, MAX_UC_FRAME_BYTES).await;
        };
        let _permit = guard.admit(std::time::Instant::now()).map_err(|why| {
            if let Some(suppressed) = guard.throttle.hit(std::time::Instant::now()) {
                warn!(
                    ?why,
                    suppressed, "certification response stream refused before reading"
                );
            }
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "uc stream refused")
        })?;
        match tokio::time::timeout(guard.timeout, read_uvi_limited(io, MAX_UC_FRAME_BYTES)).await {
            Ok(frame) => frame,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "uc frame read deadline",
            )),
        }
    }
    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> std::io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_uvi(io).await
    }
    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Vec<u8>,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_uvi(io, &req).await
    }
    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Vec<u8>,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_uvi(io, &res).await
    }
}

/// Frame limit of an inbound certification response (aggregator-go bounds a V1 response the same
/// way). It is checked before any allocation.
const MAX_UC_FRAME_BYTES: u64 = 256 * 1024;

async fn read_uvi<R: AsyncRead + Unpin + Send>(r: &mut R) -> std::io::Result<Vec<u8>> {
    read_uvi_limited(r, 10 * 1024 * 1024).await
}

async fn read_uvi_limited<R: AsyncRead + Unpin + Send>(
    r: &mut R,
    max: u64,
) -> std::io::Result<Vec<u8>> {
    let len = unsigned_varint::aio::read_u64(&mut *r)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if len == 0 || len > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad len",
        ));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_uvi<W: AsyncWrite + Unpin + Send>(w: &mut W, data: &[u8]) -> std::io::Result<()> {
    let mut lb = unsigned_varint::encode::u64_buffer();
    let lb = unsigned_varint::encode::u64(data.len() as u64, &mut lb);
    w.write_all(lb).await?;
    w.write_all(data).await?;
    w.flush().await
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    /// Only the pinned root peer may hold a connection: everybody else is denied right after the
    /// noise handshake, before any protocol stream exists.
    allow: libp2p::allow_block_list::Behaviour<libp2p::allow_block_list::AllowedPeers>,
    cert: request_response::Behaviour<BftCodec>,
    uc: request_response::Behaviour<BftCodec>,
    hs: request_response::Behaviour<BftCodec>,
    identify: identify::Behaviour,
}

/// The protocol behaviours, with the root peer as the only allowed connection.
fn build_behaviour(kp: &identity::Keypair, root_peer: PeerId) -> Behaviour {
    let mk_rr = |proto: &'static str, support: ProtocolSupport, guard: Option<Arc<ReadGuard>>| {
        request_response::Behaviour::with_codec(
            BftCodec { guard },
            std::iter::once((StreamProtocol::new(proto), support)),
            request_response::Config::default()
                .with_request_timeout(std::time::Duration::from_secs(60)),
        )
    };
    let mut allow = libp2p::allow_block_list::Behaviour::default();
    allow.allow_peer(root_peer);
    Behaviour {
        allow,
        cert: mk_rr(PROTO_CERT, ProtocolSupport::Outbound, None),
        uc: mk_rr(
            PROTO_UC,
            ProtocolSupport::Inbound,
            Some(Arc::new(ReadGuard::new(
                MAX_CONCURRENT_UC_READS,
                UC_READ_TIMEOUT,
            ))),
        ),
        hs: mk_rr(PROTO_HS, ProtocolSupport::Outbound, None),
        identify: identify::Behaviour::new(identify::Config::new(
            "/ipfs/0.1.0".into(),
            kp.public(),
        )),
    }
}

// ─── Config ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LiveBftConfig {
    pub partition_id: u32,
    /// Canonical shard bitstring, including the end marker.
    pub shard_id: Vec<u8>,
    pub bft_peer_id: PeerId,
    pub bft_addr: Multiaddr,
    pub listen_addr: Multiaddr,
    /// Raw secp256k1 bytes (32) for libp2p auth key (PeerId derivation)
    pub auth_key_bytes: Vec<u8>,
    /// Raw secp256k1 bytes (32) for signing BlockCertificationRequests
    pub sig_key_bytes: Vec<u8>,
    /// When true, use luc.InputRecord.Hash as PreviousHash (test mode).
    /// When false (default), use the aggregator's actual previous SMT root.
    pub fake_state_transitions: bool,
    /// UC inactivity timeout — re-send handshake after this many milliseconds
    /// without a UC.  Should be ~2× BFT Core's T2 for this partition.
    pub uc_timeout_ms: u64,
}

// ─── LiveBftCommitter ─────────────────────────────────────────────────────────

pub struct LiveBftCommitter {
    cmd_tx: mpsc::Sender<NetCmd>,
    shared: Arc<Shared>,
}

impl LiveBftCommitter {
    pub fn start(cfg: LiveBftConfig) -> anyhow::Result<Self> {
        let secret =
            libp2p::identity::secp256k1::SecretKey::try_from_bytes(cfg.auth_key_bytes.clone())
                .map_err(|e| anyhow::anyhow!("auth key: {e}"))?;
        let kp = identity::Keypair::from(libp2p::identity::secp256k1::Keypair::from(secret));
        let local_peer = PeerId::from(kp.public());
        let node_id = local_peer.to_string();

        let tcp = libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default());
        let transport = libp2p::dns::tokio::Transport::system(tcp)
            .map_err(|e| anyhow::anyhow!("dns transport: {e}"))?
            .upgrade(upgrade::Version::V1)
            .authenticate(libp2p::noise::Config::new(&kp)?)
            .multiplex(libp2p::yamux::Config::default())
            .boxed();

        let behaviour = build_behaviour(&kp, cfg.bft_peer_id);

        let mut swarm = Swarm::new(
            transport,
            behaviour,
            local_peer,
            libp2p::swarm::Config::with_tokio_executor()
                .with_idle_connection_timeout(std::time::Duration::from_secs(86400)),
        );
        swarm.listen_on(cfg.listen_addr.clone())?;

        let (reference_time_tx, _) = watch::channel(0);
        let shared = Arc::new(Shared {
            blk_receivers: Mutex::new(HashMap::new()),
            reference_time: AtomicU64::new(0),
            reference_time_tx,
        });

        let (cmd_tx, cmd_rx) = mpsc::channel(64);

        let shared2 = Arc::clone(&shared);
        let bft_peer = cfg.bft_peer_id;
        let bft_addr = cfg.bft_addr.clone();
        let partition_id = cfg.partition_id;
        let shard_id = cfg.shard_id;
        let node_id2 = node_id.clone();
        let sig_key2 = SecretKey::from_slice(&cfg.sig_key_bytes)
            .map_err(|e| anyhow::anyhow!("sig key (net): {e}"))?;
        let fake_st = cfg.fake_state_transitions;
        let uc_timeout_ms = cfg.uc_timeout_ms;

        tokio::spawn(async move {
            network_loop(
                swarm,
                cmd_rx,
                shared2,
                bft_peer,
                bft_addr,
                partition_id,
                shard_id,
                node_id2,
                sig_key2,
                fake_st,
                uc_timeout_ms,
            )
            .await;
        });

        Ok(Self { cmd_tx, shared })
    }

    async fn wait_init(&self) {
        let mut reference_time_rx = self.shared.reference_time_tx.subscribe();
        loop {
            if *reference_time_rx.borrow_and_update() != 0 {
                return;
            }
            if reference_time_rx.changed().await.is_err() {
                return;
            }
        }
    }
}

#[async_trait]
impl BftCommitter for LiveBftCommitter {
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
        self.wait_init().await;

        // The round built every leaf value from `reference_time`. If a newer
        // certificate has arrived since, the request would report a timestamp
        // the leaves do not match, so refuse rather than propose a root BFT
        // Core cannot reproduce.
        let current = self.shared.reference_time.load(Ordering::Acquire);
        if reference_time != current {
            anyhow::bail!(
                "round reference time {reference_time} does not match latest seal timestamp {current}"
            );
        }

        let new_hash = new_root.map(|r| r.to_vec()).unwrap_or_default();
        let prev_hash = prev_root.map(|r| r.to_vec()).unwrap_or_default();

        // Register the block → UC receiver BEFORE queuing the Submit command so
        // the network task can fill the sender side at transmission time.
        let (tx, rx) = oneshot::channel::<UcOutcome>();
        self.shared
            .blk_receivers
            .lock()
            .unwrap()
            .insert(block_number, rx);

        let data = CertReqData {
            new_hash,
            prev_hash,
            zk_proof,
            block_size,
            state_size,
            reference_time,
            uc_tx: tx,
        };

        self.cmd_tx
            .send(NetCmd::Submit(data))
            .await
            .map_err(|_| anyhow::anyhow!("net task closed"))?;

        info!(
            block = block_number,
            "cert request queued (round resolved at send time)"
        );
        Ok(())
    }

    fn reference_time(&self) -> u64 {
        self.shared.reference_time.load(Ordering::Acquire)
    }

    fn subscribe_reference_time(&self) -> watch::Receiver<u64> {
        self.shared.reference_time_tx.subscribe()
    }

    async fn wait_for_uc(&self, block_number: u64) -> anyhow::Result<Vec<u8>> {
        let rx = self
            .shared
            .blk_receivers
            .lock()
            .unwrap()
            .remove(&block_number);
        let rx = match rx {
            Some(r) => r,
            None => {
                warn!(
                    block = block_number,
                    "no UC receiver registered; returning stub"
                );
                return Ok(vec![]);
            }
        };
        let outcome = rx.await.map_err(|_| anyhow::anyhow!("UC sender dropped"))?;
        match outcome {
            Ok(uc) => {
                info!(block = block_number, "UC received ({}B)", uc.len());
                Ok(uc)
            }
            Err(rejection) => Err(anyhow::Error::new(rejection)),
        }
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn cbor_cert_req(req: &BlockCertReq) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(req, &mut buf)?;
    let mut val: ciborium::value::Value = ciborium::from_reader(&buf[..])?;
    if let ciborium::value::Value::Array(ref mut arr) = val {
        if arr.len() >= 4 {
            let ir = arr[3].clone();
            arr[3] = ciborium::value::Value::Tag(INPUT_RECORD_TAG, Box::new(ir));
        }
    }
    let mut out = Vec::new();
    ciborium::into_writer(&val, &mut out)?;
    Ok(out)
}

fn cbor_handshake(h: &Handshake) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(h, &mut buf)?;
    Ok(buf)
}

fn make_handshake_cbor(
    partition_id: u32,
    shard_id: &[u8],
    node_id: &str,
) -> anyhow::Result<Vec<u8>> {
    cbor_handshake(&Handshake {
        partition_id,
        shard_id: shard_id.to_vec(),
        node_id: node_id.to_string(),
    })
}

fn strip_tags(val: &ciborium::value::Value) -> ciborium::value::Value {
    match val {
        ciborium::value::Value::Tag(_, inner) => strip_tags(inner),
        ciborium::value::Value::Array(arr) => {
            ciborium::value::Value::Array(arr.iter().map(strip_tags).collect())
        }
        other => other.clone(),
    }
}

fn cbor_u64(val: &ciborium::value::Value) -> Option<u64> {
    match val {
        ciborium::value::Value::Integer(i) => (*i).try_into().ok(),
        _ => None,
    }
}

// ─── UC parsing ───────────────────────────────────────────────────────────────

/// Parse CertificationResponse CBOR → UcEvent (or None on parse error).
fn parse_uc(data: &[u8]) -> Option<UcEvent> {
    let val: ciborium::value::Value = ciborium::from_reader(data)
        .map_err(|e| error!("UC parse error: {e}"))
        .ok()?;
    let arr = match val {
        ciborium::value::Value::Array(a) => a,
        _ => {
            error!("UC not array");
            return None;
        }
    };
    if arr.len() < 4 {
        error!("UC array too short");
        return None;
    }

    if let Err(err) = validate_unicity_certificate_value(&arr[3]) {
        warn!(%err, "UC does not use the canonical certificate profile");
        return None;
    }

    // TechnicalRecord at index 2: [round, epoch, leader, stat_hash, fee_hash]
    let (next_round, epoch) = match strip_tags(&arr[2]) {
        ciborium::value::Value::Array(tr) if tr.len() >= 2 => {
            (cbor_u64(&tr[0]).unwrap_or(0), cbor_u64(&tr[1]).unwrap_or(0))
        }
        _ => {
            warn!("UC: bad TechnicalRecord");
            return None;
        }
    };

    // UC at index 3 — extract IR round_number and IR hash
    let uc_arr = match strip_tags(&arr[3]) {
        ciborium::value::Value::Array(a) => a,
        _ => {
            warn!("UC: bad UC value");
            return None;
        }
    };
    // UC structure: [version, input_record, tr_hash, ...]
    // InputRecord: [version, round_number, epoch, previous_hash, hash, summary, timestamp, block_hash, ...]
    let opt_bytes = |v: &ciborium::value::Value| match v {
        ciborium::value::Value::Bytes(b) => b.clone(),
        _ => Vec::new(),
    };
    let mut ir_bytes = Vec::new();
    let mut ir_prev = Vec::new();
    let mut ir_block = Vec::new();
    let (uc_round, uc_hash, input_record_timestamp) = if uc_arr.len() >= 2 {
        match strip_tags(&uc_arr[1]) {
            ciborium::value::Value::Array(ir) if ir.len() >= 8 => {
                let rnd = cbor_u64(&ir[1]).unwrap_or(0);
                let h = match &ir[4] {
                    ciborium::value::Value::Bytes(b) => Some(b.clone()),
                    _ => None,
                };
                let timestamp = cbor_u64(&ir[6]).unwrap_or(0);
                let _ = ciborium::into_writer(
                    &ciborium::value::Value::Array(ir.clone()),
                    &mut ir_bytes,
                );
                ir_prev = opt_bytes(&ir[3]);
                ir_block = opt_bytes(&ir[7]);
                (rnd, h, timestamp)
            }
            _ => (0, None, 0),
        }
    } else {
        (0, None, 0)
    };

    // Extract UnicitySeal.Timestamp from UC.
    // UC (toarray, blank _ field excluded):
    //   [Version, InputRecord, TRHash, ShardConfHash, ShardTreeCertificate, UnicityTreeCertificate, UnicitySeal]
    //   indices:  0           1       2               3                4                            5            6
    // UnicitySeal (toarray, blank _ field excluded):
    //   [Version, NetworkID, RootChainRoundNumber, Epoch, Timestamp, PreviousHash, Hash, Signatures]
    //   indices:  0          1          2                  3       4           5             6     7
    let timestamp = if uc_arr.len() >= 7 {
        match strip_tags(&uc_arr[6]) {
            ciborium::value::Value::Array(seal) if seal.len() >= 5 => {
                cbor_u64(&seal[4]).unwrap_or(0) // seal[4] = Timestamp
            }
            _ => 0,
        }
    } else {
        0
    };

    // Serialize UC element for storage/delivery
    let mut uc_cbor = Vec::new();
    let _ = ciborium::into_writer(&arr[3], &mut uc_cbor);

    // CertificationResponse (toarray): [Partition, Shard, Technical, UC, Status, Message]
    // Status/Message are transport-level fields, absent in older (4-elem) payloads.
    let status = arr.get(4).and_then(cbor_u64).map(|v| v as u32).unwrap_or(0);
    let message = match arr.get(5) {
        Some(ciborium::value::Value::Text(s)) => s.clone(),
        _ => String::new(),
    };

    let root_round = if uc_arr.len() >= 7 {
        match strip_tags(&uc_arr[6]) {
            ciborium::value::Value::Array(seal) if seal.len() >= 3 => {
                cbor_u64(&seal[2]).unwrap_or(0)
            }
            _ => 0,
        }
    } else {
        0
    };
    // The certificate's own partition (unicity tree certificate) and shard (shard tree certificate).
    let uc_partition = match uc_arr.get(5) {
        Some(ciborium::value::Value::Array(c)) => c.get(1).and_then(cbor_u64),
        _ => None,
    };
    let uc_shard = match uc_arr.get(4) {
        Some(ciborium::value::Value::Array(c)) => match c.get(1) {
            Some(ciborium::value::Value::Bytes(b)) => Some(b.clone()),
            _ => None,
        },
        _ => None,
    };
    let wrapper_partition = arr.first().and_then(cbor_u64);
    let wrapper_shard = match arr.get(1) {
        Some(ciborium::value::Value::Bytes(b)) => Some(b.clone()),
        _ => None,
    };
    let facts = UcFacts {
        root_round,
        uc_round,
        seal_timestamp: timestamp,
        ir_bytes,
        prev_hash: ir_prev,
        hash: uc_hash.clone().unwrap_or_default(),
        block_hash: ir_block,
    };

    Some(UcEvent {
        wrapper_partition,
        wrapper_shard,
        uc_partition,
        uc_shard,
        facts,
        uc_round,
        next_round,
        epoch,
        prev_hash: uc_hash,
        input_record_timestamp,
        timestamp,
        uc_cbor,
        status,
        message,
    })
}

// ─── Certification-response intake ───────────────────────────────────────────
//
// Trust model: the configured BFT Core root peer is fully trusted (transport intake hardening,
// not quorum authentication). The peer is pinned by its noise identity; there is no unicity seal
// verification, no trust base and no authority rotation. What this layer does is keep everybody
// else away from the parser and from state, bound what the pinned peer can cost, and refuse
// certificates that are inconsistent with the context and with the previously accepted one.

/// Frames per second and burst accepted on the UC protocol (token bucket). A root sends about one
/// certificate per root round, so this is far above honest traffic.
const INTAKE_RATE: f64 = 20.0;
const INTAKE_BURST: f64 = 40.0;
/// Concurrent inbound UC reads, and how long one read may take. Both bound what stalled bodies
/// can hold.
const MAX_CONCURRENT_UC_READS: usize = 4;
const UC_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// A repeated rejection is logged at most once per interval (with the number suppressed).
const DROP_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// Why an inbound certification response was not used.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum IntakeDrop {
    /// Sent by a peer other than the configured BFT Core root peer.
    NotAdmitted,
    /// Over the frame quota (refused before the frame was read).
    RateLimited,
    /// Too many reads in flight (refused before the frame was read).
    Busy,
    /// Not a well-formed certification response.
    Malformed,
    /// The wrapper or the certificate itself is not for the configured partition and shard, or
    /// does not state them in the exact valid representation.
    WrongContext,
    /// Root round behind the last accepted certificate.
    StaleRootRound,
    /// Partition round behind the last accepted certificate.
    OlderPartitionRound,
    /// Same partition round with a different input record.
    Equivocation,
    /// Consecutive partition round that does not extend the previous state hash.
    NotExtending,
    /// Block hash inconsistent with the state transition (or repeating the previous block).
    BlockHash,
    /// Seal timestamp (the reference time) went backwards.
    TimeRegression,
}

/// Rate-limits a repeated log line.
#[derive(Debug, Default)]
struct LogThrottle {
    last: Mutex<Option<std::time::Instant>>,
    suppressed: AtomicU64,
}

impl LogThrottle {
    /// `Some(n)` when the caller may log now (n lines were suppressed since the last one).
    fn hit(&self, now: std::time::Instant) -> Option<u64> {
        let mut last = self.last.lock().unwrap_or_else(|p| p.into_inner());
        if last.is_some_and(|t| now.saturating_duration_since(t) < DROP_LOG_INTERVAL) {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        *last = Some(now);
        Some(self.suppressed.swap(0, Ordering::Relaxed))
    }
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    refilled: std::time::Instant,
}

/// Admission of an inbound UC stream, decided before a single byte of the frame is read: the
/// shared frame quota, then a bounded number of concurrent reads, each with a deadline. It is
/// shared by every connection of the UC protocol (all of them are the pinned root's).
#[derive(Debug)]
struct ReadGuard {
    bucket: Mutex<Bucket>,
    permits: Arc<tokio::sync::Semaphore>,
    timeout: std::time::Duration,
    throttle: LogThrottle,
}

impl ReadGuard {
    fn new(concurrent: usize, timeout: std::time::Duration) -> Self {
        Self {
            bucket: Mutex::new(Bucket {
                tokens: INTAKE_BURST,
                refilled: std::time::Instant::now(),
            }),
            permits: Arc::new(tokio::sync::Semaphore::new(concurrent)),
            timeout,
            throttle: LogThrottle::default(),
        }
    }

    fn admit(
        &self,
        now: std::time::Instant,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, IntakeDrop> {
        {
            let mut b = self.bucket.lock().unwrap_or_else(|p| p.into_inner());
            let elapsed = now.saturating_duration_since(b.refilled).as_secs_f64();
            b.refilled = now;
            b.tokens = (b.tokens + elapsed * INTAKE_RATE).min(INTAKE_BURST);
            if b.tokens < 1.0 {
                return Err(IntakeDrop::RateLimited);
            }
            b.tokens -= 1.0;
        }
        Arc::clone(&self.permits)
            .try_acquire_owned()
            .map_err(|_| IntakeDrop::Busy)
    }
}

/// What the sequence rules need of one accepted certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UcFacts {
    root_round: u64,
    uc_round: u64,
    seal_timestamp: u64,
    /// The input record, re-encoded (identity comparison of equal-round certificates).
    ir_bytes: Vec<u8>,
    prev_hash: Vec<u8>,
    hash: Vec<u8>,
    block_hash: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Verdict {
    /// Newer than the last accepted certificate: it is now the last accepted one.
    Advance,
    /// The same root round again: a duplicate delivery, nothing to do.
    Duplicate,
}

/// Admission and sequencing of inbound certification responses. Everything a response may change
/// (the working context, the reference time, the liveness timer) happens only for a response that
/// passed this gate.
struct UcIntake {
    root_peer: PeerId,
    partition_id: u32,
    shard_id: Vec<u8>,
    last: Option<UcFacts>,
}

impl UcIntake {
    fn new(root_peer: PeerId, partition_id: u32, shard_id: Vec<u8>) -> Self {
        Self {
            root_peer,
            partition_id,
            shard_id,
            last: None,
        }
    }

    fn is_root(&self, peer: &PeerId) -> bool {
        *peer == self.root_peer
    }

    /// Fails closed: the wrapper and the certificate must both state the configured partition
    /// and shard, each in its exact valid representation (a missing or wrong-typed field is a
    /// rejection, not a pass).
    fn check_context(&self, ev: &UcEvent) -> Result<(), IntakeDrop> {
        let partition = u64::from(self.partition_id);
        let ok = ev.wrapper_partition == Some(partition)
            && ev.uc_partition == Some(partition)
            && ev.wrapper_shard.as_deref() == Some(self.shard_id.as_slice())
            && ev.uc_shard.as_deref() == Some(self.shard_id.as_slice());
        if ok {
            Ok(())
        } else {
            Err(IntakeDrop::WrongContext)
        }
    }

    /// The certificate sequence rules of aggregator-go (`CheckNonEquivocatingCertificates`, then
    /// duplicate detection), plus a non-regressing reference time. The intake state changes only
    /// on `Advance`.
    fn sequence(&mut self, new: &UcFacts) -> Result<Verdict, IntakeDrop> {
        let Some(prev) = &self.last else {
            self.last = Some(new.clone());
            return Ok(Verdict::Advance);
        };
        if new.root_round < prev.root_round {
            return Err(IntakeDrop::StaleRootRound);
        }
        if new.uc_round < prev.uc_round {
            return Err(IntakeDrop::OlderPartitionRound);
        }
        if new.uc_round == prev.uc_round {
            // a repeat certificate: the input record must be identical
            if new.ir_bytes != prev.ir_bytes {
                return Err(IntakeDrop::Equivocation);
            }
        } else {
            if new.uc_round == prev.uc_round + 1 && new.prev_hash != prev.hash {
                return Err(IntakeDrop::NotExtending);
            }
            let extends = new.prev_hash == prev.hash;
            if extends && new.hash == new.prev_hash && !new.block_hash.is_empty() {
                return Err(IntakeDrop::BlockHash); // unchanged state, but a block
            }
            if extends && new.hash != new.prev_hash && new.block_hash.is_empty() {
                return Err(IntakeDrop::BlockHash); // changed state, but no block
            }
            if !new.block_hash.is_empty() && new.block_hash == prev.block_hash {
                return Err(IntakeDrop::BlockHash); // a block hash repeats only in a repeat
            }
        }
        if new.seal_timestamp < prev.seal_timestamp {
            return Err(IntakeDrop::TimeRegression);
        }
        if new.root_round == prev.root_round {
            return Ok(Verdict::Duplicate);
        }
        self.last = Some(new.clone());
        Ok(Verdict::Advance)
    }
}

/// The state a certification response may change, and the handler that changes it. Separate from
/// the swarm so that the handler and the resulting state can be tested directly.
struct UcSession {
    intake: UcIntake,
    shared: Arc<Shared>,
    /// Cert request currently in flight (awaiting UC from BFT Core).
    pending: Option<PendingCert>,
    /// Single source of truth for building the next cert request: the last accepted certificate.
    last_uc: Option<LastUc>,
    /// Last time an authenticated certificate advanced the root round.
    last_uc_time: std::time::Instant,
    partition_id: u32,
    shard_id: Vec<u8>,
    node_id: String,
    sig_key: SecretKey,
    secp: Secp256k1<secp256k1::All>,
    fake_state_transitions: bool,
    throttle: LogThrottle,
}

impl UcSession {
    fn new(
        intake: UcIntake,
        shared: Arc<Shared>,
        node_id: String,
        sig_key: SecretKey,
        fake_state_transitions: bool,
    ) -> Self {
        Self {
            partition_id: intake.partition_id,
            shard_id: intake.shard_id.clone(),
            intake,
            shared,
            pending: None,
            last_uc: None,
            last_uc_time: std::time::Instant::now(),
            node_id,
            sig_key,
            secp: Secp256k1::new(),
            fake_state_transitions,
            throttle: LogThrottle::default(),
        }
    }

    fn dropped(&self, peer: &PeerId, why: IntakeDrop, now: std::time::Instant) {
        if let Some(suppressed) = self.throttle.hit(now) {
            warn!(%peer, ?why, suppressed, "certification response dropped");
        }
    }

    /// Handle one inbound certification response. Returns a cert request to (re)send, if any.
    ///
    /// Order: peer, parse, context, sequence; only then state. Certified state (the working
    /// context, the reference time, the liveness timer) advances only on a newer certificate; a
    /// rejection (`status != 0`) is applied to the request in flight only when the certificate
    /// it wraps is itself current, so a delayed or replayed rejection changes nothing.
    fn handle_uc(
        &mut self,
        peer: &PeerId,
        frame: &[u8],
        now: std::time::Instant,
    ) -> Option<Vec<u8>> {
        let mut resend: Option<Vec<u8>> = None;
        if !self.intake.is_root(peer) {
            self.dropped(peer, IntakeDrop::NotAdmitted, now);
            return None;
        }
        let Some(ev) = parse_uc(frame) else {
            self.dropped(peer, IntakeDrop::Malformed, now);
            return None;
        };
        if let Err(why) = self.intake.check_context(&ev) {
            self.dropped(peer, why, now);
            return None;
        }
        let verdict = match self.intake.sequence(&ev.facts) {
            Ok(v) => v,
            Err(why) => {
                self.dropped(peer, why, now);
                return None;
            }
        };
        if verdict == Verdict::Duplicate && ev.status == 0 {
            debug!(root_round = ev.facts.root_round, "duplicate UC");
            return None;
        }
        info!(
            uc_round = ev.uc_round,
            next_round = ev.next_round,
            epoch = ev.epoch,
            status = ev.status,
            "UC received from BFT Core"
        );

        if verdict == Verdict::Advance {
            self.last_uc_time = now;
            self.last_uc = Some(LastUc {
                next_round: ev.next_round,
                epoch: ev.epoch,
                prev_hash: ev.prev_hash.clone(),
                timestamp: ev.timestamp,
            });
            self.shared
                .reference_time
                .store(ev.timestamp, Ordering::Release);
            self.shared.reference_time_tx.send_replace(ev.timestamp);
        }

        // Typed rejection from BFT Core: the wrapped UC is the last-good
        // certificate, and `status`/`message` tell us why our request was
        // refused.
        //
        // Special case: RequestInvalid (status=2) with an advanced next_round
        // means BFT Core moved to a new round before our cert request arrived.
        // Re-send with the correct round rather than forcing a rollback — this
        // avoids discarding an already-computed (and possibly expensive) ZK proof.
        if ev.status != 0 {
            let is_stale_round = ev.status == 2
                && self
                    .pending
                    .as_ref()
                    .map_or(false, |p| ev.next_round > p.round_used);

            if is_stale_round {
                let current_reference_time = self.last_uc.as_ref().unwrap().timestamp;
                let pinned_reference_time = self.pending.as_ref().unwrap().reference_time;
                if pinned_reference_time != current_reference_time {
                    let p = self.pending.take().unwrap();
                    let _ = p.uc_tx.send(Err(reference_time_changed(
                        pinned_reference_time,
                        current_reference_time,
                    )));
                    return resend;
                }
                let p = self.pending.as_mut().unwrap();
                let old_round = p.round_used;
                let new_round = ev.next_round;
                p.round_used = new_round;
                let lu = self.last_uc.as_ref().unwrap();
                let prev_hash_ir = if self.fake_state_transitions {
                    lu.prev_hash.clone()
                } else if p.prev_hash.iter().all(|&b| b == 0) {
                    None
                } else {
                    Some(p.prev_hash.clone())
                };
                match make_cert_cbor(
                    p,
                    new_round,
                    lu.epoch,
                    prev_hash_ir,
                    self.partition_id,
                    &self.shard_id,
                    &self.node_id,
                    &self.secp,
                    &self.sig_key,
                ) {
                    Ok(cbor) => {
                        warn!(
                            old_round,
                            new_round,
                            "round mismatch rejection — re-sending cert request with correct round"
                        );
                        resend = Some(cbor);
                    }
                    Err(e) => {
                        error!("failed to rebuild cert req after round mismatch: {e}");
                    }
                }
                return resend;
            }

            warn!(
                status = ev.status,
                message = %ev.message,
                our_round = self.pending.as_ref().map(|p| p.round_used),
                uc_round = ev.uc_round,
                "BFT Core rejected certification request"
            );
            if let Some(p) = self.pending.take() {
                let rejection = CertRejection {
                    status: CertStatus::from_u32(ev.status),
                    raw_status: ev.status,
                    message: ev.message.clone(),
                };
                let _ = p.uc_tx.send(Err(rejection));
            }
            return resend;
        }

        // Handle pending cert request.
        if let Some(ref mut p) = self.pending {
            if ev.uc_round > 0 && ev.uc_round == p.round_used {
                if ev.input_record_timestamp != p.reference_time {
                    let pinned_reference_time = p.reference_time;
                    let certified_reference_time = ev.input_record_timestamp;
                    let p = self.pending.take().unwrap();
                    let _ = p.uc_tx.send(Err(reference_time_changed(
                        pinned_reference_time,
                        certified_reference_time,
                    )));
                    return resend;
                }
                // Our cert request was certified.
                info!(round = ev.uc_round, "UC matched — cert request certified");
                let p = self.pending.take().unwrap();
                let _ = p.uc_tx.send(Ok(ev.uc_cbor));
            } else if ev.uc_round > 0 && ev.uc_round > p.round_used {
                // A higher partition round was certified — our request
                // was superseded (should not happen in single-aggregator setup).
                warn!(
                    our_round = p.round_used,
                    uc_round = ev.uc_round,
                    "pending cert superseded — dropping"
                );
                let p = self.pending.take().unwrap();
                drop(p);
            } else if ev.next_round > p.round_used {
                // Repeat UC with an advanced partition round —
                // BFT Core timed us out.
                // Re-send the same cert request with the new round number.
                if p.reference_time != ev.timestamp {
                    let pinned_reference_time = p.reference_time;
                    let current_reference_time = ev.timestamp;
                    let p = self.pending.take().unwrap();
                    let _ = p.uc_tx.send(Err(reference_time_changed(
                        pinned_reference_time,
                        current_reference_time,
                    )));
                    return resend;
                }
                let old_round = p.round_used;
                let new_round = ev.next_round;
                p.round_used = new_round;

                let lu = self.last_uc.as_ref().unwrap();
                let prev_hash_ir = if self.fake_state_transitions {
                    lu.prev_hash.clone()
                } else if p.prev_hash.iter().all(|&b| b == 0) {
                    None
                } else {
                    Some(p.prev_hash.clone())
                };

                match make_cert_cbor(
                    p,
                    new_round,
                    lu.epoch,
                    prev_hash_ir,
                    self.partition_id,
                    &self.shard_id,
                    &self.node_id,
                    &self.secp,
                    &self.sig_key,
                ) {
                    Ok(cbor) => {
                        info!(
                            old_round,
                            new_round, "repeat UC advanced round — re-sending cert request"
                        );
                        resend = Some(cbor);
                    }
                    Err(e) => {
                        error!("failed to rebuild cert req on round advance: {e}");
                    }
                }
            } else {
                // Repeat UC at same round — still waiting.
                debug!(
                    our_round = p.round_used,
                    uc_round = ev.uc_round,
                    next_round = ev.next_round,
                    "repeat UC while cert pending — still waiting"
                );
            }
        }

        resend
    }
}

// ─── Network loop ─────────────────────────────────────────────────────────────

/// Build, sign and return the CBOR for a cert request using the given round/epoch/prev_hash.
/// Build a signed cert request CBOR.
/// `prev_hash_ir` = the last certified state hash from BFT Core (None = initial genesis state).
fn make_cert_cbor(
    pending: &PendingCert,
    round: u64,
    epoch: u64,
    prev_hash_ir: Option<Vec<u8>>,
    partition_id: u32,
    shard_id: &[u8],
    node_id: &str,
    secp: &Secp256k1<secp256k1::All>,
    sig_key: &SecretKey,
) -> anyhow::Result<Vec<u8>> {
    // State changed = new hash differs from the PreviousHash we're sending.
    let state_changed = match &prev_hash_ir {
        Some(ph) => pending.new_hash != *ph,
        None => true, // first block (genesis) — state is always "new"
    };
    let block_hash = if state_changed {
        Some(pending.new_hash.clone())
    } else {
        None
    };
    let ir = InputRecord {
        version: 1,
        round_number: round,
        epoch,
        previous_hash: prev_hash_ir,
        hash: Some(pending.new_hash.clone()),
        summary_value: Some(vec![]),
        timestamp: pending.reference_time,
        block_hash,
        sum_of_earned_fees: 0,
        et_hash: Some(vec![]),
    };
    let mut req = BlockCertReq {
        partition_id,
        shard_id: shard_id.to_vec(),
        node_id: node_id.to_string(),
        input_record: ir,
        zk_proof: pending.zk_proof.clone(),
        block_size: pending.block_size,
        state_size: pending.state_size,
        signature: None,
    };
    // Sign: compute digest of unsigned CBOR, then set signature
    req.signature = None;
    let raw = cbor_cert_req(&req)?;
    let hash: [u8; 32] = Sha256::digest(&raw).into();
    req.signature = Some(sign_recoverable(secp, sig_key, hash));
    cbor_cert_req(&req)
}

/// Sign a 32-byte digest as the 65-byte `r || s || v` recoverable signature that
/// bft-go-base's strict verifier requires (low-S is guaranteed by libsecp256k1, v is 0 or 1).
fn sign_recoverable(
    secp: &Secp256k1<secp256k1::All>,
    key: &SecretKey,
    digest: [u8; 32],
) -> Vec<u8> {
    let (rec_id, compact) = secp
        .sign_ecdsa_recoverable(&Message::from_digest(digest), key)
        .serialize_compact();
    let mut sig = Vec::with_capacity(65);
    sig.extend_from_slice(&compact);
    sig.push(rec_id.to_i32() as u8);
    sig
}

fn reference_time_changed(pinned: u64, current: u64) -> CertRejection {
    CertRejection {
        status: CertStatus::Transient,
        raw_status: CertStatus::Transient as u32,
        message: format!(
            "reference time changed from {pinned} to {current}; round must be rebuilt"
        ),
    }
}

async fn network_loop(
    mut swarm: Swarm<Behaviour>,
    mut cmd_rx: mpsc::Receiver<NetCmd>,
    shared: Arc<Shared>,
    bft_peer: PeerId,
    bft_addr: Multiaddr,
    partition_id: u32,
    shard_id: Vec<u8>,
    node_id: String,
    sig_key: SecretKey,
    fake_state_transitions: bool,
    uc_timeout_ms: u64,
) {
    let _ = swarm.dial(
        libp2p::swarm::dial_opts::DialOpts::unknown_peer_id()
            .address(bft_addr.clone())
            .allocate_new_port()
            .build(),
    );
    info!("Dialing BFT Core at {}", bft_addr);
    let mut hs_sent = false;
    // Reconnect timer: fires after a delay when a reconnect is needed.
    let mut reconnect_delay: Option<std::pin::Pin<Box<tokio::time::Sleep>>> = None;
    // BFT Core sends repeat UCs every T2 interval as a natural keepalive.
    // The heartbeat is a safety net: if repeat UCs stop arriving (e.g. silent
    // connection loss or subscription quota exhausted), re-send the handshake
    // to refresh the subscription.  The timeout must be well above T2 (default
    // 15s vs typical T2 of ~6s) so normal repeat-UC gaps don't trigger it.
    let inactivity_timeout = std::time::Duration::from_millis(uc_timeout_ms);
    let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(1));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Everything a certification response may change lives in the session: the cert request in
    // flight, the working context (`last_uc`), the reference time and the liveness timer.
    let mut core = UcSession::new(
        UcIntake::new(bft_peer, partition_id, shard_id.clone()),
        Arc::clone(&shared),
        node_id.clone(),
        sig_key,
        fake_state_transitions,
    );

    loop {
        // `biased` ensures swarm events (including incoming UCs) are always
        // drained before we accept a new Submit from the channel.  This
        // prevents using a stale round when multiple UCs are queued.
        tokio::select! {
            biased;

            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == bft_peer => {
                        reconnect_delay = None;
                        info!("Connected to BFT Core {}", peer_id);
                        if !hs_sent {
                            if let Ok(cbor) = make_handshake_cbor(partition_id, &shard_id, &node_id) {
                                swarm.behaviour_mut().hs.send_request(&peer_id, cbor);
                                hs_sent = true;
                                info!("Handshake sent, subscribed to UC feed");
                            }
                        }
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Uc(
                        request_response::Event::Message {
                            peer,
                            message: request_response::Message::Request { request, channel, .. },
                            ..
                        },
                    )) => {
                        // Only the root peer is answered (others cannot get here: their
                        // connections are denied, and their streams were refused before any read).
                        if core.intake.is_root(&peer) {
                            let _ = swarm.behaviour_mut().uc.send_response(channel, vec![]);
                        }
                        if let Some(cbor) = core.handle_uc(&peer, &request, std::time::Instant::now()) {
                            swarm.behaviour_mut().cert.send_request(&bft_peer, cbor);
                        }
                    }
                    SwarmEvent::ConnectionClosed { peer_id, cause, .. } if peer_id == bft_peer => {
                        warn!("BFT Core connection closed: {:?}", cause);
                        hs_sent = false;
                        reconnect_delay = Some(Box::pin(tokio::time::sleep(std::time::Duration::from_secs(2))));
                    }
                    SwarmEvent::OutgoingConnectionError { error, .. } => {
                        warn!("Connection error, will retry: {:?}", error);
                        reconnect_delay = Some(Box::pin(tokio::time::sleep(std::time::Duration::from_secs(3))));
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!("p2p listening on {}", address);
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Uc(
                        request_response::Event::InboundFailure { error, .. },
                    )) => {
                        warn!("UC inbound failure: {:?}", error);
                    }
                    // BFT Core uses fire-and-forget for cert and handshake protocols
                    // (closes the stream without sending a response).  The OutboundFailure
                    // is expected and harmless — the request was delivered.
                    SwarmEvent::Behaviour(BehaviourEvent::Cert(
                        request_response::Event::OutboundFailure { error, .. },
                    )) => {
                        debug!("cert outbound failure (expected — fire-and-forget): {:?}", error);
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Hs(
                        request_response::Event::OutboundFailure { error, .. },
                    )) => {
                        debug!("handshake outbound failure (expected — fire-and-forget): {:?}", error);
                    }
                    _ => {}
                }
            }
            // Reconnect timer.
            () = async {
                match reconnect_delay.as_mut() {
                    Some(d) => d.await,
                    None => std::future::pending().await,
                }
            } => {
                reconnect_delay = None;
                info!("Reconnecting to BFT Core at {}", bft_addr);
                let _ = swarm.dial(
                    libp2p::swarm::dial_opts::DialOpts::unknown_peer_id()
                        .address(bft_addr.clone())
                        .allocate_new_port()
                        .build(),
                );
            }
            // Heartbeat: re-subscribe if no UC received within inactivity timeout.
            _ = heartbeat.tick() => {
                if hs_sent && core.last_uc_time.elapsed() > inactivity_timeout {
                    warn!(
                        idle_secs = core.last_uc_time.elapsed().as_secs(),
                        "UC inactivity timeout — re-sending handshake"
                    );
                    if let Ok(cbor) = make_handshake_cbor(partition_id, &shard_id, &node_id) {
                        swarm.behaviour_mut().hs.send_request(&bft_peer, cbor);
                        core.last_uc_time = std::time::Instant::now();
                    }
                }
            }
            // Accept a new Submit only when no cert request is in flight.
            // `biased` above guarantees all pending UCs are drained first,
            // so `last_uc` holds the freshest state.
            Some(cmd) = cmd_rx.recv(), if core.pending.is_none() => {
                match cmd {
                    NetCmd::Submit(data) => {
                        let lu = match &core.last_uc {
                            Some(lu) => lu,
                            None => {
                                error!("Submit received but no UC available — dropping");
                                continue;
                            }
                        };

                        if data.reference_time != lu.timestamp {
                            warn!(
                                pinned_reference_time = data.reference_time,
                                current_reference_time = lu.timestamp,
                                "queued round reference time is stale; rebuilding required"
                            );
                            let _ = data.uc_tx.send(Err(reference_time_changed(
                                data.reference_time,
                                lu.timestamp,
                            )));
                            continue;
                        }

                        let round = lu.next_round;

                        // Check whether our SMT root matches what BFT Core certified.
                        // An all-zeros SMT root (empty tree) is semantically nil —
                        // BFT Core genesis UC has prev_hash = None.
                        let smt_prev = if data.prev_hash.iter().all(|&b| b == 0) {
                            None
                        } else {
                            Some(data.prev_hash.clone())
                        };
                        if smt_prev != lu.prev_hash {
                            let smt_hex = hex::encode(&data.prev_hash);
                            let uc_hex = lu.prev_hash.as_ref()
                                .map(|h| hex::encode(h))
                                .unwrap_or_else(|| "nil".to_string());
                            if fake_state_transitions {
                                warn!(
                                    smt_prev = %smt_hex, uc_prev = %uc_hex,
                                    "PreviousHash mismatch — using UC hash (fake-state-transitions)"
                                );
                            } else {
                                error!(
                                    smt_prev = %smt_hex, uc_prev = %uc_hex,
                                    "PreviousHash mismatch — SMT root diverged from certified chain, cert request will fail"
                                );
                            }
                        }

                        // In real mode, PreviousHash = aggregator's actual previous
                        // SMT root — it MUST form a continuous chain with BFT Core.
                        // In fake mode, PreviousHash = luc.InputRecord.Hash (whatever
                        // BFT Core last certified), allowing divergent state.
                        let prev_hash_ir = if fake_state_transitions {
                            lu.prev_hash.clone()
                        } else {
                            smt_prev
                        };

                        let p = PendingCert {
                            new_hash: data.new_hash,
                            prev_hash: data.prev_hash,
                            zk_proof: data.zk_proof,
                            block_size: data.block_size,
                            state_size: data.state_size,
                            reference_time: data.reference_time,
                            uc_tx: data.uc_tx,
                            round_used: round,
                        };

                        match make_cert_cbor(&p, round, lu.epoch, prev_hash_ir,
                                             partition_id, &shard_id, &node_id, &core.secp, &core.sig_key) {
                            Ok(cbor) => {
                                info!(round, "sending cert request to BFT Core");
                                core.pending = Some(p);
                                swarm.behaviour_mut().cert.send_request(&bft_peer, cbor);
                            }
                            Err(e) => {
                                error!("failed to build cert req: {e}");
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certification_request_uses_the_canonical_input_record_tag() {
        let request = BlockCertReq {
            partition_id: 1,
            shard_id: vec![0x80],
            node_id: "NODE".into(),
            input_record: InputRecord {
                version: 1,
                round_number: 2,
                epoch: 0,
                previous_hash: None,
                hash: Some(vec![0x11; 32]),
                summary_value: Some(vec![]),
                timestamp: 3,
                block_hash: Some(vec![0x11; 32]),
                sum_of_earned_fees: 0,
                et_hash: None,
            },
            zk_proof: None,
            block_size: 1,
            state_size: 1,
            signature: None,
        };

        let encoded = cbor_cert_req(&request).unwrap();
        let value: ciborium::Value = ciborium::from_reader(encoded.as_slice()).unwrap();
        let ciborium::Value::Array(fields) = value else {
            panic!("certification request must be an array")
        };
        assert!(matches!(
            fields.get(3),
            Some(ciborium::Value::Tag(INPUT_RECORD_TAG, _))
        ));
    }

    #[test]
    fn certification_request_uses_the_pinned_reference_time() {
        let (uc_tx, _uc_rx) = oneshot::channel();
        let pending = PendingCert {
            new_hash: vec![0x11; 32],
            prev_hash: vec![0x22; 32],
            zk_proof: None,
            block_size: 1,
            state_size: 1,
            reference_time: 1_755_000_000,
            uc_tx,
            round_used: 2,
        };
        let secp = Secp256k1::new();
        let signing_key = SecretKey::from_slice(&[7; 32]).unwrap();

        let encoded = make_cert_cbor(
            &pending,
            2,
            0,
            Some(vec![0x22; 32]),
            1,
            &[0x80],
            "NODE",
            &secp,
            &signing_key,
        )
        .unwrap();
        let request: BlockCertReq = ciborium::from_reader(encoded.as_slice()).unwrap();

        assert_eq!(request.input_record.timestamp, pending.reference_time);
    }

    #[test]
    fn configured_shard_is_signed_in_certification_request() {
        let secp = Secp256k1::new();
        let signing_key = SecretKey::from_slice(&[7; 32]).unwrap();
        let (uc_tx, _uc_rx) = oneshot::channel();
        let pending = PendingCert {
            new_hash: vec![0x11; 32],
            prev_hash: vec![0x22; 32],
            zk_proof: None,
            block_size: 1,
            state_size: 1,
            reference_time: 1_755_000_000,
            uc_tx,
            round_used: 2,
        };
        for shard_id in [[0x80], [0x40], [0xc0]] {
            let encoded = make_cert_cbor(
                &pending,
                2,
                0,
                Some(vec![0x22; 32]),
                1,
                &shard_id,
                "NODE",
                &secp,
                &signing_key,
            )
            .unwrap();
            let mut request: BlockCertReq = ciborium::from_reader(encoded.as_slice()).unwrap();
            assert_eq!(request.shard_id, shard_id);
            let sig = request.signature.clone().unwrap();
            assert_eq!(sig.len(), 65);
            assert!(sig[64] <= 1, "v must be 0 or 1");
            let recoverable = secp256k1::ecdsa::RecoverableSignature::from_compact(
                &sig[..64],
                secp256k1::ecdsa::RecoveryId::from_i32(sig[64] as i32).unwrap(),
            )
            .unwrap();
            // low-S: normalizing must be a no-op
            let mut normalized = recoverable.to_standard();
            let before = normalized.serialize_compact();
            normalized.normalize_s();
            assert_eq!(
                before,
                normalized.serialize_compact(),
                "signature must be low-S"
            );
            request.signature = None;
            let digest: [u8; 32] = Sha256::digest(cbor_cert_req(&request).unwrap()).into();
            let recovered = secp
                .recover_ecdsa(&Message::from_digest(digest), &recoverable)
                .unwrap();
            assert_eq!(
                recovered,
                secp256k1::PublicKey::from_secret_key(&secp, &signing_key)
            );
        }
    }

    #[test]
    fn configured_shard_is_used_for_initial_reconnect_and_refresh_handshakes() {
        for shard_id in [[0x80], [0x40], [0xc0]] {
            let initial = make_handshake_cbor(1, &shard_id, "NODE").unwrap();
            let reconnect = make_handshake_cbor(1, &shard_id, "NODE").unwrap();
            let refresh = make_handshake_cbor(1, &shard_id, "NODE").unwrap();
            assert_eq!(initial, reconnect);
            assert_eq!(initial, refresh);
            let handshake: Handshake = ciborium::from_reader(initial.as_slice()).unwrap();
            assert_eq!(handshake.shard_id, shard_id);
        }
    }

    // ─── intake: fixtures ────────────────────────────────────────────────────

    use crate::api::cbor::{decode_cbor_value, encode_cbor_value, test_uc_cbor};
    use ciborium::value::Value;
    use std::time::{Duration, Instant};

    fn uint(v: u64) -> Value {
        Value::Integer(v.into())
    }

    fn opt32(o: Option<[u8; 32]>) -> Value {
        o.map(|b| Value::Bytes(b.to_vec())).unwrap_or(Value::Null)
    }

    /// One certification response, field by field (so a test can break exactly one of them).
    #[derive(Clone)]
    struct Spec {
        wrapper_partition: Value,
        wrapper_shard: Value,
        uc_partition: u64,
        uc_shard: Vec<u8>,
        uc_round: u64,
        root_round: u64,
        timestamp: u64,
        prev: Option<[u8; 32]>,
        hash: Option<[u8; 32]>,
        block: Option<[u8; 32]>,
        next_round: u64,
        status: u64,
    }

    impl Spec {
        /// A consistent certificate for partition round `uc_round` (state hash `[uc_round; 32]`
        /// extending `[uc_round - 1; 32]`, a block hash of its own).
        fn new(uc_round: u64, root_round: u64) -> Self {
            Spec {
                wrapper_partition: uint(7),
                wrapper_shard: Value::Bytes(vec![0x80]),
                uc_partition: 7,
                uc_shard: vec![0x80],
                uc_round,
                root_round,
                timestamp: 1000,
                prev: (uc_round > 0).then(|| [uc_round as u8 - 1; 32]),
                hash: Some([uc_round as u8; 32]),
                block: Some([100 + uc_round as u8; 32]),
                next_round: uc_round + 1,
                status: 0,
            }
        }

        fn frame(&self) -> Vec<u8> {
            let mut uc =
                decode_cbor_value(&test_uc_cbor(Some([1; 32]), &self.uc_shard, 0)).unwrap();
            {
                let Value::Tag(_, inner) = &mut uc else {
                    panic!()
                };
                let Value::Array(f) = &mut **inner else {
                    panic!()
                };
                {
                    let Value::Tag(_, ir) = &mut f[1] else {
                        panic!()
                    };
                    let Value::Array(g) = &mut **ir else { panic!() };
                    g[1] = uint(self.uc_round);
                    g[3] = opt32(self.prev);
                    g[4] = opt32(self.hash);
                    g[6] = uint(self.timestamp);
                    g[7] = opt32(self.block);
                }
                {
                    let Value::Tag(_, tree) = &mut f[5] else {
                        panic!()
                    };
                    let Value::Array(t) = &mut **tree else {
                        panic!()
                    };
                    t[1] = uint(self.uc_partition);
                }
                {
                    let Value::Tag(_, seal) = &mut f[6] else {
                        panic!()
                    };
                    let Value::Array(t) = &mut **seal else {
                        panic!()
                    };
                    t[2] = uint(self.root_round);
                    t[4] = uint(self.timestamp);
                }
            }
            let technical = Value::Array(vec![
                uint(self.next_round),
                uint(0),
                Value::Text("leader".into()),
                Value::Null,
                Value::Null,
            ]);
            encode_cbor_value(&Value::Array(vec![
                self.wrapper_partition.clone(),
                self.wrapper_shard.clone(),
                technical,
                uc,
                uint(self.status),
                Value::Text(if self.status == 0 { "" } else { "refused" }.into()),
            ]))
            .unwrap()
        }
    }

    fn session() -> (UcSession, PeerId, Arc<Shared>) {
        let root = PeerId::random();
        let (reference_time_tx, _) = watch::channel(0);
        let shared = Arc::new(Shared {
            blk_receivers: Mutex::new(HashMap::new()),
            reference_time: AtomicU64::new(0),
            reference_time_tx,
        });
        let session = UcSession::new(
            UcIntake::new(root, 7, vec![0x80]),
            Arc::clone(&shared),
            "NODE".into(),
            SecretKey::from_slice(&[7; 32]).unwrap(),
            false,
        );
        (session, root, shared)
    }

    fn pending(
        round_used: u64,
        reference_time: u64,
    ) -> (PendingCert, oneshot::Receiver<UcOutcome>) {
        let (uc_tx, uc_rx) = oneshot::channel();
        (
            PendingCert {
                new_hash: vec![0x55; 32],
                prev_hash: vec![0x33; 32],
                zk_proof: None,
                block_size: 1,
                state_size: 1,
                reference_time,
                uc_tx,
                round_used,
            },
            uc_rx,
        )
    }

    /// The observable state a response may change.
    fn snapshot(s: &UcSession, shared: &Shared) -> (Option<(u64, u64, u64)>, u64, Instant, bool) {
        (
            s.last_uc
                .as_ref()
                .map(|l| (l.next_round, l.epoch, l.timestamp)),
            shared.reference_time.load(Ordering::Acquire),
            s.last_uc_time,
            s.pending.is_some(),
        )
    }

    // ─── intake: the event handler and the resulting state ──────────────────

    #[test]
    fn a_frame_from_another_peer_changes_nothing() {
        let (mut s, _, shared) = session();
        let before = snapshot(&s, &shared);
        let out = s.handle_uc(
            &PeerId::random(),
            &Spec::new(50, 100).frame(),
            Instant::now(),
        );
        assert!(out.is_none());
        assert_eq!(snapshot(&s, &shared), before);
        assert!(s.intake.last.is_none());
    }

    #[test]
    fn a_first_certificate_sets_the_context_the_reference_time_and_liveness() {
        let (mut s, root, shared) = session();
        let t = Instant::now() + Duration::from_secs(5);
        s.handle_uc(&root, &Spec::new(50, 100).frame(), t);
        assert_eq!(snapshot(&s, &shared).0, Some((51, 0, 1000)));
        assert_eq!(shared.reference_time.load(Ordering::Acquire), 1000);
        assert_eq!(s.last_uc_time, t);
    }

    #[test]
    fn context_fails_closed_on_the_wrapper_and_on_the_certificate() {
        let breaks: Vec<(&str, Box<dyn Fn(&mut Spec)>)> = vec![
            (
                "null partition",
                Box::new(|s| s.wrapper_partition = Value::Null),
            ),
            (
                "text partition",
                Box::new(|s| s.wrapper_partition = Value::Text("7".into())),
            ),
            (
                "overflowing partition",
                Box::new(|s| s.wrapper_partition = uint(7 + (1 << 32))),
            ),
            (
                "wrong partition",
                Box::new(|s| s.wrapper_partition = uint(8)),
            ),
            ("null shard", Box::new(|s| s.wrapper_shard = Value::Null)),
            ("integer shard", Box::new(|s| s.wrapper_shard = uint(0x80))),
            (
                "wrong shard",
                Box::new(|s| s.wrapper_shard = Value::Bytes(vec![0x40])),
            ),
            // the wrapper names the configured context, the certificate inside is another one
            (
                "certificate of another partition",
                Box::new(|s| s.uc_partition = 8),
            ),
            (
                "certificate of another shard",
                Box::new(|s| s.uc_shard = vec![0x40]),
            ),
        ];
        for (name, brk) in breaks {
            let (mut s, root, shared) = session();
            let before = snapshot(&s, &shared);
            let mut spec = Spec::new(50, 100);
            brk(&mut spec);
            let (p, mut rx) = pending(51, 1000);
            s.pending = Some(p);
            let before_pending = (before.0, before.1, before.2);
            assert!(
                s.handle_uc(&root, &spec.frame(), Instant::now()).is_none(),
                "{name}"
            );
            let after = snapshot(&s, &shared);
            assert_eq!((after.0, after.1, after.2), before_pending, "{name}");
            assert!(
                s.intake.last.is_none(),
                "{name}: the sequence watermark did not move"
            );
            assert!(
                rx.try_recv().is_err(),
                "{name}: the request in flight is untouched"
            );
        }
    }

    #[test]
    fn a_duplicate_delivery_is_idempotent() {
        let (mut s, root, shared) = session();
        let t = Instant::now();
        let frame = Spec::new(50, 100).frame();
        s.handle_uc(&root, &frame, t);
        let after_first = snapshot(&s, &shared);
        let (p, mut rx) = pending(51, 1000);
        s.pending = Some(p);
        assert!(s
            .handle_uc(&root, &frame, t + Duration::from_secs(9))
            .is_none());
        let after_second = snapshot(&s, &shared);
        assert_eq!(
            (after_second.0, after_second.1, after_second.2),
            (after_first.0, after_first.1, after_first.2)
        );
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn a_stale_rejection_does_not_roll_back_refresh_liveness_or_reject_the_current_request() {
        let (mut s, root, shared) = session();
        let t = Instant::now();
        s.handle_uc(&root, &Spec::new(50, 100).frame(), t);
        let (p, mut rx) = pending(51, 1000);
        s.pending = Some(p);
        let before = snapshot(&s, &shared);
        // a delayed rejection wrapping an old certificate (root round 5, an older time), many copies
        let mut stale = Spec::new(50, 5);
        stale.status = 3;
        stale.timestamp = 5;
        stale.next_round = 7;
        for k in 1..=30u64 {
            assert!(s
                .handle_uc(&root, &stale.frame(), t + Duration::from_secs(k))
                .is_none());
        }
        assert_eq!(
            snapshot(&s, &shared),
            before,
            "context, reference time and liveness unchanged"
        );
        assert!(
            rx.try_recv().is_err(),
            "the current request was not rejected by it"
        );
        assert_eq!(s.intake.last.as_ref().unwrap().root_round, 100);
    }

    #[test]
    fn a_non_advancing_rejection_is_applied_once_without_refreshing_liveness() {
        let (mut s, root, shared) = session();
        let t = Instant::now();
        s.handle_uc(&root, &Spec::new(50, 100).frame(), t);
        let (p, mut rx) = pending(51, 1000);
        s.pending = Some(p);
        // the root refuses our request (permanent) and wraps the current certificate
        let mut refusal = Spec::new(50, 100);
        refusal.status = 3;
        let before = snapshot(&s, &shared);
        s.handle_uc(&root, &refusal.frame(), t + Duration::from_secs(30));
        let outcome = rx
            .try_recv()
            .expect("the correlated rejection reaches the request");
        assert_eq!(outcome.unwrap_err().status, CertStatus::ProofInvalid);
        let after = snapshot(&s, &shared);
        assert_eq!((after.0, after.1, after.2), (before.0, before.1, before.2));
        assert!(!after.3, "the request is resolved");
    }

    #[test]
    fn an_advancing_rejection_carries_the_newer_certificate_it_wraps() {
        let (mut s, root, shared) = session();
        let t = Instant::now();
        s.handle_uc(&root, &Spec::new(50, 100).frame(), t);
        let mut refusal = Spec::new(50, 103);
        refusal.status = 1;
        refusal.timestamp = 1000;
        let t2 = t + Duration::from_secs(4);
        s.handle_uc(&root, &refusal.frame(), t2);
        assert_eq!(s.last_uc_time, t2, "a newer root round is genuine progress");
        assert_eq!(s.intake.last.as_ref().unwrap().root_round, 103);
        assert_eq!(shared.reference_time.load(Ordering::Acquire), 1000);
    }

    #[test]
    fn partition_round_order_is_enforced_before_any_mutation() {
        let (mut s, root, shared) = session();
        let t = Instant::now();
        s.handle_uc(&root, &Spec::new(50, 100).frame(), t);
        let before = snapshot(&s, &shared);
        // a higher root round carrying an older partition round
        assert!(s
            .handle_uc(
                &root,
                &Spec::new(49, 101).frame(),
                t + Duration::from_secs(3)
            )
            .is_none());
        assert_eq!(snapshot(&s, &shared), before);
        assert_eq!(s.intake.last.as_ref().unwrap().uc_round, 50);
    }

    #[test]
    fn equal_round_certificates_must_carry_the_same_input_record() {
        let (mut s, root, shared) = session();
        let t = Instant::now();
        s.handle_uc(&root, &Spec::new(50, 100).frame(), t);
        let before = snapshot(&s, &shared);
        for root_round in [100, 101] {
            let mut forged = Spec::new(50, root_round);
            forged.block = Some([0xee; 32]);
            assert!(s
                .handle_uc(&root, &forged.frame(), t + Duration::from_secs(3))
                .is_none());
            assert_eq!(snapshot(&s, &shared), before, "root round {root_round}");
        }
        assert_eq!(s.intake.last.as_ref().unwrap().block_hash, vec![150; 32]);
    }

    #[test]
    fn a_valid_timeout_repeat_advances_and_restarts_the_request_in_flight() {
        let (mut s, root, shared) = session();
        let t = Instant::now();
        s.handle_uc(&root, &Spec::new(50, 100).frame(), t);
        let (p, mut rx) = pending(51, 1000);
        s.pending = Some(p);
        // the same partition round again, a later root round, the next round to use is 52
        let mut repeat = Spec::new(50, 101);
        repeat.next_round = 52;
        let t2 = t + Duration::from_secs(2);
        let resend = s.handle_uc(&root, &repeat.frame(), t2);
        assert!(
            resend.is_some(),
            "the cert request is re-sent with the advanced round"
        );
        assert_eq!(s.pending.as_ref().unwrap().round_used, 52);
        assert_eq!(s.last_uc_time, t2);
        assert_eq!(snapshot(&s, &shared).0, Some((52, 0, 1000)));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn a_certificate_that_does_not_extend_the_state_or_regresses_the_time_is_dropped() {
        let t = Instant::now();
        let cases: Vec<(&str, Box<dyn Fn(&mut Spec)>)> = vec![
            (
                "does not extend the previous hash",
                Box::new(|s| s.prev = Some([9; 32])),
            ),
            (
                "changed state with an empty block",
                Box::new(|s| s.block = None),
            ),
            (
                "repeats the previous block hash",
                Box::new(|s| s.block = Some([150; 32])),
            ),
            ("time goes backwards", Box::new(|s| s.timestamp = 999)),
        ];
        for (name, brk) in cases {
            let (mut s, root, shared) = session();
            s.handle_uc(&root, &Spec::new(50, 100).frame(), t);
            let before = snapshot(&s, &shared);
            let mut next = Spec::new(51, 101);
            brk(&mut next);
            assert!(
                s.handle_uc(&root, &next.frame(), t + Duration::from_secs(2))
                    .is_none(),
                "{name}"
            );
            assert_eq!(snapshot(&s, &shared), before, "{name}");
        }
        // the consistent successor is accepted
        let (mut s, root, _) = session();
        s.handle_uc(&root, &Spec::new(50, 100).frame(), t);
        s.handle_uc(
            &root,
            &Spec::new(51, 101).frame(),
            t + Duration::from_secs(2),
        );
        assert_eq!(s.intake.last.as_ref().unwrap().uc_round, 51);
    }

    #[test]
    fn repeated_rejections_are_logged_at_most_once_per_interval() {
        let throttle = LogThrottle::default();
        let t = Instant::now();
        assert_eq!(throttle.hit(t), Some(0));
        for k in 1..=100 {
            assert_eq!(throttle.hit(t + Duration::from_millis(k)), None);
        }
        assert_eq!(throttle.hit(t + DROP_LOG_INTERVAL), Some(100));
    }

    // ─── intake: streams are refused before they are read ───────────────────

    /// A reader that delivers `data` and then never completes (a stalled sender).
    struct Stalled {
        data: Vec<u8>,
        pos: usize,
    }

    impl AsyncRead for Stalled {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut [u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if self.pos >= self.data.len() {
                return std::task::Poll::Pending;
            }
            let n = buf.len().min(self.data.len() - self.pos);
            let start = self.pos;
            buf[..n].copy_from_slice(&self.data[start..start + n]);
            self.pos += n;
            std::task::Poll::Ready(Ok(n))
        }
    }

    fn length_prefixed(payload: &[u8]) -> Vec<u8> {
        let mut buf = unsigned_varint::encode::u64_buffer();
        let mut v = unsigned_varint::encode::u64(payload.len() as u64, &mut buf).to_vec();
        v.extend_from_slice(payload);
        v
    }

    fn uc_codec(concurrent: usize, timeout: Duration) -> (BftCodec, Arc<ReadGuard>) {
        let guard = Arc::new(ReadGuard::new(concurrent, timeout));
        (
            BftCodec {
                guard: Some(Arc::clone(&guard)),
            },
            guard,
        )
    }

    #[tokio::test(start_paused = true)]
    async fn an_over_quota_stream_is_refused_without_reading_a_byte() {
        let (mut codec, guard) = uc_codec(4, Duration::from_secs(10));
        let proto = StreamProtocol::new(PROTO_UC);
        let frame = length_prefixed(&[1, 2, 3]);
        // honest traffic is served, and its permit is released
        let mut ok = futures::io::Cursor::new(frame.clone());
        assert_eq!(
            codec.read_request(&proto, &mut ok).await.unwrap(),
            vec![1, 2, 3]
        );
        assert_eq!(guard.permits.available_permits(), 4);
        // exhaust the burst
        for _ in 0..INTAKE_BURST as usize {
            let _ = guard.admit(Instant::now());
        }
        let mut over = futures::io::Cursor::new(frame.clone());
        let err = codec.read_request(&proto, &mut over).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(over.position(), 0, "nothing was read from the stream");
        // the quota refills with time
        tokio::time::advance(Duration::from_secs(1)).await;
        std::thread::sleep(Duration::from_millis(1100)); // Instant is wall-clock based
        let mut again = futures::io::Cursor::new(frame);
        assert!(codec.read_request(&proto, &mut again).await.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_bodies_hold_a_bounded_number_of_reads_for_a_bounded_time() {
        let (codec, guard) = uc_codec(2, Duration::from_secs(10));
        let proto = StreamProtocol::new(PROTO_UC);
        // declares 100 bytes, delivers 3, then stalls
        let mut stalled_frame = unsigned_varint::encode::u64_buffer();
        let mut bytes = unsigned_varint::encode::u64(100, &mut stalled_frame).to_vec();
        bytes.extend_from_slice(&[1, 2, 3]);
        let mut handles = Vec::new();
        for _ in 0..2 {
            let mut c = codec.clone();
            let proto = proto.clone();
            let bytes = bytes.clone();
            handles.push(tokio::spawn(async move {
                let mut io = Stalled {
                    data: bytes,
                    pos: 0,
                };
                c.read_request(&proto, &mut io).await
            }));
        }
        tokio::task::yield_now().await;
        assert_eq!(
            guard.permits.available_permits(),
            0,
            "both reads are in flight"
        );
        // a third stream is refused before it is read
        let mut c = codec.clone();
        let mut third = futures::io::Cursor::new(length_prefixed(&[9]));
        let err = c.read_request(&proto, &mut third).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(third.position(), 0);
        // the stalled reads are cut at the deadline and release their slots
        for h in handles {
            let err = h.await.unwrap().unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        }
        assert_eq!(guard.permits.available_permits(), 2);
    }

    /// A swarm with the production behaviour, pinned to `root`.
    fn test_swarm(kp: identity::Keypair, root: PeerId) -> Swarm<Behaviour> {
        let transport = libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default())
            .upgrade(upgrade::Version::V1)
            .authenticate(libp2p::noise::Config::new(&kp).unwrap())
            .multiplex(libp2p::yamux::Config::default())
            .boxed();
        let local = PeerId::from(kp.public());
        let mut swarm = Swarm::new(
            transport,
            build_behaviour(&kp, root),
            local,
            libp2p::swarm::Config::with_tokio_executor(),
        );
        swarm
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        swarm
    }

    #[tokio::test]
    async fn only_the_pinned_root_can_hold_a_connection() {
        let root_kp = identity::Keypair::generate_secp256k1();
        let outsider_kp = identity::Keypair::generate_secp256k1();
        let root_id = PeerId::from(root_kp.public());
        let outsider_id = PeerId::from(outsider_kp.public());
        let mut node = test_swarm(identity::Keypair::generate_secp256k1(), root_id);
        let mut root = test_swarm(root_kp, root_id);
        let mut outsider = test_swarm(outsider_kp, root_id);

        // the node's listen address
        let addr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = node.select_next_some().await {
                break address;
            }
        };
        let _ = (root.next().now_or_never(), outsider.next().now_or_never());

        outsider.dial(addr.clone()).unwrap();
        let (mut denied, mut outsider_connected) = (false, false);
        let deadline = tokio::time::sleep(Duration::from_secs(10));
        tokio::pin!(deadline);
        while !denied {
            tokio::select! {
                ev = node.select_next_some() => match ev {
                    SwarmEvent::IncomingConnectionError { .. } => denied = true,
                    SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == outsider_id => {
                        outsider_connected = true;
                        denied = true;
                    }
                    _ => {}
                },
                _ = outsider.select_next_some() => {}
                _ = &mut deadline => panic!("the outsider connection was neither denied nor established"),
            }
        }
        assert!(
            !outsider_connected,
            "the node never held a connection to the outsider"
        );

        // the pinned root connects normally
        root.dial(addr).unwrap();
        let deadline = tokio::time::sleep(Duration::from_secs(10));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                ev = node.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { peer_id, .. } = ev {
                        assert_eq!(peer_id, root_id);
                        break;
                    }
                }
                _ = root.select_next_some() => {}
                _ = outsider.select_next_some() => {}
                _ = &mut deadline => panic!("the pinned root could not connect"),
            }
        }
    }

    #[test]
    fn changed_reference_time_is_a_transient_rebuild() {
        let rejection = reference_time_changed(10, 11);

        assert_eq!(rejection.status, CertStatus::Transient);
        assert!(rejection.message.contains("round must be rebuilt"));
    }
}
