//! Live BFT Core committer using libp2p.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::time::SystemTime;

use async_trait::async_trait;
use futures::prelude::*;
use libp2p::{
    core::upgrade,
    identify,
    identity,
    request_response::{self, Codec, ProtocolSupport},
    swarm::{NetworkBehaviour, Swarm, SwarmEvent},
    Multiaddr, PeerId, StreamProtocol, Transport,
};
use secp256k1::{Message, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot, Notify};
use tracing::{debug, error, info, warn};

use super::BftCommitter;

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
    where S: Serializer {
        match v { Some(b) => serde_bytes::serialize(b.as_slice(), s), None => s.serialize_none() }
    }
    pub fn deserialize<'de, D>(d: D) -> Result<Option<Vec<u8>>, D::Error>
    where D: Deserializer<'de> {
        #[derive(Deserialize)]
        struct H(#[serde(with = "serde_bytes")] Vec<u8>);
        let opt: Option<H> = Option::deserialize(d)?;
        Ok(opt.map(|H(v)| v))
    }
}

// ─── BFT round state ──────────────────────────────────────────────────────────

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

struct Shared {
    initialized: AtomicBool,
    /// block_number → oneshot receiver (set in commit_block, awaited in wait_for_uc)
    blk_receivers: Mutex<HashMap<u64, oneshot::Receiver<Vec<u8>>>>,
    init_notify: Notify,
}

// ─── Parsed UC event ─────────────────────────────────────────────────────────

struct UcEvent {
    /// IR.round_number — 0 for sync (proactive) UCs.
    uc_round: u64,
    /// TechnicalRecord.round — the BFT round the aggregator should use next.
    next_round: u64,
    epoch: u64,
    prev_hash: Option<Vec<u8>>,
    /// UnicitySeal.Timestamp — must be echoed verbatim in our cert request.
    timestamp: u64,
    uc_cbor: Vec<u8>,
}

// ─── Pending cert request (held by network loop during certification) ─────────

struct PendingCert {
    new_hash: Vec<u8>,
    state_changed: bool,
    zk_proof: Option<Vec<u8>>,
    uc_tx: oneshot::Sender<Vec<u8>>,
    /// BFT round used when this cert request was sent.
    bft_round_used: u64,
}

// ─── libp2p plumbing ─────────────────────────────────────────────────────────

const PROTO_CERT: &str = "/ab/block-certification/0.0.1";
const PROTO_UC: &str = "/ab/certificates/0.0.1";
const PROTO_HS: &str = "/ab/handshake/0.0.1";
const TAG_INPUT_RECORD: u64 = 1008;

/// Data for a cert request, sans round/epoch (filled in at transmission time).
struct CertReqData {
    new_hash: Vec<u8>,
    state_changed: bool,
    zk_proof: Option<Vec<u8>>,
    /// Deliver the raw UC CBOR bytes to this sender once the UC arrives.
    uc_tx: oneshot::Sender<Vec<u8>>,
}

enum NetCmd { Submit(CertReqData), }

#[derive(Debug, Clone, Default)]
struct BftCodec;

#[async_trait::async_trait]
impl Codec for BftCodec {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;
    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> std::io::Result<Vec<u8>>
    where T: AsyncRead + Unpin + Send { read_uvi(io).await }
    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> std::io::Result<Vec<u8>>
    where T: AsyncRead + Unpin + Send { read_uvi(io).await }
    async fn write_request<T>(&mut self, _: &Self::Protocol, io: &mut T, req: Vec<u8>) -> std::io::Result<()>
    where T: AsyncWrite + Unpin + Send { write_uvi(io, &req).await }
    async fn write_response<T>(&mut self, _: &Self::Protocol, io: &mut T, res: Vec<u8>) -> std::io::Result<()>
    where T: AsyncWrite + Unpin + Send { write_uvi(io, &res).await }
}

async fn read_uvi<R: AsyncRead + Unpin + Send>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let len = unsigned_varint::aio::read_u64(&mut *r).await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if len == 0 || len > 10 * 1024 * 1024 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad len"));
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
    cert: request_response::Behaviour<BftCodec>,
    uc: request_response::Behaviour<BftCodec>,
    hs: request_response::Behaviour<BftCodec>,
    identify: identify::Behaviour,
}

// ─── Config ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LiveBftConfig {
    pub partition_id: u32,
    pub bft_peer_id: PeerId,
    pub bft_addr: Multiaddr,
    pub listen_addr: Multiaddr,
    /// Raw secp256k1 bytes (32) for libp2p auth key (PeerId derivation)
    pub auth_key_bytes: Vec<u8>,
    /// Raw secp256k1 bytes (32) for signing BlockCertificationRequests
    pub sig_key_bytes: Vec<u8>,
}

// ─── LiveBftCommitter ─────────────────────────────────────────────────────────

pub struct LiveBftCommitter {
    cmd_tx: mpsc::Sender<NetCmd>,
    shared: Arc<Shared>,
}

impl LiveBftCommitter {
    pub fn start(cfg: LiveBftConfig) -> anyhow::Result<Self> {
        let secret = libp2p::identity::secp256k1::SecretKey::try_from_bytes(cfg.auth_key_bytes.clone())
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

        let mk_rr = |proto: &'static str, support: ProtocolSupport| {
            request_response::Behaviour::with_codec(
                BftCodec::default(),
                std::iter::once((StreamProtocol::new(proto), support)),
                request_response::Config::default()
                    .with_request_timeout(std::time::Duration::from_secs(60)),
            )
        };

        let behaviour = Behaviour {
            cert: mk_rr(PROTO_CERT, ProtocolSupport::Outbound),
            uc: mk_rr(PROTO_UC, ProtocolSupport::Inbound),
            hs: mk_rr(PROTO_HS, ProtocolSupport::Outbound),
            identify: identify::Behaviour::new(identify::Config::new("/ipfs/0.1.0".into(), kp.public())),
        };

        let mut swarm = Swarm::new(
            transport, behaviour, local_peer,
            libp2p::swarm::Config::with_tokio_executor()
                .with_idle_connection_timeout(std::time::Duration::from_secs(120)),
        );
        swarm.listen_on(cfg.listen_addr.clone())?;

        let shared = Arc::new(Shared {
            initialized: AtomicBool::new(false),
            blk_receivers: Mutex::new(HashMap::new()),
            init_notify: Notify::new(),
        });

        let (cmd_tx, cmd_rx) = mpsc::channel(64);

        let shared2 = Arc::clone(&shared);
        let bft_peer = cfg.bft_peer_id;
        let bft_addr = cfg.bft_addr.clone();
        let partition_id = cfg.partition_id;
        let node_id2 = node_id.clone();
        let sig_key2 = SecretKey::from_slice(&cfg.sig_key_bytes)
            .map_err(|e| anyhow::anyhow!("sig key (net): {e}"))?;

        tokio::spawn(async move {
            network_loop(swarm, cmd_rx, shared2, bft_peer, bft_addr, partition_id, node_id2, sig_key2).await;
        });

        Ok(Self { cmd_tx, shared })
    }

    async fn wait_init(&self) {
        loop {
            if self.shared.initialized.load(Ordering::Acquire) { return; }
            self.shared.init_notify.notified().await;
        }
    }
}

#[async_trait]
impl BftCommitter for LiveBftCommitter {
    async fn commit_block(
        &self,
        block_number: u64,
        new_root: &[u8; 34],
        prev_root: &[u8; 34],
        zk_proof: Option<Vec<u8>>,
    ) -> anyhow::Result<()> {
        self.wait_init().await;

        // Use the full 34-byte DataHash imprint (2 algo bytes + 32 hash bytes).
        // BFT Core echoes InputRecord.Hash verbatim; the SDK reads it as a DataHash imprint.
        let new_hash = new_root.to_vec();
        let state_changed = new_root != prev_root;

        // Register the block → UC receiver BEFORE queuing the Submit command so
        // the network task can fill the sender side at transmission time.
        let (tx, rx) = oneshot::channel::<Vec<u8>>();
        self.shared.blk_receivers.lock().unwrap().insert(block_number, rx);

        // The round number and prev_hash are read by the network task at the moment
        // of actual transmission. prev_hash comes from the latest sync UC; if none
        // has arrived yet, we send None (matching BFT Core's nil initial state).
        let data = CertReqData {
            new_hash,
            state_changed,
            zk_proof,
            uc_tx: tx,
        };

        self.cmd_tx.send(NetCmd::Submit(data)).await
            .map_err(|_| anyhow::anyhow!("net task closed"))?;

        info!(block = block_number, "cert request queued (round resolved at send time)");
        Ok(())
    }

    async fn wait_for_uc(&self, block_number: u64) -> anyhow::Result<Vec<u8>> {
        let rx = self.shared.blk_receivers.lock().unwrap().remove(&block_number);
        let rx = match rx {
            Some(r) => r,
            None => {
                warn!(block = block_number, "no UC receiver registered; returning stub");
                return Ok(vec![]);
            }
        };
        let uc = rx.await.map_err(|_| anyhow::anyhow!("UC sender dropped"))?;
        info!(block = block_number, "UC received ({}B)", uc.len());
        Ok(uc)
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
            arr[3] = ciborium::value::Value::Tag(TAG_INPUT_RECORD, Box::new(ir));
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

fn strip_tags(val: &ciborium::value::Value) -> ciborium::value::Value {
    match val {
        ciborium::value::Value::Tag(_, inner) => strip_tags(inner),
        ciborium::value::Value::Array(arr) =>
            ciborium::value::Value::Array(arr.iter().map(strip_tags).collect()),
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
        .map_err(|e| error!("UC parse error: {e}")).ok()?;
    let arr = match val {
        ciborium::value::Value::Array(a) => a,
        _ => { error!("UC not array"); return None; }
    };
    if arr.len() < 4 { error!("UC array too short"); return None; }

    // TechnicalRecord at index 2: [round, epoch, leader, stat_hash, fee_hash]
    let (next_round, epoch) = match strip_tags(&arr[2]) {
        ciborium::value::Value::Array(tr) if tr.len() >= 2 => {
            (cbor_u64(&tr[0]).unwrap_or(0), cbor_u64(&tr[1]).unwrap_or(0))
        }
        _ => { warn!("UC: bad TechnicalRecord"); return None; }
    };

    // UC at index 3 — extract IR round_number and IR hash
    let uc_arr = match strip_tags(&arr[3]) {
        ciborium::value::Value::Array(a) => a,
        _ => { warn!("UC: bad UC value"); return None; }
    };
    // UC structure: [version, input_record, tr_hash, ...]
    // InputRecord: [version, round_number, epoch, previous_hash, hash, ...]
    let (uc_round, uc_hash) = if uc_arr.len() >= 2 {
        match strip_tags(&uc_arr[1]) {
            ciborium::value::Value::Array(ir) if ir.len() >= 5 => {
                let rnd = cbor_u64(&ir[1]).unwrap_or(0);
                let h = match &ir[4] { ciborium::value::Value::Bytes(b) => Some(b.clone()), _ => None };
                (rnd, h)
            }
            _ => (0, None),
        }
    } else {
        (0, None)
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
                cbor_u64(&seal[4]).unwrap_or(0)  // seal[4] = Timestamp
            }
            _ => 0,
        }
    } else { 0 };

    // Serialize UC element for storage/delivery
    let mut uc_cbor = Vec::new();
    let _ = ciborium::into_writer(&arr[3], &mut uc_cbor);

    Some(UcEvent { uc_round, next_round, epoch, prev_hash: uc_hash, timestamp, uc_cbor })
}

// ─── Network loop ─────────────────────────────────────────────────────────────

/// Build, sign and return the CBOR for a cert request using the given round/epoch/prev_hash.
/// Build a signed cert request CBOR.
/// `prev_hash_ir` = the last certified state hash from BFT Core (None = initial genesis state).
/// `timestamp` = UnicitySeal.Timestamp from the latest UC (must be echoed verbatim).
fn make_cert_cbor(
    pending: &PendingCert,
    bft_round: u64,
    epoch: u64,
    prev_hash_ir: Option<Vec<u8>>,
    timestamp: u64,
    partition_id: u32,
    node_id: &str,
    secp: &Secp256k1<secp256k1::All>,
    sig_key: &SecretKey,
) -> anyhow::Result<Vec<u8>> {
    let block_hash = if pending.state_changed { Some(pending.new_hash.clone()) } else { None };
    let ts = if timestamp > 0 { timestamp } else {
        SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
    };
    let ir = InputRecord {
        version: 1, round_number: bft_round, epoch,
        previous_hash: prev_hash_ir,
        hash: Some(pending.new_hash.clone()),
        summary_value: Some(vec![]),
        timestamp: ts, block_hash,
        sum_of_earned_fees: 0, et_hash: Some(vec![]),
    };
    let mut req = BlockCertReq {
        partition_id, shard_id: vec![0x80], node_id: node_id.to_string(),
        input_record: ir, zk_proof: pending.zk_proof.clone(),
        block_size: 0, state_size: 0, signature: None,
    };
    // Sign: compute digest of unsigned CBOR, then set signature
    req.signature = None;
    let raw = cbor_cert_req(&req)?;
    let hash: [u8; 32] = Sha256::digest(&raw).into();
    let sig = secp.sign_ecdsa(&Message::from_digest(hash), sig_key);
    req.signature = Some(sig.serialize_compact().to_vec());
    cbor_cert_req(&req)
}

async fn network_loop(
    mut swarm: Swarm<Behaviour>,
    mut cmd_rx: mpsc::Receiver<NetCmd>,
    shared: Arc<Shared>,
    bft_peer: PeerId,
    bft_addr: Multiaddr,
    partition_id: u32,
    node_id: String,
    sig_key: SecretKey,
) {
    let secp = Secp256k1::new();
    let _ = swarm.dial(bft_addr.clone());
    info!("Dialing BFT Core at {}", bft_addr);
    let mut hs_sent = false;
    // Cert request currently in flight (awaiting UC from BFT Core).
    let mut pending: Option<PendingCert> = None;
    // Reconnect timer: fires after a delay when a reconnect is needed.
    let mut reconnect_delay: Option<std::pin::Pin<Box<tokio::time::Sleep>>> = None;
    // Single source of truth for building the next cert request.
    // Updated from EVERY valid UC (sync, cert response, repeat).
    let mut last_uc: Option<LastUc> = None;

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
                            let h = Handshake { partition_id, shard_id: vec![0x80], node_id: node_id.clone() };
                            if let Ok(cbor) = cbor_handshake(&h) {
                                swarm.behaviour_mut().hs.send_request(&peer_id, cbor);
                                hs_sent = true;
                                info!("Handshake sent, subscribed to UC feed");
                            }
                        }
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Uc(
                        request_response::Event::Message {
                            message: request_response::Message::Request { request, channel, .. },
                            ..
                        },
                    )) => {
                        debug!("UC arrived ({} bytes)", request.len());
                        let _ = swarm.behaviour_mut().uc.send_response(channel, vec![]);

                        let ev = match parse_uc(&request) { Some(e) => e, None => continue };
                        info!(uc_round = ev.uc_round, next_round = ev.next_round, epoch = ev.epoch, "UC received from BFT Core");

                        // Always update last_uc from every valid UC.
                        last_uc = Some(LastUc {
                            next_round: ev.next_round,
                            epoch: ev.epoch,
                            prev_hash: ev.prev_hash.clone(),
                            timestamp: ev.timestamp,
                        });

                        // Signal initialization on first valid UC.
                        if !shared.initialized.swap(true, Ordering::AcqRel) {
                            shared.init_notify.notify_waiters();
                        }

                        // Handle pending cert: check match first, then stale detection.
                        if let Some(ref p) = pending {
                            if ev.uc_round > 0 && ev.uc_round == p.bft_round_used {
                                // Our cert request was certified.
                                info!(bft_round = ev.uc_round, "UC matched — cert request certified");
                                let p = pending.take().unwrap();
                                let _ = p.uc_tx.send(ev.uc_cbor);
                            } else if ev.next_round > p.bft_round_used {
                                // BFT Core moved past our round — pending is stale.
                                warn!(
                                    our_round = p.bft_round_used,
                                    bft_next_round = ev.next_round,
                                    "pending cert stale — dropping"
                                );
                                let p = pending.take().unwrap();
                                // uc_tx dropped → wait_for_uc error → round manager re-queues.
                                drop(p);
                            }
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
                let _ = swarm.dial(bft_addr.clone());
            }
            // Accept a new Submit only when no cert request is in flight.
            // `biased` above guarantees all pending UCs are drained first,
            // so `last_uc` holds the freshest state.
            Some(cmd) = cmd_rx.recv(), if pending.is_none() => {
                match cmd {
                    NetCmd::Submit(data) => {
                        let lu = match &last_uc {
                            Some(lu) => lu,
                            None => {
                                error!("Submit received but no UC available — dropping");
                                continue;
                            }
                        };

                        let bft_round = lu.next_round;
                        let p = PendingCert {
                            new_hash: data.new_hash,
                            state_changed: data.state_changed,
                            zk_proof: data.zk_proof,
                            uc_tx: data.uc_tx,
                            bft_round_used: bft_round,
                        };

                        match make_cert_cbor(&p, bft_round, lu.epoch, lu.prev_hash.clone(),
                                             lu.timestamp, partition_id, &node_id, &secp, &sig_key) {
                            Ok(cbor) => {
                                info!(bft_round, "sending cert request to BFT Core");
                                pending = Some(p);
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
