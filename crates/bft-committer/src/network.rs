//! libp2p networking to BFT Core root chain

use crate::cbor::serialize_certification_request;
use crate::storage::UcStorage;
use crate::types::{BlockCertificationRequest, TechnicalRecord, UnicityCertificate};
use anyhow::{Context, Result};
use futures::prelude::*;
use libp2p::{
    core::upgrade,
    identify,
    identity,
    request_response::{self, Codec, ProtocolSupport},
    swarm::{NetworkBehaviour, Swarm, SwarmEvent},
    Multiaddr, PeerId, StreamProtocol, Transport,
};
use std::io;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// BFT Core protocol names
const PROTOCOL_BLOCK_CERTIFICATION: &str = "/ab/block-certification/0.0.1";
const PROTOCOL_UNICITY_CERTIFICATES: &str = "/ab/certificates/0.0.1";
const PROTOCOL_HANDSHAKE: &str = "/ab/handshake/0.0.1";

/// UC callback now receives both UC and TechnicalRecord (they arrive together in CertificationResponse)
type UcCallback = Box<dyn Fn(UnicityCertificate, TechnicalRecord) -> Result<()> + Send + Sync>;

/// Custom codec for BFT Core's uvarint + CBOR wire format
#[derive(Debug, Clone, Default)]
struct BftCodec;

#[async_trait::async_trait]
impl Codec for BftCodec {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        // Read uvarint-length-prefixed CBOR data
        read_uvi_length_prefixed(io).await
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        // Read uvarint-length-prefixed CBOR data
        read_uvi_length_prefixed(io).await
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        // Write uvarint-length-prefixed CBOR data
        write_uvi_length_prefixed(io, &req).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        // Write uvarint-length-prefixed CBOR data
        write_uvi_length_prefixed(io, &res).await
    }
}

/// Read uvarint-length-prefixed data (matching BFT Core's wire format)
async fn read_uvi_length_prefixed<R>(reader: &mut R) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin + Send,
{
    use unsigned_varint::aio::read_u64;

    // Read length as uvarint
    let length = read_u64(&mut *reader).await
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    if length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Unexpected message length zero",
        ));
    }

    if length > 10 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Message too large: {} bytes", length),
        ));
    }

    // Read CBOR data
    let mut data = vec![0u8; length as usize];
    reader.read_exact(&mut data).await?;

    Ok(data)
}

/// Write uvarint-length-prefixed data (matching BFT Core's wire format)
async fn write_uvi_length_prefixed<W>(writer: &mut W, data: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin + Send,
{
    use unsigned_varint::encode;

    // Encode length as uvarint
    let length = data.len() as u64;
    let mut length_buf = encode::u64_buffer();
    let length_bytes = encode::u64(length, &mut length_buf);

    // Write length prefix
    writer.write_all(length_bytes).await?;

    // Write CBOR data
    writer.write_all(data).await?;

    writer.flush().await?;

    Ok(())
}

/// Network behaviour for BFT Core client
#[derive(NetworkBehaviour)]
struct BftBehaviour {
    // For sending BlockCertification requests (outbound only)
    block_cert: request_response::Behaviour<BftCodec>,
    // For receiving UnicityCertificates (inbound only)
    uc_receiver: request_response::Behaviour<BftCodec>,
    // For sending Handshake messages to subscribe to UC feed (outbound only)
    handshake: request_response::Behaviour<BftCodec>,
    // Identify protocol for peer discovery and address exchange
    identify: identify::Behaviour,
}

/// BFT Core network client using libp2p
pub struct BftCoreClient {
    swarm: Swarm<BftBehaviour>,
    command_rx: mpsc::Receiver<ClientCommand>,
    command_tx: mpsc::Sender<ClientCommand>,
    uc_callback: Option<UcCallback>,
    uc_storage: UcStorage,
    local_peer_id: PeerId,
}

enum ClientCommand {
    SubmitRequest {
        peer: PeerId,
        request: BlockCertificationRequest,
    },
    SendHandshake {
        peer: PeerId,
        data: Vec<u8>,  // Pre-serialized CBOR data
    },
}

impl BftCoreClient {
    /// Create a new BFT Core client
    /// Uses authKey (secp256k1) to derive libp2p peer ID
    pub fn new(
        listen_addr: Multiaddr,
        uc_storage: UcStorage,
        auth_key_bytes: Vec<u8>,
    ) -> Result<Self> {
        info!("Creating BFT Core client on {}", listen_addr);

        use libp2p::identity::secp256k1;
        let secret_key = secp256k1::SecretKey::try_from_bytes(auth_key_bytes)
            .context("Failed to create secp256k1 secret key from auth key bytes")?;
        let local_key = identity::Keypair::from(secp256k1::Keypair::from(secret_key));

        let local_peer_id = PeerId::from(local_key.public());

        // Create transport with DNS resolution support for /dns4/ multiaddrs
        let tcp_config = libp2p::tcp::Config::default()
            .port_reuse(false);
        let tcp_transport = libp2p::tcp::tokio::Transport::new(tcp_config);

        // Wrap TCP transport with DNS resolver to support /dns4/ addresses in Docker
        let transport = libp2p::dns::tokio::Transport::system(tcp_transport)
            .context("Failed to create DNS transport")?
            .upgrade(upgrade::Version::V1)
            .authenticate(libp2p::noise::Config::new(&local_key)?)
            .multiplex(libp2p::yamux::Config::default())
            .boxed();

        // Create BlockCertification protocol (outbound only - we send requests)
        let block_cert_protocol = StreamProtocol::new(PROTOCOL_BLOCK_CERTIFICATION);
        let block_cert_config = request_response::Config::default()
            .with_request_timeout(std::time::Duration::from_secs(60));
        let block_cert = request_response::Behaviour::with_codec(
            BftCodec::default(),
            std::iter::once((block_cert_protocol, ProtocolSupport::Outbound)),
            block_cert_config,
        );

        // Create UnicityCertificates protocol (inbound only - we receive UCs)
        let uc_protocol = StreamProtocol::new(PROTOCOL_UNICITY_CERTIFICATES);
        let uc_config = request_response::Config::default();
        let uc_receiver = request_response::Behaviour::with_codec(
            BftCodec::default(),
            std::iter::once((uc_protocol, ProtocolSupport::Inbound)),
            uc_config,
        );

        // Create Handshake protocol (outbound only - we send handshakes to subscribe to UC feed)
        let handshake_protocol = StreamProtocol::new(PROTOCOL_HANDSHAKE);
        let handshake_config = request_response::Config::default()
            .with_request_timeout(std::time::Duration::from_secs(30));
        let handshake = request_response::Behaviour::with_codec(
            BftCodec::default(),
            std::iter::once((handshake_protocol, ProtocolSupport::Outbound)),
            handshake_config,
        );

        // Create Identify protocol for peer discovery
        let identify_config = identify::Config::new(
            "/ipfs/0.1.0".to_string(),
            local_key.public(),
        );
        let identify = identify::Behaviour::new(identify_config);

        let behaviour = BftBehaviour {
            block_cert,
            uc_receiver,
            handshake,
            identify,
        };

        // Create swarm
        let mut swarm = Swarm::new(
            transport,
            behaviour,
            local_peer_id,
            libp2p::swarm::Config::with_tokio_executor()
                .with_idle_connection_timeout(std::time::Duration::from_secs(60)),
        );

        // Listen on the provided address
        swarm.listen_on(listen_addr.clone())?;

        // Add external address so BFT Core can dial back to us
        // Convert 0.0.0.0 to 127.0.0.1 for localhost connectivity
        let external_addr = if listen_addr.to_string().contains("0.0.0.0") {
            // Replace 0.0.0.0 with 127.0.0.1 for loopback
            let addr_str = listen_addr.to_string().replace("0.0.0.0", "127.0.0.1");
            addr_str.parse::<Multiaddr>()
                .unwrap_or(listen_addr.clone())
        } else {
            listen_addr.clone()
        };

        swarm.add_external_address(external_addr);
        info!("External address advertised for peer discovery");

        let (command_tx, command_rx) = mpsc::channel(32);

        Ok(BftCoreClient {
            swarm,
            command_rx,
            command_tx,
            uc_callback: None,
            uc_storage,
            local_peer_id,
        })
    }

    /// Get a handle for submitting requests
    pub fn handle(&self) -> BftCoreHandle {
        BftCoreHandle {
            command_tx: self.command_tx.clone(),
        }
    }

    /// Get the local peer ID
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Set callback for receiving Unicity Certificates and Technical Records
    /// Both are delivered together in CertificationResponse, so they're handled in one callback
    pub fn set_uc_callback<F>(&mut self, callback: F)
    where
        F: Fn(UnicityCertificate, TechnicalRecord) -> Result<()> + Send + Sync + 'static,
    {
        self.uc_callback = Some(Box::new(callback));
    }

    /// Handle a certification response containing a Unicity Certificate
    fn handle_certification_response(&mut self, data: &[u8]) -> Result<()> {
        use crate::cbor::deserialize_certification_response;

        // Deserialize the CertificationResponse
        let response = deserialize_certification_response(data)?;

        // Extract UC and TechnicalRecord
        let uc = response.uc;
        let technical = response.technical;

        // Validate required fields
        let input_record = uc.input_record.as_ref()
            .ok_or_else(|| anyhow::anyhow!("UC missing InputRecord"))?;
        let unicity_seal = uc.unicity_seal.as_ref()
            .ok_or_else(|| anyhow::anyhow!("UC missing UnicitySeal"))?;

        let round = input_record.round_number;

        // Extract state hashes from UC InputRecord
        let uc_state_hash = input_record.hash.as_ref()
            .map(|h| hex::encode(&h[..h.len().min(32)]))
            .unwrap_or_else(|| "None".to_string());
        let uc_prev_hash = input_record.previous_hash.as_ref()
            .map(|h| hex::encode(&h[..h.len().min(32)]))
            .unwrap_or_else(|| "None".to_string());

        info!("========================================");
        info!("📥 RECEIVED UC FROM BFT CORE");
        info!("========================================");
        info!("UC round number:     {}", round);
        info!("UC state hash:       {}", uc_state_hash);
        info!("UC prev hash:        {}", uc_prev_hash);
        info!("UC root round:       {}", unicity_seal.root_chain_round_number);
        info!("UC timestamp:        {}", input_record.timestamp);
        info!("UC epoch:            {}", input_record.epoch);
        info!("Signatures:          {} validators", unicity_seal.signatures.len());
        info!("TechnicalRecord:");
        info!("  Next round:        {}", technical.round);
        info!("  Epoch:             {}", technical.epoch);
        info!("  Leader:            {}", technical.leader);
        info!("========================================");

        // Clone UC and TechnicalRecord for callback before moving UC into storage
        let uc_for_callback = uc.clone();
        let technical_for_callback = technical.clone();

        self.uc_storage.store_uc(uc)?;

        if let Some(ref callback) = self.uc_callback {
            if let Err(e) = callback(uc_for_callback, technical_for_callback) {
                error!("UC callback failed: {}", e);
            }
        }

        Ok(())
    }

    /// Run the network event loop
    pub async fn run(mut self) {
        info!("Starting BFT Core client event loop");

        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await;
                }
                Some(command) = self.command_rx.recv() => {
                    self.handle_command(command).await;
                }
            }
        }
    }

    async fn handle_swarm_event(&mut self, event: SwarmEvent<BftBehaviourEvent>) {
        match event {
            // Handle BlockCertification protocol events
            SwarmEvent::Behaviour(BftBehaviourEvent::BlockCert(request_response::Event::Message { message, .. })) => {
                match message {
                    request_response::Message::Response { .. } => {
                        // We don't expect responses on this protocol
                        warn!("Received unexpected response on BlockCertification protocol");
                    }
                    request_response::Message::Request { .. } => {
                        warn!("Received unexpected request on BlockCertification protocol");
                    }
                }
            }
            SwarmEvent::Behaviour(BftBehaviourEvent::BlockCert(request_response::Event::OutboundFailure {
                error,
                peer,
                ..
            })) => {
                // Outbound failures might happen if BFT Core doesn't send responses
                debug!("BlockCertification outbound event: peer {:?}, status: {:?}", peer, error);
            }

            // Handle UnicityCertificates protocol events (incoming UCs from BFT Core)
            SwarmEvent::Behaviour(BftBehaviourEvent::UcReceiver(request_response::Event::Message { message, .. })) => {
                match message {
                    request_response::Message::Request { request, channel, .. } => {

                        // Attempt to deserialize the CertificationResponse
                        match self.handle_certification_response(&request) {
                            Ok(()) => {
                            }
                            Err(e) => {
                                error!("Failed to deserialize UC: {}", e);
                                error!("  CBOR structure from BFT Core may not match expected format");
                            }
                        }

                        // Send empty response to acknowledge receipt
                        let _ = self.swarm.behaviour_mut().uc_receiver.send_response(channel, vec![]);
                    }
                    request_response::Message::Response { .. } => {
                        warn!("Received unexpected response on UcReceiver protocol");
                    }
                }
            }
            SwarmEvent::Behaviour(BftBehaviourEvent::UcReceiver(request_response::Event::InboundFailure {
                error,
                ..
            })) => {
                error!("Inbound UC failure: {:?}", error);
            }

            // Handle Handshake protocol events
            SwarmEvent::Behaviour(BftBehaviourEvent::Handshake(request_response::Event::Message { message, .. })) => {
                match message {
                    request_response::Message::Response { .. } => {
                        // BFT Core may send empty response to acknowledge handshake
                        debug!("Received handshake response (acknowledgment)");
                    }
                    request_response::Message::Request { .. } => {
                        warn!("Received unexpected request on Handshake protocol");
                    }
                }
            }
            SwarmEvent::Behaviour(BftBehaviourEvent::Handshake(request_response::Event::OutboundFailure {
                error,
                peer,
                ..
            })) => {
                // Handshake failures may occur if BFT Core doesn't respond
                debug!("Handshake outbound event: peer {:?}, status: {:?}", peer, error);
            }

            // Handle Identify protocol events for peer discovery
            SwarmEvent::Behaviour(BftBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                debug!("Received Identify from peer: {}", peer_id);
                debug!("  Listen addrs: {:?}", info.listen_addrs);
                debug!("  Protocols: {:?}", info.protocols);
            }
            SwarmEvent::Behaviour(BftBehaviourEvent::Identify(identify::Event::Sent { peer_id, .. })) => {
                debug!("Sent Identify to peer: {}", peer_id);
            }
            SwarmEvent::Behaviour(BftBehaviourEvent::Identify(identify::Event::Pushed { peer_id, .. })) => {
                debug!("Pushed updated Identify info to peer: {}", peer_id);
            }
            SwarmEvent::Behaviour(BftBehaviourEvent::Identify(identify::Event::Error { peer_id, error, .. })) => {
                warn!("Identify error with peer {}: {:?}", peer_id, error);
            }

            SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                info!("✓ Connection established with peer: {}, endpoint: {:?}", peer_id, endpoint);
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                debug!("Connection closed with peer: {}, cause: {:?}", peer_id, cause);
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                error!("Outgoing connection error to {:?}: {:?}", peer_id, error);
            }
            SwarmEvent::IncomingConnectionError { error, .. } => {
                warn!("Incoming connection error: {:?}", error);
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {}", address);
            }
            SwarmEvent::Dialing { peer_id, .. } => {
                info!("Dialing peer: {:?}", peer_id);
            }
            _ => {}
        }
    }

    async fn handle_command(&mut self, command: ClientCommand) {
        match command {
            ClientCommand::SubmitRequest {
                peer,
                request,
            } => {
                debug!("Submitting BlockCertification request to peer {}", peer);

                // Serialize request
                let cbor_data = match serialize_certification_request(&request) {
                    Ok(data) => {
                        data
                    },
                    Err(e) => {
                        error!("Failed to serialize request: {}", e);
                        return;
                    }
                };

                // Send request (fire-and-forget, no response expected)
                let _request_id = self
                    .swarm
                    .behaviour_mut()
                    .block_cert
                    .send_request(&peer, cbor_data);

                info!("✓ BlockCertification request sent to {}", peer);
            }
            ClientCommand::SendHandshake {
                peer,
                data,
            } => {
                // Send handshake (fire-and-forget, no meaningful response expected)
                let _request_id = self
                    .swarm
                    .behaviour_mut()
                    .handshake
                    .send_request(&peer, data);

                info!("✓ Handshake sent to {} - subscribed to UC feed", peer);
            }
        }
    }

    /// Dial a peer
    pub fn dial(&mut self, addr: Multiaddr) -> Result<()> {
        self.swarm.dial(addr)?;
        Ok(())
    }
}

/// Handle for submitting requests to BFT Core
#[derive(Clone)]
pub struct BftCoreHandle {
    command_tx: mpsc::Sender<ClientCommand>,
}

impl BftCoreHandle {
    /// Submit a block certification request to a specific peer, async
    pub async fn submit_certification_request(
        &self,
        peer: PeerId,
        request: BlockCertificationRequest,
    ) -> Result<()> {
        self.command_tx
            .send(ClientCommand::SubmitRequest {
                peer,
                request,
            })
            .await
            .context("Failed to send command to client")?;

        Ok(())
    }

    /// Send a handshake message to subscribe to UC feed
    /// BFT Core will register this node and start sending UCs
    pub async fn send_handshake(
        &self,
        peer: PeerId,
        partition_id: u32,
        node_id: String,
    ) -> Result<()> {
        use crate::cbor::serialize_handshake;
        use crate::types::Handshake;

        // Create handshake message
        // ShardID: Empty go bitstring (0x80) = default shard
        let handshake = Handshake {
            partition_id,
            shard_id: vec![0x80], // Empty bitstring = default shard
            node_id,
        };

        // Serialize to CBOR
        let data = serialize_handshake(&handshake)
            .context("Failed to serialize handshake")?;

        // Send command
        self.command_tx
            .send(ClientCommand::SendHandshake {
                peer,
                data,
            })
            .await
            .context("Failed to send handshake command to client")?;

        Ok(())
    }
}
