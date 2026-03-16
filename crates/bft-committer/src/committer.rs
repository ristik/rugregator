//! BFT Core committer - submits blocks to L1

use crate::network::BftCoreHandle;
use libp2p::PeerId;
use crate::types::{
    BlockCertificationRequest, InputRecord, ProposedBlockInfo, RoundState,
    UcValidation, UnicityCertificate,
};
use anyhow::{Context, Result};
use ethrex_common::H256;
use secp256k1::{Message, Secp256k1, SecretKey};
use sha2::{Sha256, Digest};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// Configuration for the BFT committer
#[derive(Debug, Clone)]
pub struct BftCommitterConfig {
    pub partition_id: u32,
    pub shard_id: Vec<u8>,
    pub node_id: String,
    pub signing_key: SecretKey,
    pub root_chain_peers: Vec<PeerId>,  // Root chain peers (first is primary, rest are failover)
}

/// BFT Core committer - handles L2→L1 block certification
pub struct BftCommitter {
    config: BftCommitterConfig,
    bft_handle: BftCoreHandle,
    secp: Secp256k1<secp256k1::All>,
    /// Centralized round state management (replaces next_round, next_epoch)
    /// Tracks: proposed block, next round, last UC, last root round
    round_state: Arc<RoundState>,
}

impl BftCommitter {
    /// Create a new BFT committer
    ///
    /// # Arguments
    /// * `config` - BFT committer configuration
    /// * `bft_handle` - Handle to BFT Core network layer
    /// * `genesis_uc` - Optional genesis UC for initialization (round 0)
    ///                   If provided, round state will be initialized from it
    ///                   If None, will default to round 1
    pub fn new(
        config: BftCommitterConfig,
        bft_handle: BftCoreHandle,
        genesis_uc: Option<UnicityCertificate>,
    ) -> Self {
        Self {
            config,
            bft_handle,
            secp: Secp256k1::new(),
            round_state: Arc::new(RoundState::new(genesis_uc)),
        }
    }

    /// Commit a block to BFT Core L1
    /// Note: This is fire-and-forget. The UnicityCertificate will be received
    /// asynchronously via the callback configured on the BFT client.
    pub async fn commit_block(
        &mut self,
        block_number: u64,
        block_hash: H256,
        previous_state_root: H256,
        new_state_root: H256,
        zk_proof: Vec<u8>,
    ) -> Result<()> {
        // Get LUC (last unicity certificate) - may not exist for first block
        let luc_opt = self.round_state.get_last_uc();

        // CRITICAL: Use round number from RoundState (from BFT Core's TechnicalRecord)
        // NOT the block_number - partitions must align with root chain rounds
        let round_number = self.round_state.get_next_expected_round();

        if round_number == 0 {
            return Err(anyhow::anyhow!("No next_expected_round set - need to receive UC from BFT Core first"));
        }

        // Get timestamp from LUC if available, otherwise use current time
        let timestamp = luc_opt
            .as_ref()
            .and_then(|luc| luc.unicity_seal.as_ref())
            .map(|seal| seal.timestamp)
            .unwrap_or_else(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            });

        // Get epoch from LUC's InputRecord if available
        let epoch = luc_opt
            .as_ref()
            .and_then(|luc| luc.input_record.as_ref())
            .map(|ir| ir.epoch)
            .unwrap_or(0);

        // CRITICAL: PreviousHash = STATE HASH from last UC (NOT previous_state_root!)
        // For first block (no LUC or LUC with null hash), use None to let BFT Core handle genesis
        let previous_hash = luc_opt
            .as_ref()
            .and_then(|luc| luc.input_record.as_ref())
            .and_then(|ir| ir.hash.as_ref())
            .filter(|h| !h.is_empty())  // Filter out null/empty hashes
            .cloned();  // Returns Option<Vec<u8>>

        let is_first_block = previous_hash.is_none();
        if is_first_block {
            info!("⭐ FIRST BLOCK - No LUC with certified state yet");
            info!("   PreviousHash will be None - BFT Core will use genesis state");
        }

        info!("========================================");
        info!("📤 BUILDING CERTIFICATION REQUEST FROM LUC");
        info!("========================================");
        info!("Block number:        {}", block_number);
        info!("Round number:        {}", round_number);
        info!("Epoch (from LUC):    {}", epoch);
        info!("Timestamp (LUC):     {}", timestamp);
        info!("PrevHash (LUC.IR.h): {}",
            previous_hash.as_ref().map(|h| hex::encode(h)).unwrap_or_else(|| "NONE (first block)".to_string()));
        info!("New state hash:      {:?}", new_state_root);
        info!("Block hash:          {:?}", block_hash);
        info!("========================================");

        // SET PROPOSED BLOCK before sending request
        // This is critical for validating the UC when it arrives
        self.round_state.set_proposed_block(ProposedBlockInfo {
            block_number: round_number, // Use round number, not block_number
            block_hash,
            state_root: new_state_root,
            parent_state_root: previous_state_root,
            timestamp,
        });

        debug!(
            "Set proposed block: round={}, state={:?}",
            round_number, new_state_root
        );

        // Construct InputRecord (ZK proof is separate in BlockCertificationRequest)
        // Must match bft-go-base/types/input_record.go structure
        // CRITICAL: previous_hash from LUC, or None for first block
        let input_record = InputRecord {
            version: 1,
            round_number, // Use BFT Core's round number from TechnicalRecord
            epoch,        // Use epoch from LUC
            previous_hash, // CRITICAL: STATE HASH from LUC.InputRecord.Hash, or None for first block
            hash: Some(new_state_root.as_bytes().to_vec()), // New state hash to be certified
            summary_value: Some(vec![]),                    // TODO: Calculate summary value
            timestamp,    // Timestamp from LUC.UnicitySeal
            block_hash: Some(block_hash.as_bytes().to_vec()), // Actual block header hash
            sum_of_earned_fees: 0,                                 // TODO: Calculate from transactions
            et_hash: Some(vec![]),                                 // TODO: Hash of executed transactions
        };

        debug!("Created InputRecord for round {} with fields:", block_number);
        debug!("  version: {}", input_record.version);
        debug!("  round_number: {}", input_record.round_number);
        debug!("  epoch: {}", input_record.epoch);
        debug!("  timestamp: {}", input_record.timestamp);

        // Create certification request with ZK proof
        // For genesis blocks (no previous state), proof should be None
        let zk_proof_opt = if zk_proof.is_empty() {
            None // Genesis block or sync request - no proof
        } else {
            Some(zk_proof.clone()) // Normal block with proof
        };

        let mut cert_request = BlockCertificationRequest {
            partition_id: self.config.partition_id,
            shard_id: self.config.shard_id.clone(),
            node_id: self.config.node_id.clone(),
            input_record,
            zk_proof: zk_proof_opt, // ZK proof for state transition validation (None for genesis)
            block_size: zk_proof.len() as u64,
            state_size: 0, // TODO: Calculate actual state size
            signature: None,  // Will be filled after signing
        };

        // Sign the request
        let signature = self.sign_request(&cert_request)?;
        cert_request.signature = Some(signature);

        debug!("Signed certification request");

        // Submit to BFT Core via libp2p - try each peer until one succeeds
        let mut last_err = None;
        for peer in &self.config.root_chain_peers {
            match self.bft_handle
                .submit_certification_request(*peer, cert_request.clone())
                .await
            {
                Ok(()) => {
                    info!(
                        "BlockCertification request submitted for block {} (round {}) to peer {}",
                        block_number, round_number, peer
                    );
                    last_err = None;
                    break;
                }
                Err(e) => {
                    warn!("Failed to submit certification to peer {}: {}", peer, e);
                    last_err = Some(e);
                }
            }
        }
        if let Some(e) = last_err {
            return Err(e).context("Failed to submit certification request to any root chain peer");
        }

        Ok(())
    }

    /// Validate UC against proposed block
    ///
    /// This is the core validation logic that determines how to handle a received UC.
    /// Returns UcValidation enum indicating the action to take.
    pub fn validate_uc(&self, uc: &UnicityCertificate) -> UcValidation {
        let last_uc = self.round_state.get_last_uc();
        let last_root = self.round_state.get_last_root_round();
        let uc_root = uc
            .unicity_seal
            .as_ref()
            .map(|seal| seal.root_chain_round_number)
            .unwrap_or(0);

        // 1. Duplicate check - same root round number means we already processed this
        if uc_root == last_root && uc_root > 0 {
            debug!("UC duplicate: root round {} already processed", uc_root);
            return UcValidation::Duplicate;
        }

        // 2. Repeat UC check (timeout) - same InputRecord but higher root round
        //    This means BFT Core timed out waiting for our block
        if let Some(ref prev_uc) = last_uc {
            if let (Some(uc_ir), Some(prev_ir)) = (
                uc.input_record.as_ref(),
                prev_uc.input_record.as_ref(),
            ) {
                if uc_ir.matches_state(prev_ir) && uc_root > last_root {
                    warn!(
                        "Repeat UC detected: same InputRecord, root round {} -> {} (timeout)",
                        last_root, uc_root
                    );
                    return UcValidation::Repeat;
                }
            }
        }

        // 3. Check proposed block match
        let proposed = self.round_state.get_proposed_block();
        if let Some(proposed_info) = proposed {
            let uc_round = uc
                .input_record
                .as_ref()
                .map(|ir| ir.round_number)
                .unwrap_or(0);

            if uc_round != proposed_info.block_number {
                warn!(
                    "UC round {} doesn't match proposed round {}",
                    uc_round, proposed_info.block_number
                );
                return UcValidation::RoundMismatch {
                    uc_round,
                    proposed_round: proposed_info.block_number,
                };
            }

            // 4. Validate state hashes
            let uc_state = uc
                .input_record
                .as_ref()
                .and_then(|ir| ir.hash.as_ref())
                .and_then(|h| {
                    if h.len() >= 32 {
                        Some(H256::from_slice(&h[..32]))
                    } else {
                        None
                    }
                })
                .unwrap_or(H256::zero());

            if uc_state != proposed_info.state_root {
                warn!(
                    "State mismatch: UC {:?} != proposed {:?}",
                    uc_state, proposed_info.state_root
                );
                return UcValidation::RoundMismatch {
                    uc_round,
                    proposed_round: proposed_info.block_number,
                };
            }

            debug!("UC validation passed for round {}", uc_round);
            return UcValidation::Valid;
        }

        // No proposed block - likely initialization or genesis
        UcValidation::NoProposedBlock
    }

    /// Update state after receiving UC
    ///
    /// This should be called after validating the UC and determining it's valid
    /// or a legitimate initialization UC (NoProposedBlock).
    ///
    /// # Arguments
    /// * `uc` - The UC to store
    /// * `next_round` - The next round number from TechnicalRecord
    pub fn handle_uc_received(&self, uc: &UnicityCertificate, next_round: u64) {
        let uc_round = uc.input_record.as_ref()
            .map(|ir| ir.round_number)
            .unwrap_or(0);

        info!("========================================");
        info!("✓ UC ACCEPTED - Updating Round State");
        info!("========================================");
        info!("UC round:            {}", uc_round);
        info!("Next round (from TR): {}", next_round);
        info!("Root round:          {}",
            uc.unicity_seal.as_ref().map(|s| s.root_chain_round_number).unwrap_or(0));
        info!("========================================");

        // Store the UC
        self.round_state.set_last_uc(uc.clone());

        // Update root round tracking
        if let Some(seal) = uc.unicity_seal.as_ref() {
            self.round_state
                .set_last_root_round(seal.root_chain_round_number);
        }

        // Update next expected round (CRITICAL: Use TechnicalRecord.Round, not uc.round + 1)
        self.round_state.set_next_expected_round(next_round);

        info!("Round state updated: Will produce block for round {}", next_round);
    }

    /// Get access to round state for external UC validation
    pub fn round_state(&self) -> Arc<RoundState> {
        self.round_state.clone()
    }

    /// Get the current next round number (for backward compatibility)
    pub fn get_next_round(&self) -> Option<u64> {
        let round = self.round_state.get_next_expected_round();
        if round > 0 {
            Some(round)
        } else {
            None
        }
    }

    /// Get the current next epoch number (from last UC)
    pub fn get_next_epoch(&self) -> Option<u64> {
        self.round_state
            .get_last_uc()
            .as_ref()
            .and_then(|uc| uc.input_record.as_ref())
            .map(|ir| ir.epoch)
    }

    /// Request genesis UC from BFT Core by sending a probe certification request
    /// This triggers BFT Core to send us the genesis UC (round 0) for synchronization
    pub async fn request_genesis_uc(&mut self) -> Result<()> {
        info!("Sending genesis sync probe to BFT Core");

        // Send a dummy certification request that will be rejected
        // BFT Core will respond with the genesis UC (round 0)
        let dummy_state = H256::zero();

        // Construct InputRecord for round 0 probe
        let input_record = InputRecord {
            version: 1,
            round_number: 0,  // Probe for genesis
            epoch: 0,
            previous_hash: Some(dummy_state.as_bytes().to_vec()),
            hash: Some(dummy_state.as_bytes().to_vec()),
            summary_value: Some(vec![]),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs(),
            block_hash: Some(dummy_state.as_bytes().to_vec()),
            sum_of_earned_fees: 0,
            et_hash: Some(vec![]),
        };

        // Create minimal certification request
        let mut cert_request = BlockCertificationRequest {
            partition_id: self.config.partition_id,
            shard_id: self.config.shard_id.clone(),
            node_id: self.config.node_id.clone(),
            input_record,
            zk_proof: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]), // Dummy proof
            block_size: 4,
            state_size: 0,
            signature: None,
        };

        // Sign the request
        let signature = self.sign_request(&cert_request)?;
        cert_request.signature = Some(signature);

        // Submit to BFT Core - try each peer until one succeeds
        let mut last_err = None;
        for peer in &self.config.root_chain_peers {
            match self.bft_handle
                .submit_certification_request(*peer, cert_request.clone())
                .await
            {
                Ok(()) => {
                    info!("Genesis sync probe submitted to peer {} - awaiting UC round 0", peer);
                    last_err = None;
                    break;
                }
                Err(e) => {
                    warn!("Failed to submit genesis probe to peer {}: {}", peer, e);
                    last_err = Some(e);
                }
            }
        }
        if let Some(e) = last_err {
            return Err(e).context("Failed to submit genesis sync probe to any root chain peer");
        }

        Ok(())
    }

    /// Sign a certification request with secp256k1
    fn sign_request(&self, req: &BlockCertificationRequest) -> Result<Vec<u8>> {
        // Serialize request for signing (excluding signature)
        let mut req_copy = req.clone();
        req_copy.signature = None;  // CBOR null (f6) instead of empty byte string (40)

        let bytes = crate::cbor::serialize_certification_request(&req_copy)?;

        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let hash = hasher.finalize();

        // Sign with secp256k1
        let message = Message::from_digest_slice(&hash)?;
        let signature = self.secp.sign_ecdsa(&message, &self.config.signing_key);
        let sig_bytes = signature.serialize_compact();

        Ok(sig_bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let peer_id = PeerId::random();

        let config = BftCommitterConfig {
            partition_id: 1,
            shard_id: vec![1],
            node_id: "test-node".to_string(),
            signing_key: secret_key,
            root_chain_peers: vec![peer_id],
        };

        assert_eq!(config.partition_id, 1);
        assert_eq!(config.shard_id, vec![1]);
        assert_eq!(config.node_id, "test-node");
    }
}
