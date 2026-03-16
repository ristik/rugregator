//! BFT Core data structures
//!
//! These types match the BFT Core L1 specification for block certification.
//! They use tuple/array serialization to match BFT Core's CBOR `toarray` format.

use serde_tuple::{Serialize_tuple, Deserialize_tuple};
use std::sync::{Arc, Mutex, RwLock, atomic::{AtomicU64, Ordering}};
use ethrex_common::H256;

/// Block certification request sent from L2 to BFT Core L1
/// Serialized as CBOR array (not map) to match BFT Core's toarray format
/// Note: Use cbor::serialize_certification_request() which adds CBOR tag 1008 to InputRecord
#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct BlockCertificationRequest {
    pub partition_id: u32,
    #[serde(with = "serde_bytes")]
    pub shard_id: Vec<u8>,
    pub node_id: String,
    pub input_record: InputRecord,
    #[serde(with = "option_bytes_helper")]
    pub zk_proof: Option<Vec<u8>>,  // ZK proof for state transition validation (nil when excluded from signature)
    pub block_size: u64,
    pub state_size: u64,
    #[serde(with = "option_bytes_helper")]
    pub signature: Option<Vec<u8>>,  // Signature bytes (nil when computing bytes to sign)
}

/// Input record containing state transition information
/// Serialized as CBOR array (not map) to match BFT Core's toarray format
/// IMPORTANT: Must match bft-go-base/types/input_record.go exactly
/// Must be wrapped in CBOR tag 1008 when used in BlockCertificationRequest
/// Note: Byte fields are Option types because they're hex.Bytes in Go (can be nil)
#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct InputRecord {
    pub version: u32,               // Version is uint32 in Go, not uint8!
    pub round_number: u64,
    pub epoch: u64,
    #[serde(with = "option_bytes_helper")]
    pub previous_hash: Option<Vec<u8>>,     // Previously certified state hash (can be nil)
    #[serde(with = "option_bytes_helper")]
    pub hash: Option<Vec<u8>>,              // State hash to be certified (can be nil)
    #[serde(with = "option_bytes_helper")]
    pub summary_value: Option<Vec<u8>>,     // Summary value to be certified (can be nil)
    pub timestamp: u64,
    #[serde(with = "option_bytes_helper")]
    pub block_hash: Option<Vec<u8>>,        // Hash of the block (can be nil)
    pub sum_of_earned_fees: u64,    // Sum of fees
    #[serde(with = "option_bytes_helper")]
    pub et_hash: Option<Vec<u8>>,           // Hash of executed transactions (can be nil)
}

impl InputRecord {
    /// Check if two InputRecords represent the same state
    /// Used for repeat UC detection: same state but higher root round = timeout
    pub fn matches_state(&self, other: &InputRecord) -> bool {
        self.round_number == other.round_number
            && self.hash == other.hash
            && self.previous_hash == other.previous_hash
            && self.block_hash == other.block_hash
    }
}

// CBOR tags from BFT Core (bft-go-base/types/versions.go)
pub const INPUT_RECORD_TAG: u64 = 1008;
pub const UNICITY_CERTIFICATE_TAG: u64 = 1007;
pub const UNICITY_SEAL_TAG: u64 = 1001;
pub const UNICITY_TREE_CERTIFICATE_TAG: u64 = 1014;

/// Unicity certificate returned from BFT Core L1
/// CBOR tag 1007
/// Matches bft-go-base/types/unicity_certificate.go
/// Note: Some fields are Option types because they're pointers in Go (can be nil)
/// Uses tuple/array serialization to match Go's `cbor:",toarray"` format
#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct UnicityCertificate {
    pub version: u32,
    pub input_record: Option<InputRecord>,      // *InputRecord in Go
    pub tr_hash: Option<Vec<u8>>,               // hex.Bytes (can be nil)
    pub shard_conf_hash: Option<Vec<u8>>,       // hex.Bytes (can be nil)
    pub shard_tree_certificate: ShardTreeCertificate,
    pub unicity_tree_certificate: Option<UnicityTreeCertificate>, // *UnicityTreeCertificate in Go
    pub unicity_seal: Option<UnicitySeal>,      // *UnicitySeal in Go
}

/// Shard tree certificate
/// Matches bft-go-base/types/shard_certificate.go
#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct ShardTreeCertificate {
    pub shard: Vec<u8>,                         // ShardID as bitstring bytes
    pub sibling_hashes: Vec<Vec<u8>>,
}

/// Unicity tree certificate (CBOR tag 1014)
/// Matches bft-go-base/types/unicity_tree_certificate.go
#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct UnicityTreeCertificate {
    pub version: u32,
    pub partition: u32,                         // PartitionID
    pub hash_steps: Vec<PathItem>,
}

/// Path item for unicity tree certificate
#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct PathItem {
    pub key: u32,                               // PartitionID
    pub hash: Vec<u8>,
}

/// Unicity seal (CBOR tag 1001)
/// Matches bft-go-base/types/unicity_seal.go
#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct UnicitySeal {
    pub version: u32,
    pub network_id: u32,                        // NetworkID
    pub root_chain_round_number: u64,
    pub epoch: u64,
    pub timestamp: u64,
    pub previous_hash: Vec<u8>,
    pub hash: Vec<u8>,
    pub signatures: std::collections::HashMap<String, Vec<u8>>,  // SignatureMap
}

/// Technical Record provides synchronization for next block production attempt
/// Serialized as CBOR array (not map) to match BFT Core's toarray format
#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct TechnicalRecord {
    pub round: u64,
    pub epoch: u64,
    pub leader: String,           // identifier of the round leader
    pub stat_hash: Vec<u8>,       // hash of statistical records
    pub fee_hash: Vec<u8>,        // hash of validator fee records
}

/// Certification response sent from BFT Core to L2 validators
/// Contains the Unicity Certificate and synchronization data
/// Serialized as CBOR array (not map) to match BFT Core's toarray format
#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct CertificationResponse {
    pub partition: u32,           // PartitionID (uint32 in Go)
    #[serde(with = "serde_bytes")]
    pub shard: Vec<u8>,           // ShardID as bitstring bytes (must be CBOR byte string)
    pub technical: TechnicalRecord,
    pub uc: UnicityCertificate,
}

/// Handshake message for subscribing to UC feed
/// Matches bft-core/network/protocol/handshake/handhake.go
/// Serialized as CBOR array (not map) to match BFT Core's toarray format
#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct Handshake {
    pub partition_id: u32,        // PartitionID
    #[serde(with = "serde_bytes")]
    pub shard_id: Vec<u8>,        // ShardID as bitstring bytes (must be CBOR byte string)
    pub node_id: String,          // libp2p peer ID as string
}

// ============================================================================
// Round State Management Types
// ============================================================================

/// UC validation result - determines how to handle received UCs
#[derive(Debug, Clone, PartialEq)]
pub enum UcValidation {
    /// UC is a duplicate (same root round number) - ignore
    Duplicate,
    /// UC is a repeat (same InputRecord, higher root round) - timeout from BFT Core
    Repeat,
    /// UC round doesn't match proposed block round - mismatch
    RoundMismatch { uc_round: u64, proposed_round: u64 },
    /// No proposed block to validate against - initialization or cleared
    NoProposedBlock,
    /// UC is valid and matches proposed block - finalize
    Valid,
}

/// Proposed block information tracked during certification
#[derive(Debug, Clone)]
pub struct ProposedBlockInfo {
    pub block_number: u64,
    pub block_hash: H256,
    pub state_root: H256,
    pub parent_state_root: H256,
    pub timestamp: u64,
}

/// Round state management - tracks the current certification state
pub struct RoundState {
    /// Single source of truth for the block being certified
    proposed_block: Mutex<Option<ProposedBlockInfo>>,

    /// Round tracking from TechnicalRecord (next expected round)
    next_expected_round: AtomicU64,

    /// Last UC for building next InputRecord
    last_uc: RwLock<Option<UnicityCertificate>>,

    /// Root round tracking for repeat UC detection
    last_root_round: AtomicU64,
}

impl RoundState {
    /// Create new RoundState, optionally initializing from genesis UC
    pub fn new(genesis_uc: Option<UnicityCertificate>) -> Self {
        let next_round = if let Some(ref uc) = genesis_uc {
            // Initialize next expected round from genesis UC
            uc.input_record.as_ref()
                .map(|ir| ir.round_number + 1)
                .unwrap_or(1)
        } else {
            1
        };

        let last_root = genesis_uc.as_ref()
            .and_then(|uc| uc.unicity_seal.as_ref())
            .map(|seal| seal.root_chain_round_number)
            .unwrap_or(0);

        Self {
            proposed_block: Mutex::new(None),
            next_expected_round: AtomicU64::new(next_round),
            last_uc: RwLock::new(genesis_uc),
            last_root_round: AtomicU64::new(last_root),
        }
    }

    /// Set the proposed block (called before submitting certification request)
    pub fn set_proposed_block(&self, info: ProposedBlockInfo) {
        *self.proposed_block.lock().unwrap() = Some(info);
    }

    /// Clear the proposed block and return it (called on finalization or failure)
    pub fn clear_proposed_block(&self) -> Option<ProposedBlockInfo> {
        self.proposed_block.lock().unwrap().take()
    }

    /// Get a copy of the proposed block if present
    pub fn get_proposed_block(&self) -> Option<ProposedBlockInfo> {
        self.proposed_block.lock().unwrap().clone()
    }

    /// Get next expected round number
    pub fn get_next_expected_round(&self) -> u64 {
        self.next_expected_round.load(Ordering::SeqCst)
    }

    /// Set next expected round number (from TechnicalRecord)
    pub fn set_next_expected_round(&self, round: u64) {
        self.next_expected_round.store(round, Ordering::SeqCst);
    }

    /// Get last root round number
    pub fn get_last_root_round(&self) -> u64 {
        self.last_root_round.load(Ordering::SeqCst)
    }

    /// Set last root round number (from UC)
    pub fn set_last_root_round(&self, round: u64) {
        self.last_root_round.store(round, Ordering::SeqCst);
    }

    /// Get a reference to last UC
    pub fn get_last_uc(&self) -> Option<UnicityCertificate> {
        self.last_uc.read().unwrap().clone()
    }

    /// Set last UC (from CertificationResponse)
    pub fn set_last_uc(&self, uc: UnicityCertificate) {
        *self.last_uc.write().unwrap() = Some(uc);
    }
}

mod bytes_helper {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(bytes.as_slice(), serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: &[u8] = serde_bytes::deserialize(deserializer)?;
        Ok(bytes.to_vec())
    }
}

mod option_bytes_helper {
    use serde::{Deserializer, Deserialize, Serializer};

    pub fn serialize<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(b) => serde_bytes::serialize(b.as_slice(), serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper(#[serde(with = "serde_bytes")] Vec<u8>);

        let opt: Option<Helper> = Option::deserialize(deserializer)?;
        Ok(opt.map(|Helper(v)| v))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbor_serialization() {
        let input_record = InputRecord {
            version: 1,
            round_number: 1,
            epoch: 0,
            previous_hash: Some(vec![0u8; 32]),
            hash: Some(vec![1u8; 32]),
            summary_value: Some(vec![]),
            timestamp: 1234567890,
            block_hash: Some(vec![]),
            sum_of_earned_fees: 0,
            et_hash: Some(vec![]),
        };

        let req = BlockCertificationRequest {
            partition_id: 1,
            shard_id: vec![1],
            node_id: "test-node".to_string(),
            input_record,
            zk_proof: vec![0xAA, 0xBB, 0xCC],
            block_size: 1000,
            state_size: 500,
            signature: vec![],
        };

        let cbor_bytes = crate::cbor::serialize_certification_request(&req).unwrap();
        println!("CBOR hex: {}", hex::encode(&cbor_bytes));
        println!("CBOR length: {}", cbor_bytes.len());

        // Print diagnostic CBOR structure
        use ciborium::Value;
        let value: Value = ciborium::de::from_reader(&cbor_bytes[..]).unwrap();
        println!("CBOR structure: {:#?}", value);
    }

    #[test]
    fn test_input_record_matches_state_identical() {
        let ir1 = InputRecord {
            version: 1,
            round_number: 42,
            epoch: 0,
            previous_hash: Some(vec![0u8; 32]),
            hash: Some(vec![1u8; 32]),
            summary_value: Some(vec![]),
            timestamp: 1234567890,
            block_hash: Some(vec![2u8; 32]),
            sum_of_earned_fees: 0,
            et_hash: Some(vec![]),
        };

        let ir2 = ir1.clone();

        assert!(ir1.matches_state(&ir2), "Identical InputRecords should match");
    }

    #[test]
    fn test_input_record_matches_state_different_round() {
        let ir1 = InputRecord {
            version: 1,
            round_number: 42,
            epoch: 0,
            previous_hash: Some(vec![0u8; 32]),
            hash: Some(vec![1u8; 32]),
            summary_value: Some(vec![]),
            timestamp: 1234567890,
            block_hash: Some(vec![2u8; 32]),
            sum_of_earned_fees: 0,
            et_hash: Some(vec![]),
        };

        let mut ir2 = ir1.clone();
        ir2.round_number = 43; // Different round

        assert!(!ir1.matches_state(&ir2), "Different round numbers should not match");
    }

    #[test]
    fn test_input_record_matches_state_different_hash() {
        let ir1 = InputRecord {
            version: 1,
            round_number: 42,
            epoch: 0,
            previous_hash: Some(vec![0u8; 32]),
            hash: Some(vec![1u8; 32]),
            summary_value: Some(vec![]),
            timestamp: 1234567890,
            block_hash: Some(vec![2u8; 32]),
            sum_of_earned_fees: 0,
            et_hash: Some(vec![]),
        };

        let mut ir2 = ir1.clone();
        ir2.hash = Some(vec![99u8; 32]); // Different hash

        assert!(!ir1.matches_state(&ir2), "Different state hashes should not match");
    }

    #[test]
    fn test_input_record_matches_state_different_previous_hash() {
        let ir1 = InputRecord {
            version: 1,
            round_number: 42,
            epoch: 0,
            previous_hash: Some(vec![0u8; 32]),
            hash: Some(vec![1u8; 32]),
            summary_value: Some(vec![]),
            timestamp: 1234567890,
            block_hash: Some(vec![2u8; 32]),
            sum_of_earned_fees: 0,
            et_hash: Some(vec![]),
        };

        let mut ir2 = ir1.clone();
        ir2.previous_hash = Some(vec![88u8; 32]); // Different previous hash

        assert!(!ir1.matches_state(&ir2), "Different previous hashes should not match");
    }

    #[test]
    fn test_round_state_new_with_genesis_uc() {
        // Create a mock genesis UC at round 0
        let genesis_ir = InputRecord {
            version: 1,
            round_number: 0,
            epoch: 0,
            previous_hash: None,
            hash: Some(vec![0u8; 32]),
            summary_value: Some(vec![]),
            timestamp: 1234567890,
            block_hash: Some(vec![]),
            sum_of_earned_fees: 0,
            et_hash: Some(vec![]),
        };

        let genesis_seal = UnicitySeal {
            version: 1,
            network_id: 1,
            root_chain_round_number: 100,
            epoch: 0,
            timestamp: 1234567890,
            previous_hash: vec![0u8; 32],
            hash: vec![1u8; 32],
            signatures: std::collections::HashMap::new(),
        };

        let genesis_uc = UnicityCertificate {
            version: 1,
            input_record: Some(genesis_ir),
            tr_hash: None,
            shard_conf_hash: None,
            shard_tree_certificate: ShardTreeCertificate {
                shard: vec![],
                sibling_hashes: vec![],
            },
            unicity_tree_certificate: None,
            unicity_seal: Some(genesis_seal),
        };

        let round_state = RoundState::new(Some(genesis_uc));

        // Should initialize next round to genesis round + 1
        assert_eq!(round_state.get_next_expected_round(), 1, "Next round should be 1 (genesis + 1)");

        // Should initialize last root round from genesis seal
        assert_eq!(round_state.get_last_root_round(), 100, "Last root round should match genesis seal");

        // Should have genesis UC stored
        assert!(round_state.get_last_uc().is_some(), "Should have genesis UC stored");

        // Should have no proposed block initially
        assert!(round_state.get_proposed_block().is_none(), "Should have no proposed block initially");
    }

    #[test]
    fn test_round_state_new_without_genesis_uc() {
        let round_state = RoundState::new(None);

        // Should initialize next round to 1 by default
        assert_eq!(round_state.get_next_expected_round(), 1, "Next round should default to 1");

        // Should initialize last root round to 0
        assert_eq!(round_state.get_last_root_round(), 0, "Last root round should default to 0");

        // Should have no UC stored
        assert!(round_state.get_last_uc().is_none(), "Should have no UC stored");

        // Should have no proposed block
        assert!(round_state.get_proposed_block().is_none(), "Should have no proposed block");
    }

    #[test]
    fn test_round_state_proposed_block_lifecycle() {
        let round_state = RoundState::new(None);

        // Initially no proposed block
        assert!(round_state.get_proposed_block().is_none());

        // Set a proposed block
        let proposed = ProposedBlockInfo {
            block_number: 1,
            block_hash: H256::from_low_u64_be(0x1234),
            state_root: H256::from_low_u64_be(0xABCD),
            parent_state_root: H256::zero(),
            timestamp: 1234567890,
        };

        round_state.set_proposed_block(proposed.clone());

        // Should be able to retrieve it
        let retrieved = round_state.get_proposed_block();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.block_number, 1);
        assert_eq!(retrieved.block_hash, H256::from_low_u64_be(0x1234));

        // Clear it
        let cleared = round_state.clear_proposed_block();
        assert!(cleared.is_some());
        assert_eq!(cleared.unwrap().block_number, 1);

        // Should be none after clearing
        assert!(round_state.get_proposed_block().is_none());
    }
}
