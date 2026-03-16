//! Storage for Unicity Certificates and certification state

use crate::types::UnicityCertificate;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::info;

/// In-memory storage for Unicity Certificates
/// TODO: Replace with persistent storage (e.g., RocksDB) for production
#[derive(Clone)]
pub struct UcStorage {
    // Map: round_number -> UnicityCertificate
    certificates: Arc<RwLock<HashMap<u64, UnicityCertificate>>>,
    // Track the latest round we've received
    latest_round: Arc<RwLock<Option<u64>>>,
}

impl UcStorage {
    /// Create a new UC storage instance
    pub fn new() -> Self {
        Self {
            certificates: Arc::new(RwLock::new(HashMap::new())),
            latest_round: Arc::new(RwLock::new(None)),
        }
    }

    /// Store a Unicity Certificate
    pub fn store_uc(&self, uc: UnicityCertificate) -> Result<()> {
        let round = uc.input_record.as_ref()
            .ok_or_else(|| anyhow::anyhow!("UC missing InputRecord"))?
            .round_number;

        // Update certificates map
        {
            let mut certs = self.certificates.write()
                .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;
            certs.insert(round, uc);
        }

        // Update latest round
        {
            let mut latest = self.latest_round.write()
                .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

            match *latest {
                None => {
                    *latest = Some(round);
                }
                Some(current) => {
                    if round > current {
                        *latest = Some(round);
                    }
                }
            }
        }

        info!("✓ UC stored for round {}", round);
        Ok(())
    }

    /// Get a UC for a specific round
    pub fn get_uc(&self, round: u64) -> Result<Option<UnicityCertificate>> {
        let certs = self.certificates.read()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

        Ok(certs.get(&round).cloned())
    }

    /// Get the latest UC
    pub fn get_latest_uc(&self) -> Result<Option<UnicityCertificate>> {
        let latest = self.latest_round.read()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

        match *latest {
            Some(round) => self.get_uc(round),
            None => Ok(None),
        }
    }

    /// Get the latest round number
    pub fn get_latest_round(&self) -> Result<Option<u64>> {
        let latest = self.latest_round.read()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

        Ok(*latest)
    }

    /// Get the number of stored UCs
    pub fn count(&self) -> Result<usize> {
        let certs = self.certificates.read()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

        Ok(certs.len())
    }
}

impl Default for UcStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_uc(round: u64) -> UnicityCertificate {
        use crate::types::*;
        use std::collections::HashMap;

        UnicityCertificate {
            version: 1,
            input_record: Some(InputRecord {
                version: 1,
                round_number: round,
                epoch: 0,
                previous_hash: Some(vec![0u8; 32]),
                hash: Some(vec![0u8; 32]),
                summary_value: Some(vec![]),
                timestamp: 0,
                block_hash: Some(vec![]),
                sum_of_earned_fees: 0,
                et_hash: Some(vec![]),
            }),
            tr_hash: Some(vec![0u8; 32]),
            shard_conf_hash: Some(vec![0u8; 32]),
            shard_tree_certificate: ShardTreeCertificate {
                shard: vec![0x80], // Empty bitstring
                sibling_hashes: vec![],
            },
            unicity_tree_certificate: Some(UnicityTreeCertificate {
                version: 1,
                partition: 1,
                hash_steps: vec![],
            }),
            unicity_seal: Some(UnicitySeal {
                version: 1,
                network_id: 1,
                root_chain_round_number: round,
                epoch: 0,
                timestamp: 0,
                previous_hash: vec![0u8; 32],
                hash: vec![0u8; 32],
                signatures: HashMap::new(),
            }),
        }
    }

    #[test]
    fn test_store_and_retrieve() {
        let storage = UcStorage::new();

        let uc = create_test_uc(100);
        storage.store_uc(uc.clone()).unwrap();

        let retrieved = storage.get_uc(100).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().input_record.as_ref().unwrap().round_number, 100);
    }

    #[test]
    fn test_latest_round() {
        let storage = UcStorage::new();

        storage.store_uc(create_test_uc(100)).unwrap();
        storage.store_uc(create_test_uc(105)).unwrap();
        storage.store_uc(create_test_uc(102)).unwrap();

        let latest = storage.get_latest_round().unwrap();
        assert_eq!(latest, Some(105));

        let latest_uc = storage.get_latest_uc().unwrap();
        assert!(latest_uc.is_some());
        assert_eq!(latest_uc.unwrap().input_record.as_ref().unwrap().round_number, 105);
    }

    #[test]
    fn test_count() {
        let storage = UcStorage::new();

        storage.store_uc(create_test_uc(100)).unwrap();
        storage.store_uc(create_test_uc(101)).unwrap();
        storage.store_uc(create_test_uc(102)).unwrap();

        assert_eq!(storage.count().unwrap(), 3);
    }
}
