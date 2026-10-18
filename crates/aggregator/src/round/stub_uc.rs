//! Native-valid unicity certificates for `--bft-mode stub`.
//!
//! The stub stands in for BFT Core, but the certificates it issues are checked
//! by the same verifiers as real ones (the Go `UnicityCertificate.Verify`, the
//! Go consolidation client and both state-transition SDKs). Every field is
//! therefore constructed the way a real unsharded partition would:
//!
//! * an explicit positive test partition (default [`DEFAULT_PARTITION_ID`]);
//! * a technical record whose hash is the certificate's `trHash`, never null;
//! * a shard configuration hash derived from the profile, and one coherent
//!   network / epoch / epoch-start / round policy shared with the explicit
//!   test trust anchor ([`trust_base_json`]);
//! * an input record that satisfies `InputRecord.IsValid` (a changed state
//!   carries a block hash, an unchanged one does not);
//! * the empty shard ID with no sibling hashes, and a single-partition unicity
//!   tree whose root is the seal hash.
//!
//! The matching anchor is *test-only*: its private key is a published constant.
//! It must never be configured as a trust base of a real network.
//!
//! Certificates issued before this profile (partition 0, null `trHash`, epoch 0)
//! cannot be repaired in place; see `docs/stub-uc-migration.md`.

use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

use crate::api::cbor::{
    INPUT_RECORD_TAG, SHARD_TREE_CERTIFICATE_TAG, UNICITY_CERTIFICATE_TAG, UNICITY_SEAL_TAG,
    UNICITY_TREE_CERTIFICATE_TAG,
};

/// Partition the stub certifies unless configured otherwise: the fixed Unicity
/// aggregation partition (`AGGREGATION_PARTITION_ID` of the SDKs, 7). Partition 0
/// is never valid.
pub const DEFAULT_PARTITION_ID: u32 = 7;
/// The stub's default before the fixed aggregation partition (arch-cd D3). Stub
/// certificates of this partition are experimental data that needs a reset.
const RETIRED_DEFAULT_PARTITION_ID: u64 = 1;
/// `NetworkId::LOCAL` of the SDKs and `NetworkLocal` of bft-go-base.
pub const NETWORK_ID: u64 = 3;
/// Epoch of both the shard (input record, technical record) and the root chain
/// (seal); the anchor is of the same epoch.
pub const EPOCH: u64 = 1;
/// Root round at which [`EPOCH`] starts. Block numbers start at 1, so every
/// certificate's seal round is at or after it.
pub const EPOCH_START_ROUND: u64 = 1;
/// Test-only signing key of the single root node.
pub const PRIVATE_KEY: [u8; 32] = [7u8; 32];
/// Identifier of the single root node in seal signature maps.
pub const NODE_ID: &str = "NODE";

/// Inputs of one certificate.
#[derive(Clone, Copy, Debug)]
pub struct StubUcParams<'a> {
    pub partition_id: u32,
    /// Shard round number, which the stub keeps equal to the block number.
    pub block_number: u64,
    /// Root certified by the previous block (`None` for the first block or an empty tree).
    pub prev_root: Option<&'a [u8; 32]>,
    /// Root certified by this block (`None` for an empty tree).
    pub new_root: Option<&'a [u8; 32]>,
    /// `InputRecord.timestamp`: the reference time this block's leaves were built under.
    pub reference_time: u64,
    /// `UnicitySeal.timestamp`: the next round's reference time.
    pub seal_timestamp: u64,
    /// Unicity tree root of the previous seal, if known.
    pub prev_seal_hash: Option<&'a [u8; 32]>,
}

/// A generated certificate and the seal hash that chains the next one.
pub struct StubUc {
    pub cbor: Vec<u8>,
    pub seal_hash: [u8; 32],
}

fn cbor_uint(n: u64) -> Vec<u8> {
    if n < 24 {
        vec![n as u8]
    } else if n < 0x100 {
        vec![0x18, n as u8]
    } else if n < 0x10000 {
        vec![0x19, (n >> 8) as u8, n as u8]
    } else if n < 0x1_0000_0000 {
        let mut v = vec![0x1A];
        v.extend_from_slice(&(n as u32).to_be_bytes());
        v
    } else {
        let mut v = vec![0x1B];
        v.extend_from_slice(&n.to_be_bytes());
        v
    }
}

fn cbor_head(major: u8, n: usize) -> Vec<u8> {
    let m = major << 5;
    if n < 24 {
        vec![m | n as u8]
    } else if n < 0x100 {
        vec![m | 24, n as u8]
    } else {
        vec![m | 25, (n >> 8) as u8, n as u8]
    }
}

fn cbor_bytes(data: &[u8]) -> Vec<u8> {
    let mut v = cbor_head(2, data.len());
    v.extend_from_slice(data);
    v
}

fn cbor_text(s: &str) -> Vec<u8> {
    let mut v = cbor_head(3, s.len());
    v.extend_from_slice(s.as_bytes());
    v
}

fn cbor_null() -> Vec<u8> {
    vec![0xF6]
}

fn cbor_opt_bytes(data: Option<&[u8]>) -> Vec<u8> {
    match data {
        Some(d) => cbor_bytes(d),
        None => cbor_null(),
    }
}

fn cbor_array(items: &[&[u8]]) -> Vec<u8> {
    let mut v = cbor_head(4, items.len());
    for item in items {
        v.extend_from_slice(item);
    }
    v
}

fn cbor_tag(tag: u64, data: &[u8]) -> Vec<u8> {
    let mut v = if tag < 24 {
        vec![0xC0 | tag as u8]
    } else if tag < 0x100 {
        vec![0xD8, tag as u8]
    } else {
        vec![0xD9, (tag >> 8) as u8, tag as u8]
    };
    v.extend_from_slice(data);
    v
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Hash of the shard configuration of the stub partition.
///
/// It is a fixed function of the profile, so a client may pin it
/// independently of any certificate.
pub fn shard_conf_hash(partition_id: u32) -> [u8; 32] {
    let mut pre = b"rugregator-stub-shard-conf/v1".to_vec();
    pre.extend_from_slice(&partition_id.to_be_bytes());
    pre.extend_from_slice(&NETWORK_ID.to_be_bytes());
    pre.extend_from_slice(&EPOCH.to_be_bytes());
    sha256(&pre)
}

/// CBOR of the technical record `[round, epoch, leader, statHash, feeHash]`
/// the certificate's `trHash` commits to: the record for the next round.
pub fn technical_record(block_number: u64) -> Vec<u8> {
    let stat = sha256(b"rugregator-stub-stat/v1");
    let fee = sha256(b"rugregator-stub-fee/v1");
    cbor_array(&[
        &cbor_uint(block_number + 1),
        &cbor_uint(EPOCH),
        &cbor_text(NODE_ID),
        &cbor_bytes(&stat),
        &cbor_bytes(&fee),
    ])
}

fn block_hash(block_number: u64, root: &[u8]) -> [u8; 32] {
    let mut pre = b"rugregator-stub-block/v1".to_vec();
    pre.extend_from_slice(&block_number.to_be_bytes());
    pre.extend_from_slice(root);
    sha256(&pre)
}

/// Compressed public key of [`PRIVATE_KEY`].
pub fn public_key() -> [u8; 33] {
    let sk = SecretKey::from_slice(&PRIVATE_KEY).expect("valid test key");
    PublicKey::from_secret_key(&Secp256k1::new(), &sk).serialize()
}

/// The explicit test trust anchor matching [`generate`], in the JSON shape the
/// SDKs load (`RootTrustBase.fromJSON`).
pub fn trust_base_json() -> serde_json::Value {
    serde_json::json!({
        "version": "1",
        "networkId": NETWORK_ID,
        "epoch": EPOCH.to_string(),
        "epochStartRound": EPOCH_START_ROUND.to_string(),
        "rootNodes": [{
            "nodeId": NODE_ID,
            "sigKey": hex::encode(public_key()),
            "stake": "1",
        }],
        "quorumThreshold": "1",
        "stateHash": "",
        "changeRecordHash": null,
        "previousEntryHash": null,
        "signatures": {},
    })
}

/// Generate the certificate for one block. Panics only if `partition_id` is 0
/// or the fixed test key is invalid.
pub fn generate(p: &StubUcParams<'_>) -> StubUc {
    assert!(
        p.partition_id != 0,
        "partition 0 is never a valid partition"
    );
    let root: &[u8] = p.new_root.map(|r| r.as_slice()).unwrap_or(&[]);
    let prev: Option<&[u8]> = p.prev_root.map(|r| r.as_slice());
    let changed = prev.unwrap_or(&[]) != root;
    // InputRecord.IsValid: the block hash is present exactly when the state changed.
    let bh = changed.then(|| block_hash(p.block_number, root));

    let input_record = cbor_tag(
        INPUT_RECORD_TAG,
        &cbor_array(&[
            &cbor_uint(1),
            &cbor_uint(p.block_number),
            &cbor_uint(EPOCH),
            &cbor_opt_bytes(prev),
            &cbor_bytes(root),
            &cbor_bytes(&[]),
            &cbor_uint(p.reference_time),
            &cbor_opt_bytes(bh.as_ref().map(|b| b.as_slice())),
            &cbor_uint(0),
            &cbor_null(),
        ]),
    );

    let tr_hash = sha256(&technical_record(p.block_number));
    let conf = shard_conf_hash(p.partition_id);

    // Shard tree certificate of the empty shard ID: no siblings, so the shard
    // tree root is the hash of the leaf itself.
    let mut leaf = Vec::new();
    leaf.extend_from_slice(&input_record);
    leaf.extend_from_slice(&cbor_bytes(&tr_hash));
    leaf.extend_from_slice(&cbor_bytes(&conf));
    let shard_root = sha256(&leaf);

    // Single-leaf unicity tree: H(tagLeaf, key, H(shardRoot)).
    let data_hash = sha256(&cbor_bytes(&shard_root));
    let mut tree = Vec::new();
    tree.extend_from_slice(&cbor_bytes(&[0x01]));
    tree.extend_from_slice(&cbor_bytes(&p.partition_id.to_be_bytes()));
    tree.extend_from_slice(&cbor_bytes(&data_hash));
    let seal_hash = sha256(&tree);

    let seal_fields = |sigs: &[u8]| {
        cbor_array(&[
            &cbor_uint(1),
            &cbor_uint(NETWORK_ID),
            &cbor_uint(p.block_number),
            &cbor_uint(EPOCH),
            &cbor_uint(p.seal_timestamp),
            &cbor_opt_bytes(p.prev_seal_hash.map(|h| h.as_slice())),
            &cbor_bytes(&seal_hash),
            sigs,
        ])
    };
    let unsigned = cbor_tag(UNICITY_SEAL_TAG, &seal_fields(&cbor_null()));
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&PRIVATE_KEY).expect("valid test key");
    let msg = Message::from_digest(sha256(&unsigned));
    let (rec_id, compact) = secp.sign_ecdsa_recoverable(&msg, &sk).serialize_compact();
    let mut sig = [0u8; 65];
    sig[..64].copy_from_slice(&compact);
    sig[64] = rec_id.to_i32() as u8;
    let mut sig_map = vec![0xA1];
    sig_map.extend_from_slice(&cbor_text(NODE_ID));
    sig_map.extend_from_slice(&cbor_bytes(&sig));
    let seal = cbor_tag(UNICITY_SEAL_TAG, &seal_fields(&sig_map));

    let shard_tree_cert = cbor_tag(
        SHARD_TREE_CERTIFICATE_TAG,
        &cbor_array(&[
            &cbor_uint(1),
            &cbor_bytes(&[0x80]), // canonical empty ShardId end-marker encoding
            &cbor_array(&[]),
        ]),
    );
    let unicity_tree_cert = cbor_tag(
        UNICITY_TREE_CERTIFICATE_TAG,
        &cbor_array(&[
            &cbor_uint(1),
            &cbor_uint(p.partition_id as u64),
            &cbor_array(&[]),
        ]),
    );

    let cbor = cbor_tag(
        UNICITY_CERTIFICATE_TAG,
        &cbor_array(&[
            &cbor_uint(1),
            &input_record,
            &cbor_bytes(&tr_hash),
            &cbor_bytes(&conf),
            &shard_tree_cert,
            &unicity_tree_cert,
            &seal,
        ]),
    );
    StubUc { cbor, seal_hash }
}

/// Why `uc_cbor` is not a native-valid certificate of the stub profile, if it
/// is one of the legacy stub certificates (partition 0 or the retired default 1,
/// null technical-record hash, epoch 0) issued before this profile. `None` means no legacy marker was
/// found; it is not a verification result. Real native certificates never carry
/// these markers, so the check is independent of the BFT mode.
pub fn legacy_stub_marker(uc_cbor: &[u8]) -> Option<&'static str> {
    use ciborium::Value;
    let Value::Tag(_, uc) = crate::api::cbor::decode_cbor_value(uc_cbor).ok()? else {
        return None;
    };
    let Value::Array(uc) = *uc else { return None };
    if matches!(uc.get(2), Some(Value::Null)) {
        return Some("technical record hash is null");
    }
    if let Some(Value::Tag(_, utc)) = uc.get(5) {
        if let Value::Array(utc) = &**utc {
            if matches!(utc.get(1), Some(Value::Integer(i)) if u64::try_from(*i) == Ok(0)) {
                return Some("partition id is 0");
            }
            if matches!(utc.get(1), Some(Value::Integer(i)) if u64::try_from(*i) == Ok(RETIRED_DEFAULT_PARTITION_ID))
            {
                return Some("partition id is the retired stub default 1");
            }
        }
    }
    if let Some(Value::Tag(_, seal)) = uc.get(6) {
        if let Value::Array(seal) = &**seal {
            if matches!(seal.get(3), Some(Value::Integer(i)) if u64::try_from(*i) == Ok(0)) {
                return Some("root epoch is 0");
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params<'a>(
        block_number: u64,
        prev: Option<&'a [u8; 32]>,
        new: Option<&'a [u8; 32]>,
    ) -> StubUcParams<'a> {
        StubUcParams {
            partition_id: DEFAULT_PARTITION_ID,
            block_number,
            prev_root: prev,
            new_root: new,
            reference_time: 1_755_000_000,
            seal_timestamp: 1_755_000_001,
            prev_seal_hash: None,
        }
    }

    #[test]
    fn generated_certificates_carry_no_legacy_marker() {
        let a = [0xA1; 32];
        for uc in [
            generate(&params(1, None, Some(&a))),
            generate(&params(2, Some(&a), Some(&a))),
            generate(&params(3, Some(&a), None)),
            generate(&params(4, None, None)),
        ] {
            assert_eq!(legacy_stub_marker(&uc.cbor), None);
        }
    }

    #[test]
    fn block_hash_is_present_exactly_when_the_state_changes() {
        use ciborium::Value;
        let a = [0xA1; 32];
        let b = [0xB2; 32];
        for (prev, new, changed) in [
            (None, Some(&a), true),
            (Some(&a), Some(&b), true),
            (Some(&a), Some(&a), false),
            (Some(&a), None, true),
            (None, None, false),
        ] {
            let uc = generate(&params(5, prev, new));
            let Value::Tag(_, v) = crate::api::cbor::decode_cbor_value(&uc.cbor).unwrap() else {
                panic!()
            };
            let Value::Array(v) = *v else { panic!() };
            let Value::Tag(_, ir) = &v[1] else { panic!() };
            let Value::Array(ir) = &**ir else { panic!() };
            assert_eq!(!matches!(ir[7], Value::Null), changed, "{prev:?}->{new:?}");
            assert_eq!(matches!(ir[3], Value::Null), prev.is_none());
        }
    }

    #[test]
    fn technical_record_hash_is_32_bytes_and_distinct_per_block() {
        let a = [0xA1; 32];
        let one = generate(&params(1, None, Some(&a)));
        let two = generate(&params(2, Some(&a), Some(&a)));
        assert_ne!(one.cbor, two.cbor);
        assert_eq!(sha256(&technical_record(1)).len(), 32);
        assert_ne!(technical_record(1), technical_record(2));
    }

    /// The legacy shape, as the stub issued it before this profile: detected by its markers.
    #[test]
    fn legacy_marker_detection() {
        let legacy_tr_null = cbor_tag(
            UNICITY_CERTIFICATE_TAG,
            &cbor_array(&[&cbor_uint(1), &cbor_null(), &cbor_null()]),
        );
        assert_eq!(
            legacy_stub_marker(&legacy_tr_null),
            Some("technical record hash is null")
        );
        assert_eq!(legacy_stub_marker(&[0xaa]), None);
    }

    /// The default is the fixed aggregation partition, and a certificate of the retired default
    /// (partition 1) is flagged as old experimental data that needs a reset.
    #[test]
    fn the_default_is_the_aggregation_partition_and_the_retired_default_is_flagged() {
        assert_eq!(DEFAULT_PARTITION_ID, 7);
        let a = [0xA1; 32];
        let retired = generate(&StubUcParams {
            partition_id: 1,
            ..params(1, None, Some(&a))
        });
        assert_eq!(
            legacy_stub_marker(&retired.cbor),
            Some("partition id is the retired stub default 1")
        );
        assert_eq!(
            legacy_stub_marker(&generate(&params(1, None, Some(&a))).cbor),
            None
        );
    }

    #[test]
    #[should_panic(expected = "partition 0")]
    fn partition_zero_is_refused() {
        let mut p = params(1, None, None);
        p.partition_id = 0;
        generate(&p);
    }

    #[test]
    fn trust_base_matches_the_profile() {
        let tb = trust_base_json();
        assert_eq!(tb["networkId"], NETWORK_ID);
        assert_eq!(tb["epoch"], EPOCH.to_string());
        assert_eq!(tb["epochStartRound"], EPOCH_START_ROUND.to_string());
        assert_eq!(tb["rootNodes"][0]["nodeId"], NODE_ID);
        assert_eq!(
            tb["rootNodes"][0]["sigKey"].as_str().unwrap().len(),
            66,
            "compressed secp256k1 key"
        );
    }
}
