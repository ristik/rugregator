//! Verifies rugregator's stub-anchor fixture with the Rust SDK.
use unicity_token::api::bft::{RootTrustBase, UnicityCertificate};
use unicity_token::cbor::Decoder;
use unicity_token::verify::{SealAuthenticator, SealSession};

#[test]
fn stub_fixture_is_valid_for_the_rust_sdk() {
    let path = std::env::var("STUB_FIXTURE").expect("STUB_FIXTURE");
    let f: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let tb = RootTrustBase::from_json(&f["trustBase"].to_string()).unwrap();
    tb.validate().unwrap();
    let mut n = 0;
    for c in f["certificates"].as_array().unwrap() {
        let raw = hex::decode(c["unicityCertificate"].as_str().unwrap()).unwrap();
        let uc = UnicityCertificate::from_cbor(Decoder::new(&raw)).unwrap();
        assert_eq!(uc.to_cbor(), raw, "canonical re-encoding");
        assert_eq!(uc.technical_record_hash.as_ref().map(|h| h.len()), Some(32));
        assert_eq!(uc.unicity_tree_certificate.partition_identifier, f["partitionId"].as_u64().unwrap() as u32);
        let computed = uc.computed_seal_hash().unwrap();
        assert_eq!(computed.data(), uc.unicity_seal.hash.as_slice(), "path to seal hash");
        SealSession::new(&tb).authenticate_seal(&uc.unicity_seal).unwrap();
        n += 1;
    }
    assert_eq!(n, 6);
}
