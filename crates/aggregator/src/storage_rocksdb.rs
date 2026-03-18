#![cfg(feature = "rocksdb-storage")]
//! RocksDB-backed persistence store.

use std::sync::Arc;
use rocksdb::{BoundColumnFamily, ColumnFamilyDescriptor, DB, DBCompressionType, Options, WriteBatch};

use crate::api::cbor::CertDataFields;
use crate::storage::{BlockInfo, FinalizedRecord, RecordInfo, RecoveredState, Store};

// ─── Column families ──────────────────────────────────────────────────────────

const CF_RECORDS:   &str = "records";
const CF_BLOCKS:    &str = "blocks";
const CF_META:      &str = "meta";
/// SMT node storage — used by `smt_disk`.
pub const CF_SMT_NODES: &str = "smt_nodes";
/// SMT metadata (committed root hash) — used by `smt_disk`.
pub const CF_SMT_META:  &str = "smt_meta";

const KEY_BLOCK_NUMBER: &[u8] = b"block_number";

// ─── RocksDbStore ─────────────────────────────────────────────────────────────

pub struct RocksDbStore {
    db: Arc<DB>,
}

impl RocksDbStore {
    /// Open (or create) the database at `path`, returning a `RocksDbStore`
    /// and a shared `Arc<DB>` suitable for passing to `DiskBackedSmt`.
    pub fn open(path: &str) -> anyhow::Result<(Self, Arc<DB>)> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let mut node_opts = Options::default();
        node_opts.set_compression_type(DBCompressionType::Lz4);

        let cfs = [
            ColumnFamilyDescriptor::new(CF_RECORDS,   Options::default()),
            ColumnFamilyDescriptor::new(CF_BLOCKS,    Options::default()),
            ColumnFamilyDescriptor::new(CF_META,      Options::default()),
            ColumnFamilyDescriptor::new(CF_SMT_NODES, node_opts),
            ColumnFamilyDescriptor::new(CF_SMT_META,  Options::default()),
        ];
        let db = Arc::new(DB::open_cf_descriptors(&opts, path, cfs.into_iter())?);
        Ok((Self { db: Arc::clone(&db) }, db))
    }

    pub fn recover(&self) -> anyhow::Result<RecoveredState> {
        let cf_records = cf(&self.db, CF_RECORDS)?;
        let cf_blocks  = cf(&self.db, CF_BLOCKS)?;
        let cf_meta    = cf(&self.db, CF_META)?;

        let block_number = match self.db.get_cf(&cf_meta, KEY_BLOCK_NUMBER)? {
            Some(v) => u64::from_be_bytes(v[..8].try_into()?),
            None    => 1,
        };

        let mut records = Vec::new();
        for item in self.db.iterator_cf(&cf_records, rocksdb::IteratorMode::Start) {
            let (k, v) = item?;
            records.push(decode_record(&k, &v)?);
        }

        let mut blocks = Vec::new();
        for item in self.db.iterator_cf(&cf_blocks, rocksdb::IteratorMode::Start) {
            let (k, v) = item?;
            blocks.push(decode_block(&k, &v)?);
        }

        Ok(RecoveredState { block_number, records, blocks })
    }
}

impl Store for RocksDbStore {
    fn persist_round(
        &self,
        block: &BlockInfo,
        records: &[FinalizedRecord],
        next_block_number: u64,
    ) -> anyhow::Result<()> {
        let cf_records = cf(&self.db, CF_RECORDS)?;
        let cf_blocks  = cf(&self.db, CF_BLOCKS)?;
        let cf_meta    = cf(&self.db, CF_META)?;

        let mut batch = WriteBatch::default();

        for r in records {
            let key = hex::decode(&r.state_id_hex)?;
            let val = encode_record(r.block_number, &r.cert_data, &r.merkle_path_cbor);
            batch.put_cf(&cf_records, &key, &val);
        }

        batch.put_cf(&cf_blocks, block.block_number.to_be_bytes(), encode_block(block));
        batch.put_cf(&cf_meta,   KEY_BLOCK_NUMBER, next_block_number.to_be_bytes());

        self.db.write(batch)?;
        Ok(())
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn cf<'a>(db: &'a DB, name: &str) -> anyhow::Result<Arc<BoundColumnFamily<'a>>> {
    db.cf_handle(name).ok_or_else(|| anyhow::anyhow!("column family '{}' not found", name))
}

// ─── Encoding ────────────────────────────────────────────────────────────────

fn encode_record(block_number: u64, cert: &CertDataFields, merkle_path_cbor: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&block_number.to_be_bytes());
    write_var(&mut buf, &cert.predicate_cbor);
    buf.extend_from_slice(&cert.source_state_hash);
    buf.extend_from_slice(&cert.transaction_hash);
    write_var(&mut buf, &cert.witness);
    write_var(&mut buf, merkle_path_cbor);
    buf
}

fn encode_block(b: &BlockInfo) -> Vec<u8> {
    let mut buf = Vec::with_capacity(34 + 4 + b.uc_cbor.len());
    buf.extend_from_slice(&b.root_hash);
    write_var(&mut buf, &b.uc_cbor);
    buf
}

fn write_var(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

// ─── Decoding ────────────────────────────────────────────────────────────────

fn decode_record(key: &[u8], val: &[u8]) -> anyhow::Result<(String, RecordInfo)> {
    let state_id_hex = hex::encode(key);
    let mut p = 0usize;

    let block_number      = read_u64(val, &mut p)?;
    let predicate_cbor    = read_var(val, &mut p)?;
    let source_state_hash = read_exact(val, &mut p, 32)?;
    let transaction_hash  = read_exact(val, &mut p, 32)?;
    let witness           = read_var(val, &mut p)?;
    let merkle_path_cbor  = read_var(val, &mut p)?;

    Ok((state_id_hex, RecordInfo {
        block_number,
        cert_data: CertDataFields { predicate_cbor, source_state_hash, transaction_hash, witness },
        merkle_path_cbor,
    }))
}

fn decode_block(key: &[u8], val: &[u8]) -> anyhow::Result<BlockInfo> {
    let block_number = u64::from_be_bytes(key.try_into()?);
    let root_hash: [u8; 34] = val[..34].try_into()?;
    let mut p = 34usize;
    let uc_cbor = read_var(val, &mut p)?;
    Ok(BlockInfo { block_number, root_hash, uc_cbor })
}

fn read_u64(buf: &[u8], p: &mut usize) -> anyhow::Result<u64> {
    if buf.len() < *p + 8 { anyhow::bail!("truncated u64"); }
    let v = u64::from_be_bytes(buf[*p..*p+8].try_into()?);
    *p += 8;
    Ok(v)
}

fn read_var(buf: &[u8], p: &mut usize) -> anyhow::Result<Vec<u8>> {
    if buf.len() < *p + 4 { anyhow::bail!("truncated length prefix"); }
    let len = u32::from_be_bytes(buf[*p..*p+4].try_into()?) as usize;
    *p += 4;
    if buf.len() < *p + len { anyhow::bail!("truncated data (need {})", len); }
    let v = buf[*p..*p+len].to_vec();
    *p += len;
    Ok(v)
}

fn read_exact(buf: &[u8], p: &mut usize, n: usize) -> anyhow::Result<Vec<u8>> {
    if buf.len() < *p + n { anyhow::bail!("truncated fixed field (need {})", n); }
    let v = buf[*p..*p+n].to_vec();
    *p += n;
    Ok(v)
}
