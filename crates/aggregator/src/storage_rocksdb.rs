//! RocksDB-backed persistence store.

use rocksdb::{
    BlockBasedOptions, BoundColumnFamily, Cache, ColumnFamilyDescriptor, DBCompressionType,
    Options, WriteBatch, DB,
};
use std::sync::Arc;

use crate::api::cbor::CertDataFields;
use crate::storage::{
    BlockInfo, FinalizedRecord, PendingRound, RecordInfo, RecoveredState, Store, WalRecord,
    WalStore,
};

// ─── Column families ──────────────────────────────────────────────────────────

const CF_RECORDS: &str = "records";
const CF_BLOCKS: &str = "blocks";
const CF_META: &str = "meta";
/// Pre-BFT write-ahead log for the currently in-flight round.
const CF_PENDING_ROUND: &str = "pending_round";
/// SMT node storage — used by `smt-store`.
pub const CF_SMT_NODES: &str = "smt_nodes";
/// SMT metadata (committed root hash) — used by `smt-store`.
pub const CF_SMT_META: &str = "smt_meta";
/// SMT leaf values — reserved for future MemSmt::LeavesOnly persistence.
pub const CF_SMT_LEAVES: &str = "smt_leaves";

const KEY_BLOCK_NUMBER: &[u8] = b"block_number";
/// Single-key WAL entry: the pending in-flight round.
const KEY_PENDING: &[u8] = b"pending";

// ─── RocksDbStore ─────────────────────────────────────────────────────────────

pub struct RocksDbStore {
    db: Arc<DB>,
}

impl RocksDbStore {
    /// Open (or create) the database at `path`, returning a `RocksDbStore`
    /// and a shared `Arc<DB>` suitable for passing to `DiskBackedSmt`.
    /// Open (or create) the database at `path`.
    ///
    /// `block_cache_bytes` controls the RocksDB block cache size for the
    /// `smt_nodes` column family.  Pass 0 to use RocksDB's default (~8 MB).
    pub fn open(path: &str, block_cache_bytes: usize) -> anyhow::Result<(Self, Arc<DB>)> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_max_open_files(1024);

        let mut node_opts = Options::default();
        node_opts.set_compression_type(DBCompressionType::Lz4);

        if block_cache_bytes > 0 {
            let cache = Cache::new_lru_cache(block_cache_bytes);
            let mut table_opts = BlockBasedOptions::default();
            table_opts.set_block_cache(&cache);
            node_opts.set_block_based_table_factory(&table_opts);
        }

        let cfs = [
            ColumnFamilyDescriptor::new(CF_RECORDS, Options::default()),
            ColumnFamilyDescriptor::new(CF_BLOCKS, Options::default()),
            ColumnFamilyDescriptor::new(CF_META, Options::default()),
            ColumnFamilyDescriptor::new(CF_PENDING_ROUND, Options::default()),
            ColumnFamilyDescriptor::new(CF_SMT_NODES, node_opts),
            ColumnFamilyDescriptor::new(CF_SMT_META, Options::default()),
            ColumnFamilyDescriptor::new(CF_SMT_LEAVES, Options::default()),
        ];
        let db = Arc::new(DB::open_cf_descriptors(&opts, path, cfs.into_iter())?);
        Ok((
            Self {
                db: Arc::clone(&db),
            },
            db,
        ))
    }

    pub fn recover(&self) -> anyhow::Result<RecoveredState> {
        let cf_records = cf(&self.db, CF_RECORDS)?;
        let cf_blocks = cf(&self.db, CF_BLOCKS)?;
        let cf_meta = cf(&self.db, CF_META)?;

        let block_number = match self.db.get_cf(&cf_meta, KEY_BLOCK_NUMBER)? {
            Some(v) => u64::from_be_bytes(v[..8].try_into()?),
            None => 1,
        };

        let mut records = Vec::new();
        for item in self
            .db
            .iterator_cf(&cf_records, rocksdb::IteratorMode::Start)
        {
            let (k, v) = item?;
            records.push(decode_record(&k, &v)?);
        }

        let mut blocks = Vec::new();
        for item in self
            .db
            .iterator_cf(&cf_blocks, rocksdb::IteratorMode::Start)
        {
            let (k, v) = item?;
            blocks.push(decode_block(&k, &v)?);
        }

        Ok(RecoveredState {
            block_number,
            records,
            blocks,
        })
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
        let cf_blocks = cf(&self.db, CF_BLOCKS)?;
        let cf_meta = cf(&self.db, CF_META)?;
        let cf_pending = cf(&self.db, CF_PENDING_ROUND)?;

        let mut batch = WriteBatch::default();

        for r in records {
            let key = hex::decode(&r.state_id_hex)?;
            let val = encode_record(
                r.block_number,
                r.reference_time,
                &r.cert_data,
                r.merkle_path_cbor.as_deref().unwrap_or(&[]),
            );
            batch.put_cf(&cf_records, &key, &val);
        }

        batch.put_cf(
            &cf_blocks,
            block.block_number.to_be_bytes(),
            encode_block(block),
        );
        batch.put_cf(&cf_meta, KEY_BLOCK_NUMBER, next_block_number.to_be_bytes());
        // Clear the WAL entry atomically: after this write the round is committed
        // and the in-flight entry must no longer exist.
        batch.delete_cf(&cf_pending, KEY_PENDING);

        self.db.write(batch)?;
        Ok(())
    }
}

impl WalStore for RocksDbStore {
    fn write_pending_round(&self, round: &PendingRound) -> anyhow::Result<()> {
        let cf = cf(&self.db, CF_PENDING_ROUND)?;
        self.db
            .put_cf(&cf, KEY_PENDING, encode_pending_round(round))?;
        Ok(())
    }

    fn load_pending_round(&self) -> anyhow::Result<Option<PendingRound>> {
        let cf = cf(&self.db, CF_PENDING_ROUND)?;
        match self.db.get_cf(&cf, KEY_PENDING)? {
            Some(v) => Ok(Some(decode_pending_round(&v)?)),
            None => Ok(None),
        }
    }

    fn clear_pending_round(&self) -> anyhow::Result<()> {
        let cf = cf(&self.db, CF_PENDING_ROUND)?;
        self.db.delete_cf(&cf, KEY_PENDING)?;
        Ok(())
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn cf<'a>(db: &'a DB, name: &str) -> anyhow::Result<Arc<BoundColumnFamily<'a>>> {
    db.cf_handle(name)
        .ok_or_else(|| anyhow::anyhow!("column family '{}' not found", name))
}

// ─── Encoding ────────────────────────────────────────────────────────────────

fn encode_record(
    block_number: u64,
    reference_time: u64,
    cert: &CertDataFields,
    merkle_path_cbor: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&block_number.to_be_bytes());
    buf.extend_from_slice(&reference_time.to_be_bytes());
    write_var(&mut buf, &cert.predicate_cbor);
    buf.extend_from_slice(&cert.source_state_hash);
    buf.extend_from_slice(&cert.transaction_hash);
    write_var(&mut buf, &cert.witness);
    write_var(&mut buf, merkle_path_cbor);
    buf
}

fn encode_block(b: &BlockInfo) -> Vec<u8> {
    let root = b.root_hash.unwrap_or([0u8; 32]);
    let mut buf = Vec::with_capacity(32 + 4 + b.uc_cbor.len());
    buf.extend_from_slice(&root);
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

    let block_number = read_u64(val, &mut p)?;
    let reference_time = read_u64(val, &mut p)?;
    let predicate_cbor = read_var(val, &mut p)?;
    let source_state_hash = read_exact(val, &mut p, 32)?;
    let transaction_hash = read_exact(val, &mut p, 32)?;
    let witness = read_var(val, &mut p)?;
    let merkle_path_cbor = read_var(val, &mut p)?;

    Ok((
        state_id_hex,
        RecordInfo {
            block_number,
            reference_time,
            cert_data: CertDataFields {
                predicate_cbor,
                source_state_hash,
                transaction_hash,
                witness,
            },
            merkle_path_cbor: Some(merkle_path_cbor),
        },
    ))
}

fn decode_block(key: &[u8], val: &[u8]) -> anyhow::Result<BlockInfo> {
    let block_number = u64::from_be_bytes(key.try_into()?);
    let raw: [u8; 32] = val[..32].try_into()?;
    let root_hash = if raw == [0u8; 32] { None } else { Some(raw) };
    let mut p = 32usize;
    let uc_cbor = read_var(val, &mut p)?;
    Ok(BlockInfo {
        block_number,
        root_hash,
        uc_cbor,
    })
}

fn read_u64(buf: &[u8], p: &mut usize) -> anyhow::Result<u64> {
    if buf.len() < *p + 8 {
        anyhow::bail!("truncated u64");
    }
    let v = u64::from_be_bytes(buf[*p..*p + 8].try_into()?);
    *p += 8;
    Ok(v)
}

fn read_var(buf: &[u8], p: &mut usize) -> anyhow::Result<Vec<u8>> {
    if buf.len() < *p + 4 {
        anyhow::bail!("truncated length prefix");
    }
    let len = u32::from_be_bytes(buf[*p..*p + 4].try_into()?) as usize;
    *p += 4;
    if buf.len() < *p + len {
        anyhow::bail!("truncated data (need {})", len);
    }
    let v = buf[*p..*p + len].to_vec();
    *p += len;
    Ok(v)
}

fn read_exact(buf: &[u8], p: &mut usize, n: usize) -> anyhow::Result<Vec<u8>> {
    if buf.len() < *p + n {
        anyhow::bail!("truncated fixed field (need {})", n);
    }
    let v = buf[*p..*p + n].to_vec();
    *p += n;
    Ok(v)
}

// ─── WAL encoding ─────────────────────────────────────────────────────────────

fn encode_pending_round(r: &PendingRound) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&r.block_number.to_be_bytes());
    buf.extend_from_slice(&r.reference_time.to_be_bytes());
    write_opt_hash(&mut buf, r.prev_root.as_ref());
    write_opt_hash(&mut buf, r.new_root.as_ref());
    buf.extend_from_slice(&r.new_leaves.to_be_bytes());
    buf.extend_from_slice(&r.state_size.to_be_bytes());
    write_var(&mut buf, r.zk_proof.as_deref().unwrap_or(&[]));
    buf.extend_from_slice(&(r.inserted.len() as u32).to_be_bytes());
    for rec in &r.inserted {
        write_var(&mut buf, &rec.state_id);
        write_var(&mut buf, &rec.predicate_cbor);
        buf.extend_from_slice(&pad32(&rec.source_state_hash));
        buf.extend_from_slice(&pad32(&rec.transaction_hash));
        write_var(&mut buf, &rec.witness);
    }
    buf
}

fn decode_pending_round(buf: &[u8]) -> anyhow::Result<PendingRound> {
    let mut p = 0;
    let block_number = read_u64(buf, &mut p)?;
    let reference_time = read_u64(buf, &mut p)?;
    let prev_root = read_opt_hash(buf, &mut p)?;
    let new_root = read_opt_hash(buf, &mut p)?;
    let new_leaves = read_u64(buf, &mut p)?;
    let state_size = read_u64(buf, &mut p)?;
    let zk_raw = read_var(buf, &mut p)?;
    let zk_proof = if zk_raw.is_empty() {
        None
    } else {
        Some(zk_raw)
    };
    let count = read_u32(buf, &mut p)? as usize;
    let mut inserted = Vec::with_capacity(count);
    for _ in 0..count {
        let state_id = read_var(buf, &mut p)?;
        let predicate_cbor = read_var(buf, &mut p)?;
        let source_state_hash = read_exact(buf, &mut p, 32)?;
        let transaction_hash = read_exact(buf, &mut p, 32)?;
        let witness = read_var(buf, &mut p)?;
        inserted.push(WalRecord {
            state_id,
            predicate_cbor,
            source_state_hash,
            transaction_hash,
            witness,
        });
    }
    Ok(PendingRound {
        block_number,
        reference_time,
        prev_root,
        new_root,
        zk_proof,
        new_leaves,
        state_size,
        inserted,
    })
}

fn write_opt_hash(buf: &mut Vec<u8>, h: Option<&[u8; 32]>) {
    match h {
        Some(hash) => {
            buf.push(1);
            buf.extend_from_slice(hash);
        }
        None => {
            buf.push(0);
        }
    }
}

fn read_opt_hash(buf: &[u8], p: &mut usize) -> anyhow::Result<Option<[u8; 32]>> {
    if buf.len() <= *p {
        anyhow::bail!("truncated opt-hash flag");
    }
    let flag = buf[*p];
    *p += 1;
    if flag == 0 {
        return Ok(None);
    }
    if buf.len() < *p + 32 {
        anyhow::bail!("truncated opt-hash value");
    }
    let h: [u8; 32] = buf[*p..*p + 32].try_into()?;
    *p += 32;
    Ok(Some(h))
}

fn read_u32(buf: &[u8], p: &mut usize) -> anyhow::Result<u32> {
    if buf.len() < *p + 4 {
        anyhow::bail!("truncated u32");
    }
    let v = u32::from_be_bytes(buf[*p..*p + 4].try_into()?);
    *p += 4;
    Ok(v)
}

/// Pad or truncate a slice to exactly 32 bytes.
fn pad32(v: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let n = v.len().min(32);
    out[..n].copy_from_slice(&v[..n]);
    out
}
