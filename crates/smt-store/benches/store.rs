// Criterion benchmarks for SMT-store commit performance.
//
// Two groups:
//   mem_full_commit   — commit a batch to a MemSmt (PersistMode::Full), writing
//                       the delta nodes + leaves to RocksDB each round.
//   mem_leaves_commit — commit with PersistMode::LeavesOnly (leaf-only writes).
//
// Each group is parameterised by (prefill_size, batch_size).
//
// The benchmark uses iter_custom so that snapshot creation and batch insertion
// are excluded from the measured window — only snap.commit() is timed.
//
// Run:
//   cargo bench -p smt-store
//   cargo bench -p smt-store -- --save-baseline before
//   cargo bench -p smt-store -- --baseline before

use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rocksdb::{ColumnFamilyDescriptor, DBCompressionType, Options, DB};
use tempfile::TempDir;

use smt_store::mem::{CF_SMT_LEAVES, PersistMode};
use smt_store::{DiskSmt, MemSmt, SmtStore, SmtStoreSnapshot};
use smt_store::disk::materializer::CF_SMT_NODES;
use smt_store::disk::store::CF_SMT_META;

use rsmt::path::SmtKey;

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn lcg_next(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *seed
}

fn gen_key(seed: &mut u64) -> SmtKey {
    let mut k = [0u8; 32];
    for chunk in k.chunks_exact_mut(8) {
        chunk.copy_from_slice(&lcg_next(seed).to_le_bytes());
    }
    k
}

fn gen_batch(n: usize, seed: u64) -> Vec<(SmtKey, Vec<u8>)> {
    let mut s = seed;
    (0..n)
        .map(|_| (gen_key(&mut s), lcg_next(&mut s).to_le_bytes().to_vec()))
        .collect()
}

/// Open a RocksDB instance with the CFs required by MemSmt.
fn open_db(dir: &TempDir) -> Arc<DB> {
    let path = dir.path().to_str().unwrap();
    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);

    let mut node_opts = Options::default();
    node_opts.set_compression_type(DBCompressionType::Lz4);

    let cfs = [
        ColumnFamilyDescriptor::new(CF_SMT_LEAVES, Options::default()),
        ColumnFamilyDescriptor::new(CF_SMT_NODES,  node_opts),
        ColumnFamilyDescriptor::new(CF_SMT_META,   Options::default()),
    ];
    Arc::new(DB::open_cf_descriptors(&opts, path, cfs).unwrap())
}

/// Build a MemSmt pre-filled with `prefill` leaves.
fn build_store(prefill: usize, mode: PersistMode, dir: &TempDir) -> MemSmt {
    let db = open_db(dir);
    let mut store = MemSmt::open(db, mode).unwrap();
    if prefill > 0 {
        let batch = gen_batch(prefill, 0xdead_beef_cafe_0000);
        let mut snap = store.create_snapshot();
        snap.insert_batch(&batch, false).unwrap();
        snap.commit(&mut store).unwrap();
    }
    store
}

/// Build a DiskSmt pre-filled with `prefill` leaves.
fn build_disk_store(prefill: usize, dir: &TempDir) -> DiskSmt {
    let db = open_db(dir);
    let mut store = DiskSmt::open(db, 0).unwrap();
    if prefill > 0 {
        let batch = gen_batch(prefill, 0xdead_beef_cafe_0000);
        let mut snap = store.create_snapshot();
        snap.insert_batch(&batch, false).unwrap();
        snap.commit(&mut store).unwrap();
    }
    store
}

// ─── Core measurement ────────────────────────────────────────────────────────

/// Measure `iters` commits against a MemSmt using batches from `seed_base`.
///
/// Setup (create_snapshot + insert_batch) is outside the timing window;
/// only snap.commit() is measured.
fn time_commits(store: &mut MemSmt, iters: u64, batch_size: usize, seed_base: u64) -> Duration {
    let mut total = Duration::ZERO;
    for i in 0..iters {
        let seed = seed_base.wrapping_add(i.wrapping_mul(999_983));
        let batch = gen_batch(batch_size, seed);

        // Setup outside the window.
        let mut snap = store.create_snapshot();
        snap.insert_batch(&batch, false).unwrap();

        // Measure only the commit.
        let t0 = Instant::now();
        snap.commit(store).unwrap();
        total += t0.elapsed();
    }
    total
}

/// Measure `iters` commits against a DiskSmt.
///
/// Snapshot creation, insertion, and `root_hash()` (which triggers
/// materialization from disk + in-memory tree build) are outside the timing
/// window.  Only the RocksDB write (`commit_overlay`) is measured.
fn time_disk_commits(store: &mut DiskSmt, iters: u64, batch_size: usize, seed_base: u64) -> Duration {
    let mut total = Duration::ZERO;
    for i in 0..iters {
        let seed = seed_base.wrapping_add(i.wrapping_mul(999_983));
        let batch = gen_batch(batch_size, seed);

        // Setup outside the window: materialize + insert + build overlay.
        let mut snap = store.create_snapshot();
        snap.insert_batch(&batch, false).unwrap();
        let _ = snap.root_hash().unwrap(); // flushes pending → builds overlay in memory

        // Measure only the RocksDB write.
        let t0 = Instant::now();
        snap.commit(store).unwrap();
        total += t0.elapsed();
    }
    total
}

// ─── Benchmark: mem_full_commit ───────────────────────────────────────────────

fn bench_mem_full_commit(c: &mut Criterion) {
    let prefill_sizes = [0usize, 10_000, 100_000];
    let batch_sizes   = [100usize, 1_000, 10_000];

    let mut group = c.benchmark_group("mem_full_commit");

    for &prefill in &prefill_sizes {
        for &batch_size in &batch_sizes {
            group.throughput(Throughput::Elements(batch_size as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("prefill_{prefill}"), batch_size),
                &batch_size,
                |b, &batch_size| {
                    // Build the pre-filled store once; re-use across criterion
                    // samples.  The store grows by `batch_size` per iteration
                    // but prefill >> batch_size * typical_iters.
                    let dir = TempDir::new().unwrap();
                    let mut store = build_store(prefill, PersistMode::Full, &dir);

                    b.iter_custom(|iters| {
                        time_commits(&mut store, iters, batch_size, 0x1234_5678_9abc_def0)
                    });
                },
            );
        }
    }

    group.finish();
}

// ─── Benchmark: mem_leaves_commit ─────────────────────────────────────────────

fn bench_mem_leaves_commit(c: &mut Criterion) {
    let prefill_sizes = [0usize, 10_000, 100_000];
    let batch_sizes   = [100usize, 1_000, 10_000];

    let mut group = c.benchmark_group("mem_leaves_commit");

    for &prefill in &prefill_sizes {
        for &batch_size in &batch_sizes {
            group.throughput(Throughput::Elements(batch_size as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("prefill_{prefill}"), batch_size),
                &batch_size,
                |b, &batch_size| {
                    let dir = TempDir::new().unwrap();
                    let mut store = build_store(prefill, PersistMode::LeavesOnly, &dir);

                    b.iter_custom(|iters| {
                        time_commits(&mut store, iters, batch_size, 0x1234_5678_9abc_def0)
                    });
                },
            );
        }
    }

    group.finish();
}

// ─── Benchmark: disk_commit ───────────────────────────────────────────────────

fn bench_disk_commit(c: &mut Criterion) {
    let prefill_sizes = [0usize, 10_000, 100_000];
    let batch_sizes   = [100usize, 1_000, 10_000];

    let mut group = c.benchmark_group("disk_commit");

    for &prefill in &prefill_sizes {
        for &batch_size in &batch_sizes {
            group.throughput(Throughput::Elements(batch_size as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("prefill_{prefill}"), batch_size),
                &batch_size,
                |b, &batch_size| {
                    let dir = TempDir::new().unwrap();
                    let mut store = build_disk_store(prefill, &dir);

                    b.iter_custom(|iters| {
                        time_disk_commits(&mut store, iters, batch_size, 0x1234_5678_9abc_def0)
                    });
                },
            );
        }
    }

    group.finish();
}

// ─── Registration ────────────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_mem_full_commit,
    bench_mem_leaves_commit,
    bench_disk_commit,
);
criterion_main!(benches);
