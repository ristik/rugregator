// Criterion benchmarks for core SMT operations.
//
// Three groups:
//   batch_insert       — batch_insert() into a CoW snapshot, no persistence
//   verify_consistency — verify_consistency() on a pre-generated proof
//   inclusion_proof    — get_inclusion_proof() for a single key
//
// Each group is parameterised by (prefill_size, batch_size).  Throughput is
// reported as elements/sec so different batch sizes are directly comparable.
//
// Run:
//   cargo bench -p rsmt
//   cargo bench -p rsmt -- --save-baseline before   # save a named baseline
//   cargo bench -p rsmt -- --baseline before         # compare against it

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use rsmt::consistency::{batch_insert, batch_insert_with_proof, verify_consistency};
use rsmt::path::SmtKey;
use rsmt::SparseMerkleTree;

// ─── Key generation ──────────────────────────────────────────────────────────

/// LCG-based key generator: no external deps, reproducible across runs.
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

fn build_prefilled_tree(n: usize) -> SparseMerkleTree {
    let mut tree = SparseMerkleTree::new();
    if n > 0 {
        let prefill = gen_batch(n, 0xdead_beef_cafe_0000);
        batch_insert(&mut tree, &prefill).expect("prefill failed");
    }
    tree
}

// ─── Benchmark: batch_insert ─────────────────────────────────────────────────

// Measures the time to insert a batch into a CoW snapshot and compute the root
// hash.  The snapshot is created from the pre-filled tree inside the timing
// window because it is O(1) (Arc clone), so it's negligible and keeps the
// benchmark self-contained.

fn bench_batch_insert(c: &mut Criterion) {
    let prefill_sizes = [0usize, 10_000, 100_000];
    let batch_sizes   = [100usize, 1_000, 10_000];

    let mut group = c.benchmark_group("batch_insert");

    for &prefill in &prefill_sizes {
        let tree = build_prefilled_tree(prefill);

        for &batch_size in &batch_sizes {
            let batch = gen_batch(batch_size, 0x1234_5678_9abc_def0);

            group.throughput(Throughput::Elements(batch_size as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("prefill_{prefill}"), batch_size),
                &batch_size,
                |b, _| {
                    b.iter(|| {
                        let mut snap = tree.deep_clone();
                        let result = batch_insert(black_box(&mut snap), black_box(&batch));
                        let _ = black_box(snap.root_hash());
                        result
                    });
                },
            );
        }
    }

    group.finish();
}

// ─── Benchmark: verify_consistency ───────────────────────────────────────────

// Proof generation is done once in setup; only verify_consistency() is timed.
// The proof and sorted batch are pre-computed so this is a pure CPU cost.

fn bench_verify_consistency(c: &mut Criterion) {
    let prefill_sizes = [0usize, 10_000, 100_000];
    let batch_sizes   = [100usize, 1_000, 10_000];

    let mut group = c.benchmark_group("verify_consistency");

    for &prefill in &prefill_sizes {
        for &batch_size in &batch_sizes {
            // Build tree + generate proof once per (prefill, batch_size) pair.
            let mut tree = build_prefilled_tree(prefill);
            let batch = gen_batch(batch_size, 0xfeed_face_dead_beef);
            let old_root = tree.root_hash();
            let (inserted, proof) =
                batch_insert_with_proof(&mut tree, &batch).expect("insert failed");
            let new_root = tree.root_hash();

            group.throughput(Throughput::Elements(batch_size as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("prefill_{prefill}"), batch_size),
                &batch_size,
                |b, _| {
                    b.iter(|| {
                        verify_consistency(
                            black_box(&proof),
                            black_box(old_root),
                            black_box(new_root),
                            black_box(&inserted),
                        )
                    });
                },
            );
        }
    }

    group.finish();
}

// ─── Benchmark: inclusion_proof ──────────────────────────────────────────────

// get_inclusion_proof() for a single key — representative of the per-request
// proof latency after a round has committed.

fn bench_inclusion_proof(c: &mut Criterion) {
    let prefill_sizes = [1_000usize, 10_000, 100_000];

    let mut group = c.benchmark_group("inclusion_proof");

    for &prefill in &prefill_sizes {
        let mut tree = build_prefilled_tree(prefill);
        // Pick a key that is guaranteed to be in the tree.
        let probe_batch = gen_batch(1, 0xdead_beef_cafe_0000);
        let _ = batch_insert(&mut tree, &probe_batch);
        let probe_key = probe_batch[0].0;

        group.bench_function(BenchmarkId::from_parameter(prefill), |b| {
            b.iter(|| tree.get_inclusion_proof(black_box(&probe_key)));
        });
    }

    group.finish();
}

// ─── Registration ────────────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_batch_insert,
    bench_verify_consistency,
    bench_inclusion_proof,
);
criterion_main!(benches);
