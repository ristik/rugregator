//! SMT performance benchmark.
//!
//! Measures insertion throughput and inclusion-proof generation latency for
//! the Sparse Merkle Tree across a range of batch sizes.
//!
//! Usage:
//!   cargo run --release --bin perf-test [--rounds N] [--seed S]

use std::time::{Duration, Instant};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

use uni_aggregator::smt::{SparseMerkleTree, SmtSnapshot, state_id_to_smt_path};
use uni_aggregator::validation::state_id::compute_cert_data_hash_imprint;

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct Config {
    /// Number of benchmark rounds per batch size.
    rounds: usize,
    /// PRNG seed for reproducibility.
    seed: u64,
    /// Batch sizes to test.
    batch_sizes: Vec<usize>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rounds: 3,
            seed: 42,
            batch_sizes: vec![100, 1_000, 5_000, 10_000, 50_000],
        }
    }
}

fn parse_args() -> Config {
    let mut cfg = Config::default();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--rounds" => {
                if let Some(v) = args.next() { cfg.rounds = v.parse().unwrap_or(cfg.rounds); }
            }
            "--seed" => {
                if let Some(v) = args.next() { cfg.seed = v.parse().unwrap_or(cfg.seed); }
            }
            _ => {}
        }
    }
    cfg
}

// ─── Stat helpers ─────────────────────────────────────────────────────────────

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() { return 0.0; }
    let idx = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn fmt_dur(d: Duration) -> String {
    let us = d.as_secs_f64() * 1e6;
    if us < 1000.0 { format!("{:.1}µs", us) }
    else if us < 1_000_000.0 { format!("{:.2}ms", us / 1000.0) }
    else { format!("{:.2}s", us / 1_000_000.0) }
}

// ─── Leaf generation ──────────────────────────────────────────────────────────

/// Generate `n` random (smt_path, leaf_value_imprint) pairs.
fn gen_leaves(n: usize, rng: &mut StdRng) -> Vec<(uni_aggregator::smt::SmtPath, Vec<u8>)> {
    (0..n).map(|_| {
        let mut state_id = [0u8; 32];
        let mut pred = [0u8; 38]; // minimal predicate CBOR bytes
        let mut ssh  = [0u8; 32];
        let mut txh  = [0u8; 32];
        let mut wit  = [0u8; 65];
        rng.fill(&mut state_id[..]);
        rng.fill(&mut pred[..]);
        rng.fill(&mut ssh[..]);
        rng.fill(&mut txh[..]);
        rng.fill(&mut wit[..]);
        let path = state_id_to_smt_path(&state_id);
        let leaf = compute_cert_data_hash_imprint(&pred, &ssh, &txh, &wit);
        (path, leaf.to_vec())
    }).collect()
}

// ─── Benchmark sections ───────────────────────────────────────────────────────

/// Benchmark: insert `leaves` into a fresh tree.
/// Returns (total insert duration, root hash duration).
fn bench_insert(leaves: &[(uni_aggregator::smt::SmtPath, Vec<u8>)]) -> (Duration, Duration) {
    let mut tree = SparseMerkleTree::new();

    let t0 = Instant::now();
    for (path, value) in leaves {
        let _ = tree.add_leaf(path.clone(), value.clone());
    }
    let insert_dur = t0.elapsed();

    let t1 = Instant::now();
    let _ = tree.root_hash_imprint();
    let root_dur = t1.elapsed();

    (insert_dur, root_dur)
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    let cfg = parse_args();
    let proof_sample = 200; // proofs to sample per round

    println!("SMT Performance Benchmark");
    println!("  rounds={}, seed={}, proof_sample={}", cfg.rounds, cfg.seed, proof_sample);
    println!();

    for &batch_size in &cfg.batch_sizes {
        println!("── Batch size: {} leaves ──────────────────────────────", batch_size);

        let mut insert_throughputs: Vec<f64> = Vec::new();
        let mut root_times: Vec<f64> = Vec::new();
        let mut proof_latencies: Vec<f64> = Vec::new();

        for round in 0..cfg.rounds {
            let mut rng = StdRng::seed_from_u64(cfg.seed.wrapping_add(round as u64 * 1_000_003));
            let leaves = gen_leaves(batch_size, &mut rng);

            // Insertion + root hash (simulates the round processing path).
            let (ins_dur, root_dur) = bench_insert(&leaves);

            // Proof generation (sample `proof_sample` random leaves).
            let mut rng2 = StdRng::seed_from_u64(cfg.seed.wrapping_add(round as u64 * 999_983));
            let mut tree = SparseMerkleTree::new();
            let mut snap = SmtSnapshot::create(&tree);
            for (path, value) in &leaves {
                let _ = snap.add_leaf(path.clone(), value.clone());
            }
            snap.commit(&mut tree);
            let _ = tree.root_hash_imprint(); // warm root cache

            let indices: Vec<usize> = (0..proof_sample)
                .map(|_| rng2.gen_range(0..batch_size))
                .collect();
            let t_proof = Instant::now();
            for &i in &indices {
                let _ = tree.get_path(&leaves[i].0);
            }
            let proof_dur = t_proof.elapsed();

            let throughput = batch_size as f64 / ins_dur.as_secs_f64();
            insert_throughputs.push(throughput);
            root_times.push(root_dur.as_secs_f64() * 1e6);

            let per_proof_us = proof_dur.as_secs_f64() * 1e6 / proof_sample as f64;
            proof_latencies.push(per_proof_us);

            println!(
                "  round {}: insert={} ({:.0} leaves/s)  root={:>8}  proof/req={:.1}µs",
                round + 1,
                fmt_dur(ins_dur),
                throughput,
                fmt_dur(root_dur),
                per_proof_us,
            );
        }

        // Aggregated stats.
        insert_throughputs.sort_by(|a, b| a.partial_cmp(b).unwrap());
        root_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
        proof_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

        println!(
            "  ┌─ throughput  p50={:.0} p95={:.0} leaves/s",
            percentile(&insert_throughputs, 50.0),
            percentile(&insert_throughputs, 95.0),
        );
        println!(
            "  ├─ root hash   p50={:.1}µs p95={:.1}µs",
            percentile(&root_times, 50.0),
            percentile(&root_times, 95.0),
        );
        println!(
            "  └─ proof gen   p50={:.1}µs p95={:.1}µs per proof",
            percentile(&proof_latencies, 50.0),
            percentile(&proof_latencies, 95.0),
        );
        println!();
    }
}
