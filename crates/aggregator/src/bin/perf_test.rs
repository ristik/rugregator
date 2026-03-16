//! SMT performance benchmark.
//!
//! Inserts successive batches into a *persistent* tree so each round inherits
//! all previously inserted leaves.  This reveals how insertion throughput and
//! proof latency degrade as the tree grows.
//!
//! Usage:
//!   cargo run --release --bin perf-test [options]
//!
//! Options:
//!   --rounds N            Rounds per batch-size run  (default: 6)
//!   --seed S              PRNG seed                  (default: 42)
//!   --proof-sample N      Proofs sampled per round   (default: 200)
//!   --batch-sizes X,Y,..  Comma-separated sizes      (default: 1000,5000,10000)
//!   --csv                 Also emit a CSV table

use std::time::{Duration, Instant};

use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

use uni_aggregator::smt::{SmtPath, SmtSnapshot, SparseMerkleTree, state_id_to_smt_path};
use uni_aggregator::validation::state_id::compute_cert_data_hash_imprint;

// ─── CLI ─────────────────────────────────────────────────────────────────────

struct Config {
    rounds:       usize,
    seed:         u64,
    proof_sample: usize,
    batch_sizes:  Vec<usize>,
    csv:          bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rounds:       6,
            seed:         42,
            proof_sample: 200,
            batch_sizes:  vec![1_000, 5_000, 10_000],
            csv:          false,
        }
    }
}

fn parse_args() -> Config {
    let mut cfg = Config::default();
    let mut args = std::env::args().skip(1).peekable();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--rounds"       => { if let Some(v) = args.next() { cfg.rounds       = v.parse().unwrap_or(cfg.rounds); } }
            "--seed"         => { if let Some(v) = args.next() { cfg.seed         = v.parse().unwrap_or(cfg.seed); } }
            "--proof-sample" => { if let Some(v) = args.next() { cfg.proof_sample = v.parse().unwrap_or(cfg.proof_sample); } }
            "--batch-sizes"  => {
                if let Some(v) = args.next() {
                    let parsed: Vec<usize> = v.split(',')
                        .filter_map(|s| s.trim().parse().ok())
                        .collect();
                    if !parsed.is_empty() { cfg.batch_sizes = parsed; }
                }
            }
            "--csv" => { cfg.csv = true; }
            _ => {}
        }
    }
    cfg
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() { return 0.0; }
    let idx = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn fmt_dur(d: Duration) -> String {
    let us = d.as_secs_f64() * 1e6;
    if us < 1_000.0      { format!("{:.1}µs",  us) }
    else if us < 1_000_000.0 { format!("{:.2}ms", us / 1_000.0) }
    else                 { format!("{:.2}s",  us / 1_000_000.0) }
}

/// Generate `n` random (smt_path, leaf_value) pairs using the given rng.
fn gen_leaves(n: usize, rng: &mut StdRng) -> Vec<(SmtPath, Vec<u8>)> {
    (0..n).map(|_| {
        let mut state_id = [0u8; 32];
        let mut pred     = [0u8; 38];
        let mut ssh      = [0u8; 32];
        let mut txh      = [0u8; 32];
        let mut wit      = [0u8; 65];
        rng.fill(&mut state_id[..]);
        rng.fill(&mut pred[..]);
        rng.fill(&mut ssh[..]);
        rng.fill(&mut txh[..]);
        rng.fill(&mut wit[..]);
        let path  = state_id_to_smt_path(&state_id);
        let value = compute_cert_data_hash_imprint(&pred, &ssh, &txh, &wit);
        (path, value.to_vec())
    }).collect()
}

// ─── One measurement row ─────────────────────────────────────────────────────

#[derive(Debug)]
struct Row {
    batch_size:   usize,
    pre_fill:     usize,   // leaves already in tree before this batch
    inserted:     usize,   // actually inserted (excluding duplicates)
    insert_ms:    f64,
    throughput:   f64,     // inserted/s
    root_ms:      f64,
    proof_p50_us: f64,
    proof_p95_us: f64,
}

fn measure_round(
    tree:         &mut SparseMerkleTree,
    pre_fill:     usize,
    batch:        &[(SmtPath, Vec<u8>)],
    proof_sample: usize,
    rng:          &mut StdRng,
) -> Row {
    let batch_size = batch.len();

    // ── Insert via snapshot (mirrors the real round path) ────────────────────
    let mut snap = SmtSnapshot::create(tree);
    let mut inserted = 0usize;

    let t_ins = Instant::now();
    for (path, value) in batch {
        if snap.add_leaf(path.clone(), value.clone()).is_ok() {
            inserted += 1;
        }
    }
    let insert_dur = t_ins.elapsed();

    // ── Root hash ─────────────────────────────────────────────────────────────
    let t_root = Instant::now();
    let _ = snap.root_hash_imprint();
    let root_dur = t_root.elapsed();

    snap.commit(tree);

    // ── Proof generation on a random sample ──────────────────────────────────
    let n = batch.len();
    let sample: Vec<usize> = (0..proof_sample.min(inserted))
        .map(|_| rng.gen_range(0..n))
        .collect();

    let mut proof_times: Vec<f64> = Vec::with_capacity(sample.len());
    for &i in &sample {
        let t = Instant::now();
        let _ = tree.get_path(&batch[i].0);
        proof_times.push(t.elapsed().as_secs_f64() * 1e6);
    }
    proof_times.sort_by(|a, b| a.partial_cmp(b).unwrap());

    Row {
        batch_size,
        pre_fill,
        inserted,
        insert_ms:    insert_dur.as_secs_f64() * 1e3,
        throughput:   inserted as f64 / insert_dur.as_secs_f64(),
        root_ms:      root_dur.as_secs_f64() * 1e3,
        proof_p50_us: percentile(&proof_times, 50.0),
        proof_p95_us: percentile(&proof_times, 95.0),
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    let cfg = parse_args();

    println!("SMT Performance Benchmark");
    println!("  rounds={}, seed={}, proof_sample={}", cfg.rounds, cfg.seed, cfg.proof_sample);
    println!("  batch_sizes={:?}", cfg.batch_sizes);
    println!();

    if cfg.csv {
        println!("batch_size,pre_fill,inserted,insert_ms,throughput_leaves_per_s,root_ms,proof_p50_us,proof_p95_us");
    }

    for &batch_size in &cfg.batch_sizes {
        println!("── Batch size: {} ───────────────────────────────────────", batch_size);
        println!(
            "  {:>10}  {:>10}  {:>12}  {:>10}  {:>10}  {:>10}  {:>10}",
            "pre_fill", "inserted", "leaves/s", "insert", "root", "proof p50", "proof p95"
        );

        let mut tree     = SparseMerkleTree::new();
        let mut pre_fill = 0usize;
        // Use a single RNG that advances across rounds so each batch is fresh data.
        let mut rng      = StdRng::seed_from_u64(cfg.seed);

        for round in 0..cfg.rounds {
            let batch = gen_leaves(batch_size, &mut rng);
            let mut proof_rng = StdRng::seed_from_u64(cfg.seed.wrapping_add(round as u64 * 999_983));

            let row = measure_round(&mut tree, pre_fill, &batch, cfg.proof_sample, &mut proof_rng);

            println!(
                "  {:>10}  {:>10}  {:>12.0}  {:>10}  {:>10}  {:>9.1}µs  {:>9.1}µs",
                row.pre_fill,
                row.inserted,
                row.throughput,
                fmt_dur(Duration::from_secs_f64(row.insert_ms / 1e3)),
                fmt_dur(Duration::from_secs_f64(row.root_ms   / 1e3)),
                row.proof_p50_us,
                row.proof_p95_us,
            );

            if cfg.csv {
                println!(
                    "{},{},{},{:.3},{:.0},{:.3},{:.2},{:.2}",
                    row.batch_size, row.pre_fill, row.inserted,
                    row.insert_ms, row.throughput, row.root_ms,
                    row.proof_p50_us, row.proof_p95_us,
                );
            }

            pre_fill += row.inserted;
        }
        println!();
    }
}
