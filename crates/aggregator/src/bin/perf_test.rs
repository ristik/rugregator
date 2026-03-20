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
//!   --disk                Use disk-backed SMT
//!   --cache-capacity N    Disk SMT node cache capacity (default: 500000)
//!   --db-path PATH        Persistent DB path; empty = temp dir  (default: "")
//!   --csv                 Also emit a CSV table

use std::time::{Duration, Instant};

use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

use uni_aggregator::smt::{SmtPath, SmtSnapshot, SparseMerkleTree, state_id_to_smt_path};
use uni_aggregator::validation::state_id::compute_cert_data_hash_imprint;

// ─── CLI ─────────────────────────────────────────────────────────────────────

struct Config {
    rounds:          usize,
    seed:            u64,
    proof_sample:    usize,
    batch_sizes:     Vec<usize>,
    disk:            bool,
    cache_capacity:  usize,
    db_path:         String,
    csv:             bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rounds:         6,
            seed:           42,
            proof_sample:   200,
            batch_sizes:    vec![1_000, 5_000, 10_000],
            disk:           false,
            cache_capacity: 500_000,
            db_path:        String::new(),
            csv:            false,
        }
    }
}

fn parse_args() -> Config {
    let mut cfg = Config::default();
    let mut args = std::env::args().skip(1).peekable();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--rounds"          => { if let Some(v) = args.next() { cfg.rounds         = v.parse().unwrap_or(cfg.rounds); } }
            "--seed"            => { if let Some(v) = args.next() { cfg.seed           = v.parse().unwrap_or(cfg.seed); } }
            "--proof-sample"    => { if let Some(v) = args.next() { cfg.proof_sample   = v.parse().unwrap_or(cfg.proof_sample); } }
            "--cache-capacity"  => { if let Some(v) = args.next() { cfg.cache_capacity = v.parse().unwrap_or(cfg.cache_capacity); } }
            "--db-path"         => { if let Some(v) = args.next() { cfg.db_path = v; } }
            "--batch-sizes"     => {
                if let Some(v) = args.next() {
                    let parsed: Vec<usize> = v.split(',')
                        .filter_map(|s| s.trim().parse().ok())
                        .collect();
                    if !parsed.is_empty() { cfg.batch_sizes = parsed; }
                }
            }
            "--disk" => { cfg.disk = true; }
            "--csv"  => { cfg.csv  = true; }
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
    if us < 1_000.0          { format!("{:.1}µs",  us) }
    else if us < 1_000_000.0 { format!("{:.2}ms", us / 1_000.0) }
    else                     { format!("{:.2}s",  us / 1_000_000.0) }
}

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
    pre_fill:     usize,
    inserted:     usize,
    insert_ms:    f64,
    throughput:   f64,
    root_ms:      f64,
    proof_p50_us: f64,
    proof_p95_us: f64,
}

// ─── In-memory measurement ───────────────────────────────────────────────────

fn measure_round_mem(
    tree:         &mut SparseMerkleTree,
    pre_fill:     usize,
    batch:        &[(SmtPath, Vec<u8>)],
    proof_sample: usize,
    rng:          &mut StdRng,
) -> Row {
    let batch_size = batch.len();

    let mut snap = SmtSnapshot::create(tree);
    let mut inserted = 0usize;

    let t_ins = Instant::now();
    for (path, value) in batch {
        if snap.add_leaf(path.clone(), value.clone()).is_ok() {
            inserted += 1;
        }
    }
    let insert_dur = t_ins.elapsed();

    let t_root = Instant::now();
    let _ = snap.root_hash_imprint();
    let root_dur = t_root.elapsed();

    snap.commit(tree);

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

// ─── Disk-backed measurement ──────────────────────────────────────────────────

fn measure_round_disk(
    disk:         &mut smt_store::DiskSmt,
    pre_fill:     usize,
    batch:        &[(SmtPath, Vec<u8>)],
    proof_sample: usize,
    rng:          &mut StdRng,
) -> Row {
    use smt_store::disk::overlay::Overlay;

    let batch_size = batch.len();

    let t_ins = Instant::now();
    let (new_root, overlay) = disk.batch_insert_round(batch)
        .expect("batch_insert_round failed");
    let insert_dur = t_ins.elapsed();

    let t_commit = Instant::now();
    disk.commit_overlay(overlay, new_root).expect("commit_overlay failed");
    let commit_dur = t_commit.elapsed();

    let empty_overlay = Overlay::new();
    let n = batch.len();
    let sample: Vec<usize> = (0..proof_sample.min(batch_size))
        .map(|_| rng.gen_range(0..n))
        .collect();

    let mut proof_times: Vec<f64> = Vec::with_capacity(sample.len());
    for &i in &sample {
        let t = Instant::now();
        let _ = disk.get_path(&batch[i].0, &empty_overlay);
        proof_times.push(t.elapsed().as_secs_f64() * 1e6);
    }
    proof_times.sort_by(|a, b| a.partial_cmp(b).unwrap());

    Row {
        batch_size,
        pre_fill,
        inserted: batch_size,
        insert_ms:    insert_dur.as_secs_f64() * 1e3,
        throughput:   batch_size as f64 / insert_dur.as_secs_f64(),
        root_ms:      commit_dur.as_secs_f64() * 1e3,
        proof_p50_us: percentile(&proof_times, 50.0),
        proof_p95_us: percentile(&proof_times, 95.0),
    }
}

// ─── Print helpers ────────────────────────────────────────────────────────────

fn print_header(label: &str, batch_size: usize) {
    println!("── {} batch_size={} ──────────────────────────────────────", label, batch_size);
    println!(
        "  {:>10}  {:>10}  {:>12}  {:>10}  {:>10}  {:>10}  {:>10}",
        "pre_fill", "inserted", "leaves/s", "insert", "commit", "proof p50", "proof p95"
    );
}

fn print_row(row: &Row, csv: bool) {
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
    if csv {
        println!(
            "{},{},{},{:.3},{:.0},{:.3},{:.2},{:.2}",
            row.batch_size, row.pre_fill, row.inserted,
            row.insert_ms, row.throughput, row.root_ms,
            row.proof_p50_us, row.proof_p95_us,
        );
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    let cfg = parse_args();

    let backend = if cfg.disk { "disk-backed" } else { "in-memory" };
    println!("SMT Performance Benchmark  [{}]", backend);
    println!("  rounds={}, seed={}, proof_sample={}", cfg.rounds, cfg.seed, cfg.proof_sample);
    println!("  batch_sizes={:?}", cfg.batch_sizes);
    if cfg.disk {
        println!("  cache_capacity={}", cfg.cache_capacity);
    }
    println!();

    if cfg.disk {
        run_disk(&cfg);
    } else {
        run_memory(&cfg);
    }
}

fn run_memory(cfg: &Config) {
    if cfg.csv {
        println!("batch_size,pre_fill,inserted,insert_ms,throughput_leaves_per_s,root_ms,proof_p50_us,proof_p95_us");
    }

    for &batch_size in &cfg.batch_sizes {
        print_header("in-memory", batch_size);

        let mut tree     = SparseMerkleTree::new();
        let mut pre_fill = 0usize;
        let mut rng      = StdRng::seed_from_u64(cfg.seed);

        for round in 0..cfg.rounds {
            let batch = gen_leaves(batch_size, &mut rng);
            let mut proof_rng = StdRng::seed_from_u64(cfg.seed.wrapping_add(round as u64 * 999_983));
            let row = measure_round_mem(&mut tree, pre_fill, &batch, cfg.proof_sample, &mut proof_rng);
            print_row(&row, cfg.csv);
            pre_fill += row.inserted;
        }
        println!();
    }
}

fn run_disk(cfg: &Config) {
    use uni_aggregator::storage_rocksdb::RocksDbStore;
    use smt_store::DiskSmt;

    if cfg.csv {
        println!("batch_size,pre_fill,inserted,insert_ms,throughput_leaves_per_s,commit_ms,proof_p50_us,proof_p95_us");
    }

    let _owned_tmp;
    let db_path = if cfg.db_path.is_empty() {
        let mut tmp = std::env::temp_dir();
        tmp.push(format!("perf_test_smt_{}", std::process::id()));
        _owned_tmp = tmp;
        let _ = std::fs::remove_dir_all(&_owned_tmp);
        _owned_tmp.to_str().unwrap().to_string()
    } else {
        cfg.db_path.clone()
    };

    let (_store, arc_db) = RocksDbStore::open(&db_path).expect("failed to open RocksDB");
    let mut disk = DiskSmt::open(arc_db, cfg.cache_capacity)
        .expect("failed to open DiskSmt");

    for &batch_size in &cfg.batch_sizes {
        print_header("disk-backed", batch_size);

        let mut pre_fill = 0usize;
        let mut rng      = StdRng::seed_from_u64(cfg.seed);

        for round in 0..cfg.rounds {
            let batch = gen_leaves(batch_size, &mut rng);
            let mut proof_rng = StdRng::seed_from_u64(cfg.seed.wrapping_add(round as u64 * 999_983));
            let row = measure_round_disk(&mut disk, pre_fill, &batch, cfg.proof_sample, &mut proof_rng);
            print_row(&row, cfg.csv);
            pre_fill += row.inserted;
        }
        println!();
    }
}
