//! SMT performance benchmark.
//!
//! Inserts successive batches into a *persistent* tree so each round inherits
//! all previously inserted leaves.  This reveals how insertion throughput and
//! proof latency degrade as the tree grows.
//!
//! For backends that write to RocksDB (`disk`, `mem-leaves`, `mem-full`) each
//! batch-size run gets a fresh temporary database directory so measurements are
//! independent.  Pass `--db-path PATH` to reuse a fixed directory across runs
//! (the tree then grows cumulatively across batch sizes).
//!
//! Usage:
//!   cargo run --release --bin perf-test [options]
//!
//! Options:
//!   --backend NAME        mem | mem-leaves | mem-full | disk  (default: mem)
//!   --rounds N            Rounds per batch-size run            (default: 6)
//!   --seed S              PRNG seed                            (default: random)
//!   --proof-sample N      Proofs sampled per round             (default: 200)
//!   --batch-sizes X,Y,..  Comma-separated sizes                (default: 1000,5000,10000)
//!   --cache-capacity N    RocksDB block cache bytes for SMT CF  (default: 0 = RocksDB default)
//!   --db-path PATH        Fixed DB directory; default = fresh temp dir per sweep
//!   --csv                 Also emit CSV rows

use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use smt_store::{SmtStore, SmtStoreSnapshot};
use uni_aggregator::smt::{SmtPath, state_id_to_smt_path};
use uni_aggregator::validation::state_id::compute_cert_data_hash_imprint;

// ─── CLI ─────────────────────────────────────────────────────────────────────

struct Config {
    backend:        String,
    rounds:         usize,
    seed:           u64,
    proof_sample:   usize,
    batch_sizes:    Vec<usize>,
    cache_capacity: usize,
    db_path:        String,
    csv:            bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            backend:        "mem".into(),
            rounds:         6,
            seed:           0, // resolved in parse_args
            proof_sample:   200,
            batch_sizes:    vec![1_000, 5_000, 10_000],
            cache_capacity: 0,
            db_path:        String::new(),
            csv:            false,
        }
    }
}

fn parse_args() -> Config {
    let mut cfg = Config::default();
    let mut seed_override: Option<u64> = None;
    let mut args = std::env::args().skip(1).peekable();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--backend"         => { if let Some(v) = args.next() { cfg.backend         = v; } }
            "--rounds"          => { if let Some(v) = args.next() { cfg.rounds          = v.parse().unwrap_or(cfg.rounds); } }
            "--seed"            => { if let Some(v) = args.next() { seed_override       = v.parse().ok(); } }
            "--proof-sample"    => { if let Some(v) = args.next() { cfg.proof_sample    = v.parse().unwrap_or(cfg.proof_sample); } }
            "--cache-capacity"  => { if let Some(v) = args.next() { cfg.cache_capacity  = v.parse().unwrap_or(cfg.cache_capacity); } }
            "--db-path"         => { if let Some(v) = args.next() { cfg.db_path = v; } }
            "--batch-sizes"     => {
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
    cfg.seed = seed_override.unwrap_or_else(|| rand::random());
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
    else if us < 1_000_000.0 { format!("{:.2}ms",  us / 1_000.0) }
    else                     { format!("{:.2}s",   us / 1_000_000.0) }
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

fn open_db(path: &str, block_cache_bytes: usize) -> anyhow::Result<Arc<rocksdb::DB>> {
    let (_, arc_db) = uni_aggregator::storage_rocksdb::RocksDbStore::open(path, block_cache_bytes)?;
    Ok(arc_db)
}

// ─── Row ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct Row {
    batch_size:   usize,
    pre_fill:     usize,
    inserted:     usize,
    /// SMT work: add_leaf loop + root hash computation (and for disk: materialise + overlay).
    insert_ms:    f64,
    /// Persistence work: DB write (zero for `mem` backend).
    commit_ms:    f64,
    throughput:   f64,
    proof_p50_us: f64,
    proof_p95_us: f64,
}

// ─── Generic measurement ──────────────────────────────────────────────────────

fn measure_round<S: SmtStore>(
    store:        &mut S,
    pre_fill:     usize,
    batch:        &[(SmtPath, Vec<u8>)],
    proof_sample: usize,
    rng:          &mut StdRng,
) -> anyhow::Result<Row> {
    let batch_size = batch.len();
    let mut snap   = store.create_snapshot();
    let mut inserted = 0usize;

    // ── Insert + root hash ────────────────────────────────────────────────────
    // For DiskSmtSnapshot: add_leaf is O(1) (deferred); root_hash_imprint()
    // triggers flush_pending() which materialises the batch from RocksDB,
    // runs batch_insert, computes root, and builds the overlay.
    // For MemSmtSnapshot: add_leaf modifies the in-memory snapshot; root_hash_imprint
    // is cheap (already cached).
    let t_ins = Instant::now();
    for (path, value) in batch {
        if snap.add_leaf(path.clone(), value.clone()).is_ok() {
            inserted += 1;
        }
    }
    let _ = snap.root_hash_imprint()?;
    let insert_dur = t_ins.elapsed();

    // ── Commit ────────────────────────────────────────────────────────────────
    // For disk backends: flushes the overlay to a RocksDB WriteBatch.
    // For mem-leaves / mem-full: writes to the appropriate CFs.
    // For pure mem: in-memory tree swap only.
    let t_commit = Instant::now();
    snap.commit(store)?;
    let commit_dur = t_commit.elapsed();

    // ── Proof generation ──────────────────────────────────────────────────────
    let n = batch.len();
    let sample: Vec<usize> = (0..proof_sample.min(inserted))
        .map(|_| rng.gen_range(0..n))
        .collect();

    let mut proof_times: Vec<f64> = Vec::with_capacity(sample.len());
    for &i in &sample {
        let t = Instant::now();
        let _ = store.get_path(&batch[i].0)?;
        proof_times.push(t.elapsed().as_secs_f64() * 1e6);
    }
    proof_times.sort_by(|a, b| a.partial_cmp(b).unwrap());

    Ok(Row {
        batch_size,
        pre_fill,
        inserted,
        insert_ms:    insert_dur.as_secs_f64() * 1e3,
        commit_ms:    commit_dur.as_secs_f64() * 1e3,
        throughput:   inserted as f64 / insert_dur.as_secs_f64(),
        proof_p50_us: percentile(&proof_times, 50.0),
        proof_p95_us: percentile(&proof_times, 95.0),
    })
}

// ─── Print helpers ────────────────────────────────────────────────────────────

fn print_header(label: &str, batch_size: usize) {
    println!(
        "── {} batch_size={} ────────────────────────────────────────────",
        label, batch_size
    );
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
        fmt_dur(Duration::from_secs_f64(row.insert_ms  / 1e3)),
        fmt_dur(Duration::from_secs_f64(row.commit_ms  / 1e3)),
        row.proof_p50_us,
        row.proof_p95_us,
    );
    if csv {
        println!(
            "{},{},{},{:.3},{:.0},{:.3},{:.2},{:.2}",
            row.batch_size, row.pre_fill, row.inserted,
            row.insert_ms, row.throughput, row.commit_ms,
            row.proof_p50_us, row.proof_p95_us,
        );
    }
}

// ─── Generic runner ───────────────────────────────────────────────────────────

/// Run all batch-size sweeps against a single store instance.
///
/// `initial_prefill` is the number of leaves already in the tree before the
/// first round (non-zero when loading from a pre-existing DB).  Pre-fill
/// accumulates globally across all batch-size sweeps so the output accurately
/// reflects the growing tree.
fn run_sweeps<S: SmtStore>(store: &mut S, cfg: &Config, label: &str, initial_prefill: usize) {
    if cfg.csv {
        println!("batch_size,pre_fill,inserted,insert_ms,throughput_leaves_per_s,commit_ms,proof_p50_us,proof_p95_us");
    }

    let mut pre_fill = initial_prefill;

    for &batch_size in &cfg.batch_sizes {
        print_header(label, batch_size);
        let mut rng = StdRng::seed_from_u64(cfg.seed);

        for round in 0..cfg.rounds {
            let batch = gen_leaves(batch_size, &mut rng);
            let mut proof_rng = StdRng::seed_from_u64(
                cfg.seed.wrapping_add(round as u64 * 999_983)
            );
            let row = measure_round(store, pre_fill, &batch, cfg.proof_sample, &mut proof_rng)
                .expect("measure_round failed");
            print_row(&row, cfg.csv);
            pre_fill += row.inserted;
        }
        println!();
    }
}

// ─── DB helpers ───────────────────────────────────────────────────────────────

fn count_leaves_in_db(db: &rocksdb::DB) -> usize {
    smt_store::count_db_leaves(db)
}

/// Make a temp DB path unique to this process and sweep index.
fn temp_db_path(tag: &str, sweep: usize) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("perf_test_{}_{}_{}", tag, std::process::id(), sweep));
    let _ = std::fs::remove_dir_all(&p);
    p
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() -> anyhow::Result<()> {
    let cfg = parse_args();

    println!("SMT Performance Benchmark  [{}]", cfg.backend);
    println!("  rounds={}, seed={}, proof_sample={}", cfg.rounds, cfg.seed, cfg.proof_sample);
    println!("  batch_sizes={:?}", cfg.batch_sizes);
    if cfg.backend != "mem" {
        println!("  cache_capacity={}", cfg.cache_capacity);
        if !cfg.db_path.is_empty() {
            println!("  db_path={}", cfg.db_path);
        }
    }
    println!();

    match cfg.backend.as_str() {

        // ── Pure in-memory: no DB at all ──────────────────────────────────────
        "mem" => {
            let mut store = smt_store::MemSmt::new();
            run_sweeps(&mut store, &cfg, "mem", 0);
        }

        // ── Persistent in-memory backends ─────────────────────────────────────
        "mem-leaves" | "mem-full" => {
            use smt_store::mem::PersistMode;
            let mode  = if cfg.backend == "mem-leaves" { PersistMode::LeavesOnly } else { PersistMode::Full };
            let label = cfg.backend.as_str();

            if cfg.db_path.is_empty() {
                // Temp mode: fresh DB per batch-size sweep, cleaned up after.
                for (sweep, &batch_size) in cfg.batch_sizes.iter().enumerate() {
                    let tmp = temp_db_path(label, sweep);
                    let db_path = tmp.to_str().unwrap().to_string();
                    let arc_db = open_db(&db_path, cfg.cache_capacity)?;
                    let mut store = smt_store::MemSmt::open(arc_db, mode)?;

                    print_header(label, batch_size);
                    let mut pre_fill = 0usize;
                    let mut rng = StdRng::seed_from_u64(cfg.seed);
                    for round in 0..cfg.rounds {
                        let batch = gen_leaves(batch_size, &mut rng);
                        let mut prng = StdRng::seed_from_u64(cfg.seed.wrapping_add(round as u64 * 999_983));
                        let row = measure_round(&mut store, pre_fill, &batch, cfg.proof_sample, &mut prng)?;
                        print_row(&row, cfg.csv);
                        pre_fill += row.inserted;
                    }
                    println!();
                    let _ = std::fs::remove_dir_all(&db_path);
                }
            } else {
                // Persistent mode: load once, run all sweeps on the same tree, keep DB.
                let arc_db = open_db(&cfg.db_path, cfg.cache_capacity)?;
                let existing = count_leaves_in_db(&arc_db);

                print!("Loading {} leaves from '{}'...", existing, cfg.db_path);
                let _ = std::io::Write::flush(&mut std::io::stdout());
                let t_load = Instant::now();
                let mut store = smt_store::MemSmt::open(Arc::clone(&arc_db), mode)?;
                let load_dur = t_load.elapsed();
                println!("  done in {}", fmt_dur(load_dur));
                println!("  root = {}", hex::encode(smt_store::SmtStore::root_hash_imprint(&store)));
                println!();

                run_sweeps(&mut store, &cfg, label, existing);
            }
        }

        // ── Disk-backed ───────────────────────────────────────────────────────
        "disk" => {
            if cfg.db_path.is_empty() {
                // Temp mode: fresh DB per batch-size sweep, cleaned up after.
                for (sweep, &batch_size) in cfg.batch_sizes.iter().enumerate() {
                    let tmp = temp_db_path("disk", sweep);
                    let db_path = tmp.to_str().unwrap().to_string();
                    let arc_db = open_db(&db_path, cfg.cache_capacity)?;
                    let mut store = smt_store::DiskSmt::open(arc_db, cfg.cache_capacity)?;

                    print_header("disk", batch_size);
                    let mut pre_fill = 0usize;
                    let mut rng = StdRng::seed_from_u64(cfg.seed);
                    for round in 0..cfg.rounds {
                        let batch = gen_leaves(batch_size, &mut rng);
                        let mut prng = StdRng::seed_from_u64(cfg.seed.wrapping_add(round as u64 * 999_983));
                        let row = measure_round(&mut store, pre_fill, &batch, cfg.proof_sample, &mut prng)?;
                        print_row(&row, cfg.csv);
                        pre_fill += row.inserted;
                    }
                    println!();
                    let _ = std::fs::remove_dir_all(&db_path);
                }
            } else {
                // Persistent mode: open once (root hash only; nodes are lazy), keep DB.
                let arc_db = open_db(&cfg.db_path, cfg.cache_capacity)?;
                let existing = count_leaves_in_db(&arc_db);

                print!("Opening disk-SMT '{}' ({} persisted leaves)...", cfg.db_path, existing);
                let _ = std::io::Write::flush(&mut std::io::stdout());
                let t_open = Instant::now();
                let mut store = smt_store::DiskSmt::open(Arc::clone(&arc_db), cfg.cache_capacity)?;
                let open_dur = t_open.elapsed();
                println!("  done in {}", fmt_dur(open_dur));
                println!("  root = {}", hex::encode(smt_store::SmtStore::root_hash_imprint(&store)));
                println!();

                run_sweeps(&mut store, &cfg, "disk", existing);
            }
        }

        other => anyhow::bail!(
            "unknown backend '{other}' — supported: mem, mem-leaves, mem-full, disk"
        ),
    }

    Ok(())
}
