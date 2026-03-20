#!/usr/bin/env tsx
/**
 * Multi-threaded aggregator perf test.
 *
 * Each worker_thread generates cert data AND sends HTTP requests independently,
 * bypassing the single-threaded JS bottleneck from secp256k1 signing.
 *
 * Usage:
 *   tsx perf-test-mt.ts [options]
 *
 * Options:
 *   --url <url>        Aggregator base URL  (default: http://localhost:3000)
 *   --threads <n>      Number of worker threads (default: 4)
 *   --workers <n>      Concurrent HTTP workers per thread (default: 10)
 *   --duration <s>     Test duration in seconds (default: 30)
 */

import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);

// ── Worker thread body ────────────────────────────────────────────────────────

interface WorkerData {
  url: string;
  concurrency: number;
  durationMs: number;
}

interface WorkerResult {
  sent: number;
  success: number;
  errors: number;
  latencies: number[];
}

async function runWorker(cfg: WorkerData): Promise<void> {
  const { AggregatorClient } = await import('@unicitylabs/state-transition-sdk/lib/api/AggregatorClient.js');
  const { CertificationData } = await import('@unicitylabs/state-transition-sdk/lib/api/CertificationData.js');
  const { CertificationStatus } = await import('@unicitylabs/state-transition-sdk/lib/api/CertificationResponse.js');
  const { SigningService } = await import('@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js');
  const { PayToPublicKeyPredicate } = await import('@unicitylabs/state-transition-sdk/lib/predicate/builtin/PayToPublicKeyPredicate.js');
  const { CborSerializer } = await import('@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js');
  const { StateTransitionClient } = await import('@unicitylabs/state-transition-sdk/lib/StateTransitionClient.js');
  const { MintTransaction } = await import('@unicitylabs/state-transition-sdk/lib/transaction/MintTransaction.js');
  const { PayToScriptHash } = await import('@unicitylabs/state-transition-sdk/lib/transaction/PayToScriptHash.js');
  const { TokenId } = await import('@unicitylabs/state-transition-sdk/lib/transaction/TokenId.js');
  const { TokenType } = await import('@unicitylabs/state-transition-sdk/lib/transaction/TokenType.js');

  const client = new StateTransitionClient(new AggregatorClient(cfg.url));
  const endTime = Date.now() + cfg.durationMs;

  let sent = 0, success = 0, errors = 0;
  const latencies: number[] = [];

  async function makeCertData(): Promise<CertificationData> {
    const s = new SigningService(SigningService.generatePrivateKey());
    const p = PayToPublicKeyPredicate.create(s);
    const tx = await MintTransaction.create(
      await PayToScriptHash.create(p),
      new TokenId(crypto.getRandomValues(new Uint8Array(32))),
      new TokenType(crypto.getRandomValues(new Uint8Array(32))),
      CborSerializer.encodeArray(),
    );
    return CertificationData.fromMintTransaction(tx);
  }

  async function worker(): Promise<void> {
    while (Date.now() < endTime) {
      const cd = await makeCertData();
      const t0 = Date.now();
      try {
        const resp = await client.submitCertificationRequest(cd);
        latencies.push(Date.now() - t0);
        sent++;
        if (resp.status === CertificationStatus.SUCCESS) success++;
        else errors++;
      } catch {
        sent++;
        errors++;
      }
    }
  }

  await Promise.all(Array.from({ length: cfg.concurrency }, worker));
  parentPort!.postMessage({ sent, success, errors, latencies } satisfies WorkerResult);
}

// ── Main thread ───────────────────────────────────────────────────────────────

function parseArgs() {
  const args = process.argv.slice(2);
  const get = (f: string) => { const i = args.indexOf(f); return i !== -1 ? args[i + 1] : undefined; };
  return {
    url:      get('--url')     ?? 'http://localhost:3000',
    threads:  parseInt(get('--threads')  ?? '4', 10),
    workers:  parseInt(get('--workers')  ?? '10', 10),
    duration: parseInt(get('--duration') ?? '30', 10),
  };
}

function pct(sorted: number[], p: number): number {
  if (!sorted.length) return 0;
  return sorted[Math.max(0, Math.ceil(p / 100 * sorted.length) - 1)];
}

async function main() {
  if (!isMainThread) {
    await runWorker(workerData as WorkerData);
    return;
  }

  const cfg = parseArgs();
  const durationMs = cfg.duration * 1000;

  console.log('\n=== Aggregator Perf Test (multi-threaded) ===');
  console.log(`  url=${cfg.url}  threads=${cfg.threads}  workers/thread=${cfg.workers}  duration=${cfg.duration}s`);
  console.log(`  total concurrency=${cfg.threads * cfg.workers}\n`);

  const startTime = Date.now();

  const results = await Promise.all(
    Array.from({ length: cfg.threads }, () =>
      new Promise<WorkerResult>((resolve, reject) => {
        const w = new Worker(__filename, {
          workerData: { url: cfg.url, concurrency: cfg.workers, durationMs } satisfies WorkerData,
        });
        w.once('message', resolve);
        w.once('error', reject);
      }),
    ),
  );

  const elapsed = (Date.now() - startTime) / 1000;
  const sent    = results.reduce((s, r) => s + r.sent,    0);
  const success = results.reduce((s, r) => s + r.success, 0);
  const errors  = results.reduce((s, r) => s + r.errors,  0);
  const allLat  = results.flatMap(r => r.latencies).sort((a, b) => a - b);
  const avg     = allLat.length ? allLat.reduce((a, b) => a + b, 0) / allLat.length : 0;

  console.log('=== Results ===');
  console.log(`Duration:    ${elapsed.toFixed(2)}s`);
  console.log(`Total sent:  ${sent}  (${(sent / elapsed).toFixed(1)} req/s)`);
  console.log(`Success:     ${success}  (${(success / elapsed).toFixed(1)} req/s)   Errors: ${errors}`);
  console.log(`\nRequest latency:  avg=${avg.toFixed(0)}ms  p50=${pct(allLat,50)}ms  p95=${pct(allLat,95)}ms  p99=${pct(allLat,99)}ms  max=${allLat[allLat.length-1] ?? 0}ms`);
  console.log('');
}

main().catch(e => { console.error(e); process.exit(1); });
