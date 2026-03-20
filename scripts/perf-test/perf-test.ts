#!/usr/bin/env tsx
/**
 * Aggregator Performance Test
 *
 * Sends minimal certification requests to the aggregator and measures throughput.
 * No token minting/transfer logic — each request uses a fresh random keypair and hashes.
 *
 * Usage:
 *   npm run perf-test [-- options]
 *   tsx perf-test.ts [options]
 *
 * Options:
 *   --url <url>          Aggregator base URL (default: http://localhost:3000)
 *   --workers <n>        Parallel workers in workers mode (default: 10)
 *   --rps <n>            Target requests/sec; overrides --workers
 *   --duration <s>       Test duration in seconds (default: 30)
 *   --proofs             Fetch inclusion proofs after certification
 *   --proof-delay <ms>   Delay before fetching each proof (default: 5000)
 */

import { AggregatorClient } from '@unicitylabs/state-transition-sdk/lib/api/AggregatorClient.js';
import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import { CertificationStatus } from '@unicitylabs/state-transition-sdk/lib/api/CertificationResponse.js';
import { StateId } from '@unicitylabs/state-transition-sdk/lib/api/StateId.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { PayToPublicKeyPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/PayToPublicKeyPredicate.js';
import { CborSerializer } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';
import { StateTransitionClient } from '@unicitylabs/state-transition-sdk/lib/StateTransitionClient.js';
import { MintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/MintTransaction.js';
import { PayToScriptHash } from '@unicitylabs/state-transition-sdk/lib/transaction/PayToScriptHash.js';
import { TokenId } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenId.js';
import { TokenType } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenType.js';

// ── Config ────────────────────────────────────────────────────────────────────

interface Config {
  url: string;
  workers: number;
  rps: number | null;
  duration: number;
  proofs: boolean;
  proofDelay: number;
}

function parseArgs(): Config {
  const args = process.argv.slice(2);
  const get = (flag: string): string | undefined => {
    const i = args.indexOf(flag);
    return i !== -1 ? args[i + 1] : undefined;
  };

  const url = get('--url') ?? 'http://localhost:3000';
  const rpsStr = get('--rps');
  const rps = rpsStr ? parseInt(rpsStr, 10) : null;
  const workersStr = get('--workers');
  // In RPS mode, use enough workers to sustain the target rate
  const workers = rps ? Math.min(rps * 2, 200) : workersStr ? parseInt(workersStr, 10) : 10;
  const duration = parseInt(get('--duration') ?? '30', 10);
  const proofs = args.includes('--proofs');
  const proofDelay = parseInt(get('--proof-delay') ?? '5000', 10);

  return { url, workers, rps, duration, proofs, proofDelay };
}

// ── Token bucket rate limiter ─────────────────────────────────────────────────

class TokenBucket {
  private tokens: number;
  private readonly waiters: Array<() => void> = [];
  private readonly handle: ReturnType<typeof setInterval>;

  public constructor(private readonly rps: number) {
    this.tokens = rps;
    this.handle = setInterval(() => {
      this.tokens = this.rps;
      while (this.tokens > 0 && this.waiters.length > 0) {
        this.tokens--;
        (this.waiters.shift()!)();
      }
    }, 1000);
    this.handle.unref();
  }

  public async acquire(): Promise<void> {
    if (this.tokens > 0) {
      this.tokens--;
      return;
    }
    return new Promise<void>((resolve) => this.waiters.push(resolve));
  }

  public stop(): void {
    clearInterval(this.handle);
  }
}

// ── Cert data factory ─────────────────────────────────────────────────────────

async function makeCertData(): Promise<{ certData: CertificationData; stateId: StateId }> {
  const signingService = new SigningService(SigningService.generatePrivateKey());
  const predicate = PayToPublicKeyPredicate.create(signingService);
  const mintTx = await MintTransaction.create(
    await PayToScriptHash.create(predicate),
    new TokenId(crypto.getRandomValues(new Uint8Array(32))),
    new TokenType(crypto.getRandomValues(new Uint8Array(32))),
    CborSerializer.encodeArray(),
  );
  const certData = await CertificationData.fromMintTransaction(mintTx);
  const stateId = await StateId.fromCertificationData(certData);
  return { certData, stateId };
}

// ── Stats helpers ─────────────────────────────────────────────────────────────

function pct(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  return sorted[Math.max(0, Math.ceil((p / 100) * sorted.length) - 1)];
}

function fmtLatency(sorted: number[]): string {
  if (sorted.length === 0) return 'n/a';
  const avg = sorted.reduce((a, b) => a + b, 0) / sorted.length;
  return `avg=${avg.toFixed(0)}ms  p50=${pct(sorted, 50)}ms  p95=${pct(sorted, 95)}ms  p99=${pct(sorted, 99)}ms  max=${sorted[sorted.length - 1]}ms`;
}

// ── Main ──────────────────────────────────────────────────────────────────────

interface ReqResult {
  sentAt: number;
  latencyMs: number;
  status: string;
}

interface ProofResult {
  sentAt: number;
  fetchedAt: number;
  success: boolean;
  error?: string;
}

async function main(): Promise<void> {
  const cfg = parseArgs();
  const client = new StateTransitionClient(new AggregatorClient(cfg.url));

  const results: ReqResult[] = [];
  const proofResults: ProofResult[] = [];
  const pendingProofs: Array<Promise<void>> = [];

  const startTime = Date.now();
  const endTime = startTime + cfg.duration * 1000;
  const bucket = cfg.rps ? new TokenBucket(cfg.rps) : null;

  console.log('\n=== Aggregator Perf Test ===');
  console.log(
    `  url=${cfg.url}  ` +
      `mode=${cfg.rps ? `rps=${cfg.rps} (${cfg.workers} workers)` : `workers=${cfg.workers}`}  ` +
      `duration=${cfg.duration}s  proofs=${cfg.proofs}` +
      (cfg.proofs ? `  proof-delay=${cfg.proofDelay}ms` : ''),
  );
  console.log('');

  const progressHandle = setInterval(() => {
    const elapsed = (Date.now() - startTime) / 1000;
    const sent = results.length;
    const success = results.filter((r) => r.status === CertificationStatus.SUCCESS).length;
    const errors = sent - success;
    process.stdout.write(
      `  [${elapsed.toFixed(1)}s] sent=${sent}  success=${success}  errors=${errors}  rps=${(sent / elapsed).toFixed(1)}` +
        (cfg.proofs ? `  proofs_fetched=${proofResults.length}` : '') +
        '\n',
    );
  }, 3000);
  progressHandle.unref();

  const worker = async (): Promise<void> => {
    while (Date.now() < endTime) {
      if (bucket) {
        await bucket.acquire();
        if (Date.now() >= endTime) break;
      }

      let certData: CertificationData;
      let stateId: StateId;
      try {
        ({ certData, stateId } = await makeCertData());
      } catch (err) {
        results.push({ sentAt: Date.now(), latencyMs: 0, status: `create_error: ${String(err).slice(0, 60)}` });
        continue;
      }

      const sentAt = Date.now();
      try {
        const response = await client.submitCertificationRequest(certData);
        const latencyMs = Date.now() - sentAt;
        results.push({ sentAt, latencyMs, status: response.status });

        if (cfg.proofs && response.status === CertificationStatus.SUCCESS) {
          const capturedStateId = stateId;
          const capturedSentAt = sentAt;
          const p = new Promise<void>((resolve) => {
            setTimeout(async () => {
              try {
                await client.getInclusionProof(capturedStateId);
                proofResults.push({ sentAt: capturedSentAt, fetchedAt: Date.now(), success: true });
              } catch (err) {
                proofResults.push({
                  sentAt: capturedSentAt,
                  fetchedAt: Date.now(),
                  success: false,
                  error: String(err),
                });
              }
              resolve();
            }, cfg.proofDelay);
          });
          pendingProofs.push(p);
        }
      } catch (err) {
        results.push({
          sentAt,
          latencyMs: Date.now() - sentAt,
          status: `http_error: ${String(err).slice(0, 60)}`,
        });
      }
    }
  };

  await Promise.all(Array.from({ length: cfg.workers }, worker));
  clearInterval(progressHandle);
  bucket?.stop();

  if (pendingProofs.length > 0) {
    const fetched = proofResults.length;
    const pending = pendingProofs.length - fetched;
    if (pending > 0) {
      console.log(`\n  Waiting for ${pending} pending proof fetches...`);
    }
    await Promise.all(pendingProofs);
  }

  // ── Summary ─────────────────────────────────────────────────────────────────
  const elapsed = (Date.now() - startTime) / 1000;
  const total = results.length;
  const statusMap = new Map<string, number>();
  for (const r of results) statusMap.set(r.status, (statusMap.get(r.status) ?? 0) + 1);

  const successCount = statusMap.get(CertificationStatus.SUCCESS) ?? 0;
  const latencies = results.map((r) => r.latencyMs).sort((a, b) => a - b);

  console.log('\n=== Results ===');
  console.log(`Duration:    ${elapsed.toFixed(2)}s`);
  console.log(`Total sent:  ${total}  (${(total / elapsed).toFixed(2)} req/s)`);
  console.log(`Certified:   ${successCount}  (${(successCount / elapsed).toFixed(2)} req/s)\n`);

  console.log('Status breakdown:');
  for (const [status, count] of [...statusMap.entries()].sort((a, b) => b[1] - a[1])) {
    console.log(`  ${status.padEnd(36)} ${String(count).padStart(6)}  (${((count / total) * 100).toFixed(1)}%)`);
  }

  if (latencies.length > 0) {
    console.log(`\nRequest latency:  ${fmtLatency(latencies)}`);
  }

  if (proofResults.length > 0) {
    const ok = proofResults
      .filter((p) => p.success)
      .map((p) => p.fetchedAt - p.sentAt)
      .sort((a, b) => a - b);
    const fail = proofResults.filter((p) => !p.success).length;
    console.log(
      `\nInclusion proof latency (cert→proof) [${proofResults.length} fetched, ${fail} failed]:`,
    );
    console.log(`  ${fmtLatency(ok)}`);
  }

  console.log('');
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
