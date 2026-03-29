#!/usr/bin/env tsx
/**
 * Pre-generate unique certification requests for load testing.
 *
 * Each request is a complete, signed, hex-CBOR payload ready to send.
 * Output format: vegeta JSON targets (one JSON object per line) — pipe directly
 * into `vegeta attack` or save to a file for later use.
 *
 * Usage:
 *   # Stream directly into vegeta:
 *   tsx gen-requests.ts --count 100000 --url http://localhost:8080 \
 *     | vegeta attack -format=json -rate=8000 -duration=15s \
 *     | vegeta report
 *
 *   # Save first, then replay at different rates:
 *   tsx gen-requests.ts --count 100000 --url http://localhost:8080 -o requests.json
 *   vegeta attack -format=json -targets=requests.json -rate=5000 -duration=20s | vegeta report
 *   vegeta attack -format=json -targets=requests.json -rate=10000 -duration=10s | vegeta report
 *
 * Options:
 *   --count <n>    Number of requests to generate (default: 50000)
 *   --url <url>    Aggregator URL used in the target (default: http://localhost:3000)
 *   --threads <n>  Worker threads for parallel generation (default: CPU count)
 *   -o <file>      Write to file instead of stdout
 */

import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import { createWriteStream, WriteStream } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as os from 'node:os';

const __filename = fileURLToPath(import.meta.url);

// ── Worker thread ─────────────────────────────────────────────────────────────

interface WorkerIn {
  count: number;
  url: string;
}

async function runWorker({ count, url }: WorkerIn): Promise<void> {
  const { CertificationData } = await import(
    '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js'
  );
  const { CertificationRequest } = await import(
    '@unicitylabs/state-transition-sdk/lib/api/CertificationRequest.js'
  );
  const { SigningService } = await import(
    '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js'
  );
  const { PayToPublicKeyPredicate } = await import(
    '@unicitylabs/state-transition-sdk/lib/predicate/builtin/PayToPublicKeyPredicate.js'
  );
  const { CborSerializer } = await import(
    '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js'
  );
  const { MintTransaction } = await import(
    '@unicitylabs/state-transition-sdk/lib/transaction/MintTransaction.js'
  );
  const { Address } = await import(
    '@unicitylabs/state-transition-sdk/lib/transaction/Address.js'
  );
  const { TokenId } = await import(
    '@unicitylabs/state-transition-sdk/lib/transaction/TokenId.js'
  );
  const { TokenType } = await import(
    '@unicitylabs/state-transition-sdk/lib/transaction/TokenType.js'
  );
  const { HexConverter } = await import(
    '@unicitylabs/state-transition-sdk/lib/serialization/HexConverter.js'
  );

  const lines: string[] = [];

  for (let i = 0; i < count; i++) {
    const svc = new SigningService(SigningService.generatePrivateKey());
    const tx = await MintTransaction.create(
      await Address.fromPredicate(PayToPublicKeyPredicate.fromSigningService(svc)),
      new TokenId(crypto.getRandomValues(new Uint8Array(32))),
      new TokenType(crypto.getRandomValues(new Uint8Array(32))),
      CborSerializer.encodeArray(),
    );
    const certData = await CertificationData.fromMintTransaction(tx);
    const req = await CertificationRequest.create(certData);
    const hexCbor = HexConverter.encode(req.toCBOR());

    // Vegeta JSON target format — body is base64-encoded HTTP request body.
    const body = JSON.stringify({ id: crypto.randomUUID(), jsonrpc: '2.0', method: 'certification_request', params: hexCbor });
    lines.push(
      JSON.stringify({
        body: Buffer.from(body).toString('base64'),
        header: { 'Content-Type': ['application/json'] },
        method: 'POST',
        url,
      }),
    );

    // Flush in batches to avoid unbounded memory growth.
    if (lines.length >= 2000) {
      parentPort!.postMessage(lines.splice(0));
    }
  }

  if (lines.length > 0) {
    parentPort!.postMessage(lines);
  }
  parentPort!.postMessage(null); // signal done
}

// ── Main thread ───────────────────────────────────────────────────────────────

function parseArgs() {
  const args = process.argv.slice(2);
  const get = (flag: string): string | undefined => {
    const i = args.indexOf(flag);
    return i !== -1 ? args[i + 1] : undefined;
  };
  return {
    count: parseInt(get('--count') ?? '50000', 10),
    output: get('-o') ?? null,
    threads: parseInt(get('--threads') ?? String(os.cpus().length), 10),
    url: get('--url') ?? 'http://localhost:3000',
  };
}

async function main(): Promise<void> {
  if (!isMainThread) {
    await runWorker(workerData as WorkerIn);
    return;
  }

  const cfg = parseArgs();
  const perThread = Math.ceil(cfg.count / cfg.threads);
  const actual = perThread * cfg.threads;

  const out: WriteStream | NodeJS.WriteStream = cfg.output
    ? createWriteStream(cfg.output)
    : process.stdout;

  if (cfg.output) {
    process.stderr.write(
      `Generating ${actual} requests with ${cfg.threads} threads → ${cfg.output}\n`,
    );
  } else {
    process.stderr.write(
      `Generating ${actual} requests with ${cfg.threads} threads → stdout\n`,
    );
  }

  const t0 = Date.now();
  let written = 0;

  await new Promise<void>((resolve, reject) => {
    let done = 0;

    for (let t = 0; t < cfg.threads; t++) {
      const w = new Worker(__filename, {
        workerData: { count: perThread, url: cfg.url } satisfies WorkerIn,
      });

      w.on('message', (lines: string[] | null) => {
        if (lines === null) {
          done++;
          if (done === cfg.threads) resolve();
          return;
        }
        for (const line of lines) {
          out.write(line + '\n');
          written++;
        }
      });

      w.on('error', reject);
    }
  });

  const elapsed = (Date.now() - t0) / 1000;
  process.stderr.write(
    `Done: ${written} requests in ${elapsed.toFixed(1)}s (${(written / elapsed).toFixed(0)} req/s)\n`,
  );

  if (cfg.output) {
    (out as WriteStream).end();
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
