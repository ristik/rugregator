#!/usr/bin/env tsx
// Upload a partition shard config to BFT Core, patching epoch and epochStart.
//
// BFT Core requires:  epoch = prev.epoch + 1
//                     epochStart > prev.epochStart  (and a future root round)
//
// Usage:
//   upload-partition-config.ts <shard-conf.json> [options]
//
// Options:
//   --rpc-url <url>      BFT Core RPC base URL  (default: http://127.0.0.1:26660)
//   --epoch-offset <n>   Activate N root rounds after current root round (default: 10)
//   --epoch-start <n>    Override epochStart directly
//   --dry-run            Print patched config without uploading

import { readFileSync } from 'node:fs';

const args = process.argv.slice(2);
const get = (flag: string) => { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : undefined; };
const has = (flag: string) => args.includes(flag);

const confFile      = args.find(a => !a.startsWith('-'));
const rpcUrl        = get('--rpc-url') ?? 'http://127.0.0.1:26660';
const offset        = parseInt(get('--epoch-offset') ?? '10');
const startOverride = get('--epoch-start') ? parseInt(get('--epoch-start')!) : undefined;
const dryRun        = has('--dry-run');

if (!confFile) { console.error('Usage: upload-partition-config.ts <shard-conf.json> [options]'); process.exit(1); }

const base = JSON.parse(readFileSync(confFile, 'utf8'));

async function main() {
  // Query current root round and partition state (optional in dry-run).
  let rootRound: number = base.epochStart ?? 0;
  let liveEpoch: number | undefined;
  try {
    const info = await fetch(`${rpcUrl}/api/v1/roundInfo`).then(r => r.json());
    rootRound = parseInt(info.roundNumber);
    const shard = (info.partitionShards ?? []).find((s: any) => s.partitionId === base.partitionId);
    if (shard) liveEpoch = parseInt(shard.epochNumber);
    console.log(`root round: ${rootRound}  partition ${base.partitionId} epoch: ${liveEpoch ?? 'n/a'}`);
    if (liveEpoch !== undefined && liveEpoch !== base.epoch)
      console.warn(`warning: live epoch (${liveEpoch}) differs from base file epoch (${base.epoch}), using live epoch`);
  } catch (e) {
    if (!dryRun) throw e;
    console.warn(`warning: BFT Core unreachable, computing epochStart from base file only`);
  }

  const prevEpoch = liveEpoch ?? base.epoch;
  const newEpoch  = prevEpoch + 1;
  const floor    = Math.max(base.epochStart ?? 0, rootRound);
  const newStart = startOverride ?? (floor + offset);

  if (newStart <= (base.epochStart ?? 0))
    { console.error(`epoch-start ${newStart} must be > base epochStart ${base.epochStart}`); process.exit(1); }

  const patched = { ...base, epoch: newEpoch, epochStart: newStart };

  console.log(`patching epoch=${newEpoch} epochStart=${newStart} (activates at root round ${newStart})`);

  if (dryRun) { console.log(JSON.stringify(patched, null, 2)); return; }

  const res = await fetch(`${rpcUrl}/api/v1/configurations`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(patched),
  });

  if (res.ok) {
    console.log(`OK: partition ${base.partitionId} epoch ${newEpoch} accepted, activates at round ${newStart}`);
  } else {
    console.error(`error: HTTP ${res.status} — ${await res.text()}`);
    process.exit(1);
  }
}

main();
