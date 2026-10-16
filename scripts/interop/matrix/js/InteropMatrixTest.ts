/*
 * Interop matrix driver, JS SDK client (C3).
 *
 * Copied by run.sh into a state-transition-sdk-js checkout as tests/interop/InteropMatrixTest.ts and run with
 * `npx jest --testPathPatterns=tests/interop --coverage=false --runInBand`. Appends one JSON line per scenario to
 * IX_OUT (and prints it):
 *   {"client":"js","scenario":"2","name":"...","status":"PASS|FAIL|N-A","evidence":"..."}
 *
 * Environment: IX_URL, IX_TRUSTBASE (RootTrustBase JSON), IX_PARTITION, IX_N (default 6), IX_CASES
 * (envelope_cases.json), IX_RETAINED (views the server retains; 0 = unknown), IX_ROUND_MS (server round duration),
 * IX_OUT (result file).
 */
import { appendFileSync, readFileSync } from 'node:fs';

import { AggregatorClient } from '../../src/api/AggregatorClient.js';
import { RootTrustBase } from '../../src/api/bft/RootTrustBase.js';
import { SealVerificationSession } from '../../src/api/bft/verification/SealVerificationSession.js';
import { UnicitySealQuorumSignaturesVerificationRule } from '../../src/api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js';
import { BatchProofError } from '../../src/api/BatchProofError.js';
import { CertificationData } from '../../src/api/CertificationData.js';
import { CertificationStatus } from '../../src/api/CertificationResponse.js';
import { InclusionProof } from '../../src/api/InclusionProof.js';
import { verifyNonInclusion } from '../../src/api/NonInclusionVerification.js';
import { NonInclusionProof } from '../../src/api/NonInclusionProof.js';
import { NonInclusionProofError } from '../../src/api/NonInclusionProofError.js';
import { StateId } from '../../src/api/StateId.js';
import { ProofConsolidator } from '../../src/consolidation/ProofConsolidator.js';
import { ShardRouting } from '../../src/consolidation/ShardRouting.js';
import { Secp256k1SignatureVerifier } from '../../src/crypto/secp256k1/Secp256k1SignatureVerifier.js';
import { SigningService } from '../../src/crypto/secp256k1/SigningService.js';
import { DataHash } from '../../src/crypto/hash/DataHash.js';
import { HashAlgorithm } from '../../src/crypto/hash/HashAlgorithm.js';
import { SignaturePredicate } from '../../src/predicate/builtin/SignaturePredicate.js';
import { PredicateVerifierService } from '../../src/predicate/verification/PredicateVerifierService.js';
import { MintTransaction } from '../../src/transaction/MintTransaction.js';
import { TokenSalt } from '../../src/transaction/TokenSalt.js';
import { TokenType } from '../../src/transaction/TokenType.js';
import { MintJustificationVerifierService } from '../../src/transaction/verification/MintJustificationVerifierService.js';
import { TokenIssuanceVerifierService } from '../../src/transaction/verification/TokenIssuanceVerifierService.js';
import { VerificationContext } from '../../src/transaction/verification/VerificationContext.js';
import { HexConverter } from '../../src/util/HexConverter.js';
import { waitInclusionProof } from '../../src/util/InclusionProofUtils.js';
import { VerificationStatus } from '../../src/verification/VerificationStatus.js';
import { StateTransitionClient } from '../../src/StateTransitionClient.js';
import { createUnicityCertificateVerifier } from '../utils/UnicityCertificateVerifierFixture.js';

const env = (k: string): string => process.env[k] ?? '';
const OUT = env('IX_OUT');

function emit(scenario: string, name: string, status: 'FAIL' | 'N-A' | 'PASS', evidence: string): void {
  const line = JSON.stringify({ client: 'js', evidence, name, scenario, status });
  process.stdout.write(`${line}\n`);
  if (OUT) {
    appendFileSync(OUT, `${line}\n`);
  }
}

function describeBatchError(e: unknown): string {
  if (e instanceof BatchProofError) {
    return `kind=${e.kind} code=${e.code} detail=${e.detail} retryable=${e.retryable} indexes=${JSON.stringify(e.indexesByClass ?? {})}`;
  }
  return e instanceof Error ? `${e.name}: ${e.message}` : String(e);
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

async function post(url: string, body: string): Promise<{ status: number; json: any }> {
  const resp = await fetch(url, { body, headers: { 'Content-Type': 'application/json' }, method: 'POST' });
  const text = await resp.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = { nonJson: text.slice(0, 120) };
  }
  return { json, status: resp.status };
}

interface IMinted {
  certificationData: CertificationData;
  stateId: StateId;
  transaction: MintTransaction;
}

describe('interop matrix', () => {
  it('runs the scenarios', async () => {
    const url = env('IX_URL');
    const trustBase = RootTrustBase.fromJSON(JSON.parse(readFileSync(env('IX_TRUSTBASE'), 'utf8')));
    const partition = BigInt(env('IX_PARTITION'));
    const n = Number(env('IX_N') || '6');
    const retained = Number(env('IX_RETAINED') || '0');
    const roundMs = Number(env('IX_ROUND_MS') || '1000');
    const waitMs = roundMs * 20 + 30_000;

    const aggregator = new AggregatorClient(url);
    const client = new StateTransitionClient(aggregator);
    const ucVerifier = createUnicityCertificateVerifier();
    const predicateVerifier = PredicateVerifierService.create();
    const context = new VerificationContext(
      trustBase,
      predicateVerifier,
      ucVerifier,
      new MintJustificationVerifierService(),
      new TokenIssuanceVerifierService(false),
    );

    const newMint = async (expiresAt: bigint | null = null): Promise<IMinted> => {
      const owner = SigningService.generate();
      const transaction = await MintTransaction.create(trustBase.networkId, SignaturePredicate.create(owner.publicKey), {
        data: null,
        expiresAt,
        justification: undefined,
        salt: TokenSalt.generate(),
        tokenType: TokenType.generate(),
      });
      const certificationData = await CertificationData.fromMintTransaction(transaction);
      return { certificationData, stateId: await StateId.fromTransaction(transaction), transaction };
    };
    const submit = async (m: IMinted): Promise<void> => {
      const r = await client.submitCertificationRequest(m.certificationData);
      if (r.status !== String(CertificationStatus.SUCCESS)) {
        throw new Error(`certification_request status ${r.status}`);
      }
    };
    // The SDK's own wait ends with the JSON-RPC error when the server answers "pending" as -32021 (HTTP 200), which only
    // rugregator does; the driver retries on that code so the remaining scenarios can run, and reports the finding.
    let nativeWaitBroken: string | null = null;
    const wait = async (m: IMinted): Promise<InclusionProof> => {
      const deadline = Date.now() + waitMs;
      for (;;) {
        try {
          return await waitInclusionProof(client, trustBase, predicateVerifier, ucVerifier, m.transaction, {
            intervalMs: 200,
            signal: AbortSignal.timeout(Math.max(1000, deadline - Date.now())),
            statusHints: true,
            unknownGraceMs: 5000,
          });
        } catch (e) {
          const code = (e as { code?: number }).code;
          if (code === -32021 && Date.now() < deadline) {
            nativeWaitBroken ??= `waitInclusionProof threw ${(e as Error).name} code=${code} "${(e as Error).message}"`;
            await sleep(200);
            continue;
          }
          throw e;
        }
      }
    };

    // ---- scenario 1: submit N, wait with status hints, verify each (waitInclusionProof verifies)
    const minted: IMinted[] = [];
    for (let i = 0; i < n; i++) {
      minted.push(await newMint());
    }
    const proofs: InclusionProof[] = [];
    try {
      const wave = Math.max(1, Math.ceil(n / 3));
      for (let lo = 0; lo < n; lo += wave) {
        const chunk = minted.slice(lo, lo + wave);
        for (const m of chunk) {
          await submit(m);
        }
        for (const m of chunk) {
          proofs.push(await wait(m));
        }
      }
      emit(
        '1',
        'submit and wait',
        nativeWaitBroken ? 'FAIL' : 'PASS',
        nativeWaitBroken
          ? `${nativeWaitBroken}; the SDK wait does not treat a -32021 pending answer as "not yet"; with a driver-side retry on that code all ${n} requests were included and verified`
          : `${n} requests included (waitInclusionProof with statusHints), proofs verified`,
      );
    } catch (e) {
      emit('1', 'submit and wait', 'FAIL', describeBatchError(e));
      return;
    }

    // ---- scenario 1b: JS has no raw count field: the SDK always writes the reserved slot 0
    emit('1b', 'reference-tool request (aggregateRequestCount=1)', 'N-A', 'the JS SDK never writes a non-zero reserved slot');

    // ---- scenario 2: consolidate latest, direct unsharded path
    const routing = ShardRouting.single(aggregator, partition);
    const session = new SealVerificationSession(trustBase, new UnicitySealQuorumSignaturesVerificationRule(new Secp256k1SignatureVerifier()));
    const consolidator = new ProofConsolidator(routing, session);
    let masterRoot: Uint8Array | null = null;
    try {
      const attempt = await consolidator.consolidate(
        minted.map((m, i) => ({ certificationData: m.certificationData, proof: proofs[i] })),
        { timeoutMs: 30_000 },
      );
      if (attempt.status !== 'consolidated') {
        emit('2', 'consolidate latest (direct unsharded)', 'FAIL', `unavailable: ${attempt.reason} detail=${attempt.detail}`);
      } else {
        const c = attempt.counters;
        const ok = attempt.requests === 1 && attempt.waves === 1 && attempt.shards === 1 && c.quorumChecks <= 1 && c.leafChecks === n;
        masterRoot = attempt.responses[0].inclusionProof?.unicityCertificate.inputRecord.hash ?? null;
        emit(
          '2',
          'consolidate latest (direct unsharded)',
          ok ? 'PASS' : 'FAIL',
          `requests=${attempt.requests} waves=${attempt.waves} shards=${attempt.shards} quorumChecks=${c.quorumChecks} evidenceQuorumChecks=${c.evidenceQuorumChecks} leafChecks=${c.leafChecks} bodyChecks=${c.bodyChecks} masterRound=${attempt.masterRound}`,
        );
      }
    } catch (e) {
      emit('2', 'consolidate latest (direct unsharded)', 'FAIL', describeBatchError(e));
    }

    const ids = minted.map((m) => m.stateId);
    const rootOf = (b: Uint8Array): DataHash => new DataHash(HashAlgorithm.SHA256, b);

    // ---- scenario 3: exact root
    if (masterRoot === null) {
      emit('3', 'exact root', 'FAIL', 'no latest root known (scenario 2 failed)');
    } else {
      const ev: string[] = [];
      let failed = false;
      try {
        const b = await aggregator.getInclusionProofs(ids, { stateRoot: rootOf(masterRoot) });
        ev.push(`retained root: ${b.proofs.length} proofs, partitionView=${b.partitionViewBytes !== null}`);
        failed ||= b.proofs.length !== n || b.partitionViewBytes !== null;
      } catch (e) {
        failed = true;
        ev.push(`retained root: ${describeBatchError(e)}`);
      }
      const extra = await newMint();
      await submit(extra);
      await wait(extra);
      try {
        await aggregator.getInclusionProofs([...ids, extra.stateId], { stateRoot: rootOf(masterRoot) });
        failed = true;
        ev.push('old root unexpectedly contains the new state');
      } catch (e) {
        ev.push(`old root + new state: ${describeBatchError(e)}`);
        failed ||= !(e instanceof BatchProofError && e.code === -32008 && e.detail === 'state_not_in_root' && JSON.stringify(e.indexesByClass?.not_in_root) === JSON.stringify([n]));
      }
      const unknownRoot = new Uint8Array(32);
      unknownRoot[0] = 0xde;
      unknownRoot[31] = 0xad;
      try {
        await aggregator.getInclusionProofs(ids, { stateRoot: rootOf(unknownRoot) });
        failed = true;
        ev.push('unknown root unexpectedly served');
      } catch (e) {
        ev.push(`unknown root: ${describeBatchError(e)}`);
        failed ||= !(e instanceof BatchProofError && e.code === -32008 && e.detail === 'view_not_retained');
      }
      emit('3', 'exact root (retained, other-state, unknown)', failed ? 'FAIL' : 'PASS', ev.join('; '));
      if (retained > 0 && retained <= 40) {
        for (let i = 0; i < retained + 1; i++) {
          const m = await newMint();
          await submit(m);
          await wait(m);
        }
        try {
          await aggregator.getInclusionProofs(ids, { stateRoot: rootOf(masterRoot) });
          emit('3b', 'evicted root', 'FAIL', 'evicted root still served');
        } catch (e) {
          const ok = e instanceof BatchProofError && e.code === -32008 && e.detail === 'view_not_retained';
          emit('3b', 'evicted root', ok ? 'PASS' : 'FAIL', describeBatchError(e));
        }
      } else {
        emit('3b', 'evicted root', 'N-A', `server retention not small enough to evict cheaply (IX_RETAINED=${retained})`);
      }
    }

    // ---- scenario 4: status hints and batch details
    {
      const ev: string[] = [];
      let failed = false;
      let gotPending = false;
      for (let attempt = 0; attempt < 3 && !gotPending; attempt++) {
        const pend = await newMint();
        await submit(pend);
        try {
          await aggregator.getInclusionProofs([pend.stateId]);
          ev.push('batch served the state before the round closed (race)');
        } catch (e) {
          ev.push(`pending: ${describeBatchError(e)}`);
          gotPending =
            e instanceof BatchProofError &&
            e.code === -32008 &&
            e.detail === 'state_pending' &&
            e.retryable &&
            JSON.stringify(e.indexesByClass?.pending) === JSON.stringify([0]);
        }
        await wait(pend);
      }
      if (!gotPending) {
        failed = true;
        ev.push('pending not reproduced');
      }
      const unk = await newMint(); // never submitted
      try {
        await aggregator.getInclusionProofs([ids[0], unk.stateId, ids[1]]);
        failed = true;
        ev.push('unknown state served');
      } catch (e) {
        ev.push(`unknown: ${describeBatchError(e)}`);
        failed ||= !(e instanceof BatchProofError && e.code === -32008 && e.detail === 'state_unknown' && JSON.stringify(e.indexesByClass?.unknown) === JSON.stringify([1]));
      }
      try {
        const r = await aggregator.getInclusionProof(unk.stateId, { includeStatusHint: true });
        ev.push(`v2 includeStatus unknown -> hint=${r.statusHint} proof=${r.inclusionProof !== null}`);
        failed ||= r.inclusionProof !== null;
      } catch (e) {
        // rugregator's legacy v2 answers an RPC error (-32020) instead of a status object
        ev.push(`v2 unknown -> ${e instanceof Error ? e.name + ': ' + e.message : String(e)}`);
      }
      emit('4', 'status hints (pending/unknown) and data.indexes', failed ? 'FAIL' : 'PASS', ev.join('; '));
      // expired: a deadline one second after the latest seal time lands in a later round when the request arrives
      // while a round waits for its certificate; scan the round period
      let expired = false;
      const notes: string[] = [];
      for (let off = 0; off < 24 && !expired; off++) {
        await sleep(off * 60);
        const latest = await aggregator.getInclusionProofs([ids[0]]);
        const ts = latest.proofs[0].inclusionProof?.unicityCertificate.unicitySeal.timestamp ?? 0n;
        const m = await newMint(ts + 1n);
        try {
          await submit(m);
        } catch (e) {
          notes.push(`attempt ${off}: rejected at admission: ${describeBatchError(e)}`);
          continue;
        }
        for (;;) {
          try {
            await aggregator.getInclusionProofs([m.stateId]);
            notes.push(`attempt ${off}: included`);
            break;
          } catch (e) {
            if (e instanceof BatchProofError && e.detail === 'state_pending') {
              await sleep(100);
              continue;
            }
            notes.push(`attempt ${off}: batch ${describeBatchError(e)}`);
            if (e instanceof BatchProofError && e.detail === 'state_expired' && JSON.stringify(e.indexesByClass?.expired) === JSON.stringify([0])) {
              // the SDK wait maps the same hint to its typed error
              try {
                await wait(m);
                notes.push('SDK wait returned a proof');
              } catch (w) {
                notes.push(`SDK wait -> ${(w as Error).name}`);
                expired = (w as Error).name === 'InclusionProofExpiredError';
              }
            }
            break;
          }
        }
      }
      const shown = notes.length > 5 ? [...notes.slice(0, 2), '...', ...notes.slice(-3)] : notes;
      emit('4b', 'expired hint', expired ? 'PASS' : 'N-A', expired ? shown.join('; ') : `not reproduced: ${shown.join('; ')}`);
    }

    // ---- scenario 5: non-inclusion
    {
      const ev: string[] = [];
      let failed = false;
      const absent = (await newMint()).stateId;
      let encoded = new Uint8Array(0);
      const verifyCtx = { trustBase: context.trustBase, unicityCertificateVerifier: context.unicityCertificateVerifier };
      try {
        const answer = await aggregator.getNonInclusionProof(absent);
        if (answer.kind !== 'absence_proof') {
          failed = true;
          ev.push(`absent id: ${answer.kind}`);
        } else {
          const v = await verifyNonInclusion(answer.proof, verifyCtx, { expectedPartition: partition });
          if (v.status === VerificationStatus.OK) {
            ev.push(`absence verified at round ${v.absence.absentAtRound} (emptyTree=${v.absence.emptyTree})`);
            encoded = answer.proof.toCBOR();
          } else {
            failed = true;
            ev.push(`verify: ${v.verdict}`);
          }
        }
      } catch (e) {
        failed = true;
        ev.push(`absent id: ${describeBatchError(e)}`);
      }
      try {
        const answer = await aggregator.getNonInclusionProof(ids[0]);
        ev.push(`present id: ${answer.kind}`);
        failed ||= answer.kind !== 'state_included_hint';
      } catch (e) {
        failed = true;
        ev.push(`present id: ${e instanceof NonInclusionProofError ? e.kind : String(e)}`);
      }
      // tampering: flip one bit of every byte in turn
      const accepted: number[] = [];
      let total = 0;
      for (let i = 0; i < encoded.length; i++) {
        const mutated = new Uint8Array(encoded);
        mutated[i] ^= 1;
        total++;
        let proof: NonInclusionProof;
        try {
          proof = NonInclusionProof.decode(absent, mutated);
        } catch {
          continue;
        }
        const v = await verifyNonInclusion(proof, verifyCtx, { expectedPartition: partition });
        if (v.status === VerificationStatus.OK) {
          accepted.push(i);
        }
      }
      if (encoded.length === 0) {
        failed = true;
      } else if (accepted.length === 0) {
        ev.push(`tamper: all ${total} single-bit flips rejected`);
      } else {
        // block number (unauthenticated metadata, right after the array header) and the final byte are non-binding
        const head = ({ 0x18: 2, 0x19: 3, 0x1a: 5, 0x1b: 9 } as Record<number, number>)[encoded[1]] ?? 1;
        const nonBinding = new Set<number>([encoded.length - 1]);
        for (let k = 1; k < 1 + head; k++) {
          nonBinding.add(k);
        }
        const binding = accepted.filter((o) => !nonBinding.has(o));
        ev.push(
          `tamper: ${accepted.length} of ${total} single-bit flips still verified at offsets ${JSON.stringify(accepted)} (non-binding: block number, final byte; binding offsets accepted: ${JSON.stringify(binding)})`,
        );
        failed ||= binding.length > 0;
      }
      emit('5', 'non-inclusion (absent, present, tampered)', failed ? 'FAIL' : 'PASS', ev.join('; '));
    }

    // ---- scenario 6: error envelope
    {
      const cases = JSON.parse(readFileSync(env('IX_CASES'), 'utf8')).cases as any[];
      const id0 = HexConverter.encode(ids[0].data);
      const bad: string[] = [];
      for (const c of cases) {
        const method = c.method ?? 'get_inclusion_proofs.v1';
        let params: unknown;
        if (c.gen === 'ids257') {
          params = { stateIds: Array.from({ length: 257 }, (_, i) => (i + 1).toString(16).padStart(64, '0')), stateRoot: 'latest' };
        } else if (c.gen === 'oversize') {
          params = { pad: 'a'.repeat(70 * 1024), stateIds: [id0], stateRoot: 'latest' };
        } else {
          params = JSON.parse(JSON.stringify(c.params).replaceAll('{ID}', id0));
        }
        const { json, status } = await post(url, JSON.stringify({ id: 7, jsonrpc: '2.0', method, params }));
        const e = json?.error;
        if (!e) {
          bad.push(`${c.name}: no error`);
          continue;
        }
        let diffs = '';
        if (status !== c.http) diffs += ` http=${status}(want ${c.http})`;
        if (e.code !== c.code) diffs += ` code=${e.code}(want ${c.code})`;
        if (c.reason !== null && e.data?.reason !== c.reason) diffs += ` reason=${e.data?.reason}(want ${c.reason})`;
        if (c.detail !== null && e.data?.detail !== c.detail) diffs += ` detail=${e.data?.detail}(want ${c.detail})`;
        if (diffs) bad.push(`${c.name}:${diffs}`);
      }
      // the typed client mapping of a limit error: the SDK refuses 257 ids before sending
      let local: string;
      try {
        await aggregator.getInclusionProofs(await Promise.all(Array.from({ length: 257 }, async () => (await newMint()).stateId)));
        local = 'client-side 257 ids: sent';
      } catch (e) {
        local = `client-side 257 ids: ${describeBatchError(e)}`;
      }
      emit(
        '6',
        'error envelope (limits, malformed params)',
        bad.length === 0 ? 'PASS' : 'FAIL',
        bad.length === 0 ? `${cases.length} cases match the reference envelope; ${local}` : `${bad.join('; ')}; ${local}`,
      );
    }
    await sleep(0);
  }, 600_000);
});
