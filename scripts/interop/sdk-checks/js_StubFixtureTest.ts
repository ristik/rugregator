import { readFileSync } from 'node:fs';

import { UnicityCertificate } from '../../../src/api/bft/UnicityCertificate.js';
import { RootTrustBase } from '../../../src/api/bft/RootTrustBase.js';
import { UnicitySealHashMatchesWithRootHashRule } from '../../../src/api/bft/verification/rule/UnicitySealHashMatchesWithRootHashRule.js';
import { UnicitySealQuorumSignaturesVerificationRule } from '../../../src/api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js';
import { Secp256k1SignatureVerifier } from '../../../src/crypto/secp256k1/Secp256k1SignatureVerifier.js';
import { VerificationStatus } from '../../../src/verification/VerificationStatus.js';
import { HexConverter } from '../../../src/util/HexConverter.js';

describe('stub-anchor fixture', () => {
  it('is valid for the JS SDK', async () => {
    const f = JSON.parse(readFileSync(process.env.STUB_FIXTURE as string, 'utf8'));
    const tb = RootTrustBase.fromJSON(f.trustBase);
    const rule = new UnicitySealQuorumSignaturesVerificationRule(new Secp256k1SignatureVerifier());
    expect(f.certificates).toHaveLength(6);
    for (const c of f.certificates) {
      const raw = HexConverter.decode(c.unicityCertificate);
      const uc = UnicityCertificate.fromCBOR(raw);
      expect(HexConverter.encode(uc.toCBOR())).toEqual(c.unicityCertificate);
      expect(uc.technicalRecordHash?.length).toEqual(32);
      expect(uc.unicityTreeCertificate.partitionIdentifier).toEqual(BigInt(f.partitionId));
      expect((await UnicitySealHashMatchesWithRootHashRule.verify(uc)).status).toEqual(VerificationStatus.OK);
      expect(uc.unicitySeal.networkId.equals(tb.networkId)).toBe(true);
      expect(uc.unicitySeal.epoch).toEqual(tb.epoch);
      expect(uc.unicitySeal.rootChainRoundNumber >= tb.epochStartRound).toBe(true);
      expect((await rule.verify(tb, uc.unicitySeal)).status).toEqual(VerificationStatus.OK);
    }
  });
});
