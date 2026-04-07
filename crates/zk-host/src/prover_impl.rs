//! Real SP1 prover — compiled only with `--features prove`.

use anyhow::Context;
use sp1_sdk::blocking::{
    CpuProver, ProveRequest as SP1ProveRequest, Prover as SP1Prover, ProverClient,
};
use sp1_sdk::{Elf, HashableKey, ProvingKey, SP1Proof, SP1ProvingKey, SP1PublicValues, SP1Stdin};
use sp1_verifier::{Groth16Verifier, PlonkVerifier, GROTH16_VK_BYTES, PLONK_VK_BYTES};

/// The compiled guest ELF, embedded at build time by `sp1-build`.
const GUEST_ELF: Elf = sp1_sdk::include_elf!("zk-guest-program");

/// Selects the SP1 proof type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZkProofKind {
    /// Large proof, fast to generate (development / testing).
    Core,
    /// Constant-size recursive proof (~1.5MB), suitable for off-chain verification.
    Compressed,
    /// Groth16 SNARK (~260 bytes); cheap on-chain verification.
    Groth16,
    /// PLONK SNARK (~868 bytes); no trusted setup.
    Plonk,
}

impl std::fmt::Display for ZkProofKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZkProofKind::Core => f.write_str("core"),
            ZkProofKind::Compressed => f.write_str("compressed"),
            ZkProofKind::Groth16 => f.write_str("groth16"),
            ZkProofKind::Plonk => f.write_str("plonk"),
        }
    }
}

impl std::str::FromStr for ZkProofKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "core" => Ok(Self::Core),
            "compressed" => Ok(Self::Compressed),
            "groth16" => Ok(Self::Groth16),
            "plonk" => Ok(Self::Plonk),
            other => Err(format!("unknown proof kind: {other}")),
        }
    }
}

/// SP1 prover bound to the aggregator guest program.
///
/// Initialise once at startup with [`Prover::new`]; the resulting struct is
/// cheap to clone (it holds `Arc`-based internals).
pub struct Prover {
    client: CpuProver,
    pk: SP1ProvingKey,
}

impl Prover {
    /// Set up the prover.
    ///
    /// Run this once at startup and store the result in an `Arc<Prover>`.
    pub fn new() -> anyhow::Result<Self> {
        let client = ProverClient::builder().cpu().build();
        let pk = client.setup(GUEST_ELF).context("SP1 setup failed")?;
        Ok(Self { client, pk })
    }

    /// Build the stdin buffer: `prev_root[32] || new_root[32] || envelope`.
    fn make_stdin(envelope: &[u8], prev_root: [u8; 32], new_root: [u8; 32]) -> SP1Stdin {
        let mut input_buf = Vec::with_capacity(64 + envelope.len());
        input_buf.extend_from_slice(&prev_root);
        input_buf.extend_from_slice(&new_root);
        input_buf.extend_from_slice(envelope);

        let mut stdin = SP1Stdin::new();
        stdin.write(&input_buf);
        stdin
    }

    /// Generate a ZK consistency proof using the default (Core) proof kind.
    ///
    /// **Returns:** bincode-serialised `SP1ProofWithPublicValues` — the bytes
    /// expected by the `aggregator-zk-verifier-ffi` BFT Core library.
    ///
    /// This call is CPU-bound and can take minutes.  Run it inside
    /// `std::thread::spawn` so the async runtime is not blocked.
    pub fn prove(
        &self,
        envelope: &[u8],
        prev_root: [u8; 32],
        new_root: [u8; 32],
    ) -> anyhow::Result<Vec<u8>> {
        self.prove_with_kind(envelope, prev_root, new_root, ZkProofKind::Core)
    }

    /// Prove with an explicit proof kind.
    pub fn prove_with_kind(
        &self,
        envelope: &[u8],
        prev_root: [u8; 32],
        new_root: [u8; 32],
        kind: ZkProofKind,
    ) -> anyhow::Result<Vec<u8>> {
        let stdin = Self::make_stdin(envelope, prev_root, new_root);
        let proof = match kind {
            ZkProofKind::Core => self.client.prove(&self.pk, stdin).run(),
            ZkProofKind::Compressed => self.client.prove(&self.pk, stdin).compressed().run(),
            ZkProofKind::Groth16 => self.client.prove(&self.pk, stdin).groth16().run(),
            ZkProofKind::Plonk => self.client.prove(&self.pk, stdin).plonk().run(),
        }
        .context("SP1 proving failed")?;

        bincode::serialize(&proof).context("proof serialisation failed")
    }

    /// Execute the guest program without generating a proof.
    ///
    /// Fast (seconds); useful for testing.  Returns the public values bytes
    /// (`prev_root || new_root`).
    pub fn execute(
        &self,
        envelope: &[u8],
        prev_root: [u8; 32],
        new_root: [u8; 32],
    ) -> anyhow::Result<[u8; 64]> {
        let stdin = Self::make_stdin(envelope, prev_root, new_root);
        let (mut public_values, _): (SP1PublicValues, _) = self
            .client
            .execute(GUEST_ELF, stdin)
            .run()
            .context("SP1 execution failed")?;

        let mut out = [0u8; 64];
        public_values.read_slice(&mut out);
        Ok(out)
    }

    /// The 32-byte vkey hash that uniquely identifies this guest program.
    pub fn vkey_bytes32(&self) -> [u8; 32] {
        self.pk.verifying_key().bytes32_raw()
    }

    /// Serialise the verifying key to bytes (bincode).
    ///
    /// These bytes are what `extract-vkey` writes to `vkey.bin` and what
    /// `aggregator-zk-verifier-ffi` loads at startup.
    pub fn vkey_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self.pk.verifying_key()).context("vkey serialisation failed")
    }

    /// Verify a proof using the prover's own verifying key.
    ///
    /// - **Groth16 / Plonk**: verified with a pure algebraic verifier (`sp1-verifier`) in < 5 ms.
    ///   No worker infrastructure is involved.
    /// - **Core / Compressed (STARK)**: verified via the cached [`CpuProver`] instance.
    ///
    /// Useful for in-process round-trip testing.
    pub fn verify(
        &self,
        proof_bytes: &[u8],
        prev_root: [u8; 32],
        new_root: [u8; 32],
    ) -> anyhow::Result<()> {
        let proof: sp1_sdk::SP1ProofWithPublicValues =
            bincode::deserialize(proof_bytes).context("proof deserialisation failed")?;

        // Check public values match.
        let pv = proof.public_values.as_slice();
        anyhow::ensure!(pv.len() >= 64, "public values too short");
        anyhow::ensure!(&pv[0..32] == prev_root, "prev_root mismatch");
        anyhow::ensure!(&pv[32..64] == new_root, "new_root mismatch");

        let vkey_hash = self.pk.verifying_key().bytes32(); // "0x<64 hex chars>"
        let pv_bytes = proof.public_values.to_vec();

        match &proof.proof {
            SP1Proof::Groth16(_) => {
                // Fast algebraic path — does NOT initialise any worker/prover state.
                let wire = proof.bytes();
                Groth16Verifier::verify(&wire, &pv_bytes, &vkey_hash, &GROTH16_VK_BYTES)
                    .map_err(|e| anyhow::anyhow!("Groth16 verification failed: {e:?}"))
            }
            SP1Proof::Plonk(_) => {
                let wire = proof.bytes();
                PlonkVerifier::verify(&wire, &pv_bytes, &vkey_hash, &PLONK_VK_BYTES)
                    .map_err(|e| anyhow::anyhow!("Plonk verification failed: {e:?}"))
            }
            SP1Proof::Core(_) | SP1Proof::Compressed(_) => {
                // STARK verification uses the cached CpuProver (initialised once in Prover::new).
                self.client
                    .verify(&proof, self.pk.verifying_key(), None)
                    .context("SP1 STARK verification failed")
            }
        }
    }
}
