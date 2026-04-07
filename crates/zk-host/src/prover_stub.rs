//! Stub prover used when the `prove` feature is NOT enabled.
//!
//! Calling [`Prover::prove`] always returns an error; the type exists so the
//! aggregator binary can be compiled and linked without SP1.

/// Proof kind selection (stub — all variants produce an error at runtime).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZkProofKind {
    Core,
    Compressed,
    Groth16,
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

/// Stub prover — always errors when `prove` feature is disabled.
pub struct Prover;

impl Prover {
    /// Attempt to construct a prover.
    ///
    /// Always returns `Err` because the crate was compiled without the
    /// `prove` feature.  Print a clear message so the operator knows how
    /// to fix it.
    pub fn new() -> anyhow::Result<Self> {
        anyhow::bail!(
            "zk-host was compiled without --features prove; \
             rebuild with `cargo build --features aggregator/zk` to enable SP1 proving"
        )
    }

    /// Generate a ZK consistency proof (stub — always errors).
    pub fn prove(
        &self,
        _envelope: &[u8],
        _prev_root: [u8; 32],
        _new_root: [u8; 32],
    ) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("zk-host compiled without prove feature")
    }

    /// Generate a ZK consistency proof with an explicit kind (stub — always errors).
    pub fn prove_with_kind(
        &self,
        _envelope: &[u8],
        _prev_root: [u8; 32],
        _new_root: [u8; 32],
        _kind: ZkProofKind,
    ) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("zk-host compiled without prove feature")
    }

    /// Returns the guest program's 32-byte vkey hash (stub — always errors).
    pub fn vkey_bytes32(&self) -> anyhow::Result<[u8; 32]> {
        anyhow::bail!("zk-host compiled without prove feature")
    }

    /// Verify a proof (stub — always errors).
    pub fn verify(
        &self,
        _proof_bytes: &[u8],
        _prev_root: [u8; 32],
        _new_root: [u8; 32],
    ) -> anyhow::Result<()> {
        anyhow::bail!("zk-host compiled without prove feature")
    }
}
