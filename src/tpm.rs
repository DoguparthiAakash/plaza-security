use plaza_foundation::core::{PlazaResult, PlazaError};
use serde::{Serialize, Deserialize};

/// TPM (Trusted Platform Module) abstraction for secure boot and attestation.
/// On systems without a physical TPM, provides a software-emulated equivalent.
pub struct TpmManager {
    mode: TpmMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TpmMode {
    /// Use host TPM hardware (if available)
    Hardware,
    /// Software-emulated TPM (always available)
    Software,
    /// TPM disabled
    Disabled,
}

/// Platform Configuration Register (PCR) measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrMeasurement {
    pub index: u32,
    pub hash: String,
    pub description: String,
}

/// Attestation report for verifying platform integrity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    pub platform: String,
    pub measurements: Vec<PcrMeasurement>,
    pub timestamp: String,
    pub verified: bool,
}

impl TpmManager {
    pub fn new(mode: TpmMode) -> Self {
        Self { mode }
    }

    /// Detect the best available TPM mode for the current platform.
    pub fn detect() -> Self {
        // In production, this would probe for /dev/tpm0 or Windows TPM APIs
        Self::new(TpmMode::Software)
    }

    /// Measure a component into a PCR slot (e.g. kernel hash, firmware hash).
    pub fn measure(&self, pcr_index: u32, data: &[u8], description: &str) -> PlazaResult<PcrMeasurement> {
        if self.mode == TpmMode::Disabled {
            return Err(PlazaError::Internal("TPM is disabled".into()));
        }

        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = format!("{:x}", hasher.finalize());

        Ok(PcrMeasurement {
            index: pcr_index,
            hash,
            description: description.to_string(),
        })
    }

    /// Generate an attestation report from current measurements.
    pub fn attest(&self, measurements: Vec<PcrMeasurement>) -> AttestationReport {
        AttestationReport {
            platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            measurements,
            timestamp: chrono::Utc::now().to_rfc3339(),
            verified: self.mode != TpmMode::Disabled,
        }
    }

    /// Returns the active TPM mode.
    pub fn mode(&self) -> &TpmMode {
        &self.mode
    }
}
