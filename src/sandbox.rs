use std::collections::{HashMap, HashSet};
use tokio::sync::RwLock;
use plaza_foundation::core::{PlazaResult, PlazaError};
use serde::{Serialize, Deserialize};

/// Sandbox capability that can be granted or denied to a VM instance.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SandboxCapability {
    FileSystemRead,
    FileSystemWrite,
    NetworkAccess,
    ProcessSpawn,
    DeviceAccess,
    ClipboardAccess,
    DisplayAccess,
    AudioAccess,
    UsbPassthrough,
    GpuAccess,
}

/// Enforcement mode for sandbox violations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementMode {
    /// Block and log the violation
    Enforce,
    /// Allow but log a warning (useful for migration)
    Permissive,
    /// Disabled — no enforcement
    Disabled,
}

/// Per-instance sandbox profile.
#[derive(Debug, Clone)]
pub struct SandboxProfile {
    pub instance_id: String,
    pub allowed_capabilities: HashSet<SandboxCapability>,
    pub mode: EnforcementMode,
}

/// The sandbox manager enforces capability-based isolation for VM instances.
pub struct SandboxManager {
    profiles: RwLock<HashMap<String, SandboxProfile>>,
    default_mode: EnforcementMode,
}

impl SandboxManager {
    pub fn new(default_mode: EnforcementMode) -> Self {
        Self {
            profiles: RwLock::new(HashMap::new()),
            default_mode,
        }
    }

    /// Create a default-deny sandbox profile for an instance.
    pub async fn create_profile(&self, instance_id: &str) -> PlazaResult<()> {
        let mut profiles = self.profiles.write().await;
        if profiles.contains_key(instance_id) {
            return Err(PlazaError::Internal(format!("Profile already exists for {}", instance_id)));
        }
        profiles.insert(instance_id.to_string(), SandboxProfile {
            instance_id: instance_id.to_string(),
            allowed_capabilities: HashSet::new(), // default-deny
            mode: self.default_mode.clone(),
        });
        Ok(())
    }

    /// Grant a capability to an instance.
    pub async fn grant_capability(&self, instance_id: &str, cap: SandboxCapability) -> PlazaResult<()> {
        let mut profiles = self.profiles.write().await;
        let profile = profiles.get_mut(instance_id)
            .ok_or_else(|| PlazaError::NotFound(format!("Sandbox profile for {}", instance_id)))?;
        profile.allowed_capabilities.insert(cap);
        Ok(())
    }

    /// Revoke a capability from an instance.
    pub async fn revoke_capability(&self, instance_id: &str, cap: &SandboxCapability) -> PlazaResult<()> {
        let mut profiles = self.profiles.write().await;
        let profile = profiles.get_mut(instance_id)
            .ok_or_else(|| PlazaError::NotFound(format!("Sandbox profile for {}", instance_id)))?;
        profile.allowed_capabilities.remove(cap);
        Ok(())
    }

    /// Check if a capability is allowed for an instance.
    pub async fn check_capability(&self, instance_id: &str, cap: &SandboxCapability) -> bool {
        let profiles = self.profiles.read().await;
        match profiles.get(instance_id) {
            Some(profile) => {
                match profile.mode {
                    EnforcementMode::Disabled => true,
                    EnforcementMode::Permissive => {
                        // Allow but would log warning in production
                        true
                    }
                    EnforcementMode::Enforce => {
                        profile.allowed_capabilities.contains(cap)
                    }
                }
            }
            None => false, // No profile = fully denied
        }
    }

    /// Remove a sandbox profile (on instance deletion).
    pub async fn remove_profile(&self, instance_id: &str) {
        let mut profiles = self.profiles.write().await;
        profiles.remove(instance_id);
    }

    /// List all capabilities for an instance.
    pub async fn list_capabilities(&self, instance_id: &str) -> Vec<SandboxCapability> {
        let profiles = self.profiles.read().await;
        profiles.get(instance_id)
            .map(|p| p.allowed_capabilities.iter().cloned().collect())
            .unwrap_or_default()
    }
}
