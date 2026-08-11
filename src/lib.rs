//! # plaza-security
//!
//! Comprehensive security subsystem for PlazaVM.
//!
//! Provides:
//! - **RBAC**: Role-Based Access Control with built-in roles
//! - **Audit**: Append-only immutable audit log with retention
//! - **Encryption**: Key derivation, hashing, and data-at-rest encryption
//! - **Sandbox**: Capability-based VM isolation with enforcement modes
//! - **IAM**: Identity and Access Management with service accounts
//! - **Network Policy**: Priority-based traffic rule evaluation
//! - **TPM**: Trusted Platform Module for attestation and measurements

pub mod audit;
pub mod encryption;
pub mod iam;
pub mod network_policy;
pub mod rbac;
pub mod sandbox;
pub mod tpm;

pub use audit::{AuditLogger, AuditEntry, AuditSeverity, AuditOutcome};
pub use encryption::{EncryptionEngine, EncryptionMode};
pub use iam::{IamManager, Identity, IdentityProvider};
pub use network_policy::{NetworkPolicyEngine, NetworkSecurityPolicy, PolicyAction};
pub use rbac::{RbacEngine, Role, Permission, Principal};
pub use sandbox::{SandboxManager, SandboxCapability, EnforcementMode};
pub use tpm::{TpmManager, TpmMode, AttestationReport};

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rbac_lifecycle() {
        let rbac = RbacEngine::new();
        rbac.seed_defaults().await;

        rbac.assign_role("user-1", "operator").await.unwrap();

        assert!(rbac.has_permission("user-1", &Permission::WorkspaceCreate).await);
        assert!(!rbac.has_permission("user-1", &Permission::SecurityAudit).await);

        rbac.assign_role("user-1", "admin").await.unwrap();
        assert!(rbac.has_permission("user-1", &Permission::SecurityAudit).await);
    }

    #[tokio::test]
    async fn test_audit_logging() {
        let logger = AuditLogger::new(100);

        logger.log_success("admin", "workspace.create", "ws-1").await;
        logger.log_denied("viewer", "workspace.delete", "ws-1").await;
        logger.log_critical("hacker", "brute_force", "auth", serde_json::json!({"attempts": 100})).await;

        assert_eq!(logger.count().await, 3);

        let criticals = logger.by_severity(AuditSeverity::Critical, 10).await;
        assert_eq!(criticals.len(), 1);
        assert_eq!(criticals[0].principal, "hacker");
    }

    #[tokio::test]
    async fn test_sandbox_default_deny() {
        let sandbox = SandboxManager::new(EnforcementMode::Enforce);
        sandbox.create_profile("vm-1").await.unwrap();

        // Default deny - nothing allowed
        assert!(!sandbox.check_capability("vm-1", &SandboxCapability::NetworkAccess).await);
        assert!(!sandbox.check_capability("vm-1", &SandboxCapability::FileSystemWrite).await);

        // Grant network access
        sandbox.grant_capability("vm-1", SandboxCapability::NetworkAccess).await.unwrap();
        assert!(sandbox.check_capability("vm-1", &SandboxCapability::NetworkAccess).await);
        assert!(!sandbox.check_capability("vm-1", &SandboxCapability::FileSystemWrite).await);
    }

    #[tokio::test]
    async fn test_encryption_roundtrip() {
        let engine = EncryptionEngine::new(EncryptionMode::Aes256Gcm);
        let params = encryption::KeyDerivationParams::default();
        let key = engine.derive_key("my-secret-passphrase", &params);
        assert_eq!(key.len(), 32);

        let plaintext = b"Hello, PlazaVM!";
        let ciphertext = engine.encrypt(&key, plaintext).unwrap();
        assert_ne!(&ciphertext, plaintext);

        let decrypted = engine.decrypt(&key, &ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_iam_identity_crud() {
        let iam = IamManager::new();

        let identity = iam.create_identity("alice", "Alice Smith", Some("alice@example.com")).await.unwrap();
        assert_eq!(identity.username, "alice");

        // Duplicate should fail
        let result = iam.create_identity("alice", "Alice Duplicate", None).await;
        assert!(result.is_err());

        // Find by username
        let found = iam.find_by_username("alice").await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().display_name, "Alice Smith");
    }

    #[tokio::test]
    async fn test_network_policy_evaluation() {
        let engine = NetworkPolicyEngine::new();
        let mut policy = NetworkPolicyEngine::default_deny_policy("vm-1");

        // Default deny - HTTP ingress should be denied
        let action = engine.evaluate(&policy, "ingress", "tcp", 80, None);
        assert_eq!(action, PolicyAction::Deny);

        // DNS egress should be allowed (built-in rule)
        let action = engine.evaluate(&policy, "egress", "udp", 53, None);
        assert_eq!(action, PolicyAction::Allow);

        // Add HTTP ingress rule
        policy.ingress_rules.push(network_policy::NetworkRule {
            name: "allow-http".into(),
            protocol: "tcp".into(),
            port_range: Some((80, 80)),
            cidr: None,
            action: PolicyAction::Allow,
            priority: 100,
        });

        let action = engine.evaluate(&policy, "ingress", "tcp", 80, None);
        assert_eq!(action, PolicyAction::Allow);
    }

    #[test]
    fn test_tpm_measurement() {
        let tpm = TpmManager::detect();
        let measurement = tpm.measure(0, b"kernel-image-data", "Kernel Image Hash").unwrap();
        assert!(!measurement.hash.is_empty());
        assert_eq!(measurement.index, 0);
    }
}
