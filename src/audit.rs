use std::collections::VecDeque;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// Severity level for audit events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditSeverity {
    Info,
    Warning,
    Critical,
}

/// An immutable audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub principal: String,
    pub action: String,
    pub resource: String,
    pub outcome: AuditOutcome,
    pub severity: AuditSeverity,
    pub details: Option<serde_json::Value>,
    pub source_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditOutcome {
    Success,
    Denied,
    Error,
}

/// Append-only audit logger with configurable retention.
pub struct AuditLogger {
    entries: RwLock<VecDeque<AuditEntry>>,
    max_entries: usize,
}

impl AuditLogger {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(VecDeque::new()),
            max_entries,
        }
    }

    /// Log a successful action.
    pub async fn log_success(&self, principal: &str, action: &str, resource: &str) {
        self.log(principal, action, resource, AuditOutcome::Success, AuditSeverity::Info, None, None).await;
    }

    /// Log a denied action.
    pub async fn log_denied(&self, principal: &str, action: &str, resource: &str) {
        self.log(principal, action, resource, AuditOutcome::Denied, AuditSeverity::Warning, None, None).await;
    }

    /// Log a critical security event.
    pub async fn log_critical(&self, principal: &str, action: &str, resource: &str, details: serde_json::Value) {
        self.log(principal, action, resource, AuditOutcome::Error, AuditSeverity::Critical, Some(details), None).await;
    }

    /// General-purpose audit log entry.
    pub async fn log(
        &self,
        principal: &str,
        action: &str,
        resource: &str,
        outcome: AuditOutcome,
        severity: AuditSeverity,
        details: Option<serde_json::Value>,
        source_ip: Option<String>,
    ) {
        let entry = AuditEntry {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            principal: principal.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            outcome,
            severity,
            details,
            source_ip,
        };

        let mut entries = self.entries.write().await;
        entries.push_back(entry);

        // Enforce retention
        while entries.len() > self.max_entries {
            entries.pop_front();
        }
    }

    /// Query recent audit entries.
    pub async fn recent(&self, limit: usize) -> Vec<AuditEntry> {
        let entries = self.entries.read().await;
        entries.iter().rev().take(limit).cloned().collect()
    }

    /// Query entries by principal.
    pub async fn by_principal(&self, principal: &str, limit: usize) -> Vec<AuditEntry> {
        let entries = self.entries.read().await;
        entries.iter()
            .rev()
            .filter(|e| e.principal == principal)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Query entries by severity.
    pub async fn by_severity(&self, severity: AuditSeverity, limit: usize) -> Vec<AuditEntry> {
        let entries = self.entries.read().await;
        entries.iter()
            .rev()
            .filter(|e| e.severity == severity)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Total count of audit entries.
    pub async fn count(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Export all entries as JSON.
    pub async fn export_json(&self) -> String {
        let entries = self.entries.read().await;
        let all: Vec<_> = entries.iter().collect();
        serde_json::to_string_pretty(&all).unwrap_or_default()
    }
}
