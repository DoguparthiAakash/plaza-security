use plaza_foundation::core::{PlazaResult, PlazaError};
use serde::{Serialize, Deserialize};

/// Network security policy for a workspace or instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSecurityPolicy {
    pub instance_id: String,
    pub default_action: PolicyAction,
    pub ingress_rules: Vec<NetworkRule>,
    pub egress_rules: Vec<NetworkRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyAction {
    Allow,
    Deny,
    Log,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRule {
    pub name: String,
    pub protocol: String,
    pub port_range: Option<(u16, u16)>,
    pub cidr: Option<String>,
    pub action: PolicyAction,
    pub priority: u32,
}

/// Network policy engine for evaluating traffic rules.
pub struct NetworkPolicyEngine;

impl NetworkPolicyEngine {
    pub fn new() -> Self {
        Self
    }

    /// Create a default-deny policy for an instance.
    pub fn default_deny_policy(instance_id: &str) -> NetworkSecurityPolicy {
        NetworkSecurityPolicy {
            instance_id: instance_id.to_string(),
            default_action: PolicyAction::Deny,
            ingress_rules: Vec::new(),
            egress_rules: vec![
                // Allow DNS egress by default
                NetworkRule {
                    name: "allow-dns".into(),
                    protocol: "udp".into(),
                    port_range: Some((53, 53)),
                    cidr: None,
                    action: PolicyAction::Allow,
                    priority: 100,
                },
            ],
        }
    }

    /// Evaluate whether traffic should be allowed given a policy.
    pub fn evaluate(
        &self,
        policy: &NetworkSecurityPolicy,
        direction: &str,
        protocol: &str,
        port: u16,
        remote_cidr: Option<&str>,
    ) -> PolicyAction {
        let rules = match direction {
            "ingress" => &policy.ingress_rules,
            "egress" => &policy.egress_rules,
            _ => return policy.default_action.clone(),
        };

        // Sort by priority (lower number = higher priority)
        let mut sorted: Vec<_> = rules.iter().collect();
        sorted.sort_by_key(|r| r.priority);

        for rule in sorted {
            // Protocol match
            if rule.protocol != "*" && rule.protocol != protocol {
                continue;
            }

            // Port range match
            if let Some((lo, hi)) = rule.port_range {
                if port < lo || port > hi {
                    continue;
                }
            }

            // CIDR match (simplified — exact string match for now)
            if let (Some(rule_cidr), Some(req_cidr)) = (&rule.cidr, remote_cidr) {
                if rule_cidr != req_cidr {
                    continue;
                }
            }

            return rule.action.clone();
        }

        policy.default_action.clone()
    }
}
