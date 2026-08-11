use std::collections::HashMap;
use tokio::sync::RwLock;
use plaza_foundation::core::{PlazaResult, PlazaError};
use serde::{Serialize, Deserialize};

/// Identity provider type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IdentityProvider {
    Local,
    Ldap,
    OAuth2,
    Saml,
}

/// A managed identity (user or service account).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub email: Option<String>,
    pub provider: IdentityProvider,
    pub enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_login: Option<chrono::DateTime<chrono::Utc>>,
    pub metadata: HashMap<String, String>,
}

/// Service account for machine-to-machine auth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccount {
    pub id: String,
    pub name: String,
    pub secret_hash: String,
    pub scopes: Vec<String>,
    pub enabled: bool,
}

/// Identity and Access Management engine.
pub struct IamManager {
    identities: RwLock<HashMap<String, Identity>>,
    service_accounts: RwLock<HashMap<String, ServiceAccount>>,
}

impl IamManager {
    pub fn new() -> Self {
        Self {
            identities: RwLock::new(HashMap::new()),
            service_accounts: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new local identity.
    pub async fn create_identity(&self, username: &str, display_name: &str, email: Option<&str>) -> PlazaResult<Identity> {
        let mut store = self.identities.write().await;
        if store.values().any(|i| i.username == username) {
            return Err(PlazaError::Internal(format!("Username '{}' already exists", username)));
        }

        let identity = Identity {
            id: uuid::Uuid::new_v4().to_string(),
            username: username.to_string(),
            display_name: display_name.to_string(),
            email: email.map(String::from),
            provider: IdentityProvider::Local,
            enabled: true,
            created_at: chrono::Utc::now(),
            last_login: None,
            metadata: HashMap::new(),
        };

        store.insert(identity.id.clone(), identity.clone());
        Ok(identity)
    }

    /// Get an identity by ID.
    pub async fn get_identity(&self, id: &str) -> PlazaResult<Identity> {
        let store = self.identities.read().await;
        store.get(id).cloned().ok_or_else(|| PlazaError::NotFound(format!("Identity {}", id)))
    }

    /// Find identity by username.
    pub async fn find_by_username(&self, username: &str) -> Option<Identity> {
        let store = self.identities.read().await;
        store.values().find(|i| i.username == username).cloned()
    }

    /// Disable an identity (soft delete).
    pub async fn disable_identity(&self, id: &str) -> PlazaResult<()> {
        let mut store = self.identities.write().await;
        let identity = store.get_mut(id).ok_or_else(|| PlazaError::NotFound(format!("Identity {}", id)))?;
        identity.enabled = false;
        Ok(())
    }

    /// Record a login timestamp.
    pub async fn record_login(&self, id: &str) -> PlazaResult<()> {
        let mut store = self.identities.write().await;
        let identity = store.get_mut(id).ok_or_else(|| PlazaError::NotFound(format!("Identity {}", id)))?;
        identity.last_login = Some(chrono::Utc::now());
        Ok(())
    }

    /// Create a service account for M2M authentication.
    pub async fn create_service_account(&self, name: &str, scopes: Vec<String>) -> PlazaResult<ServiceAccount> {
        let mut store = self.service_accounts.write().await;
        let sa = ServiceAccount {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            secret_hash: uuid::Uuid::new_v4().to_string(), // placeholder
            scopes,
            enabled: true,
        };
        store.insert(sa.id.clone(), sa.clone());
        Ok(sa)
    }

    /// List all identities.
    pub async fn list_identities(&self) -> Vec<Identity> {
        let store = self.identities.read().await;
        store.values().cloned().collect()
    }
}
