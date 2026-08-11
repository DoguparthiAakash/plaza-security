use std::collections::{HashMap, HashSet};
use tokio::sync::RwLock;
use plaza_foundation::core::{PlazaResult, PlazaError};
use serde::{Serialize, Deserialize};

/// A named role with a set of permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    pub description: String,
    pub permissions: HashSet<Permission>,
}

/// Fine-grained permission constants.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    WorkspaceCreate,
    WorkspaceRead,
    WorkspaceUpdate,
    WorkspaceDelete,
    WorkspaceStart,
    WorkspaceStop,
    ImageImport,
    ImageDelete,
    ImageGarbageCollect,
    NetworkManage,
    SecurityAudit,
    UserManage,
    RoleManage,
    SystemAdmin,
}

/// A principal (user or service account) with assigned roles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    pub id: String,
    pub name: String,
    pub roles: Vec<String>,
}

/// Role-Based Access Control engine.
pub struct RbacEngine {
    roles: RwLock<HashMap<String, Role>>,
    principals: RwLock<HashMap<String, Principal>>,
}

impl RbacEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            roles: RwLock::new(HashMap::new()),
            principals: RwLock::new(HashMap::new()),
        };
        // Seed with default roles
        tokio::runtime::Handle::try_current().ok(); // no-op, just for context
        engine
    }

    /// Seed the default built-in roles.
    pub async fn seed_defaults(&self) {
        let admin = Role {
            name: "admin".into(),
            description: "Full system access".into(),
            permissions: HashSet::from([
                Permission::SystemAdmin,
                Permission::WorkspaceCreate, Permission::WorkspaceRead,
                Permission::WorkspaceUpdate, Permission::WorkspaceDelete,
                Permission::WorkspaceStart, Permission::WorkspaceStop,
                Permission::ImageImport, Permission::ImageDelete, Permission::ImageGarbageCollect,
                Permission::NetworkManage, Permission::SecurityAudit,
                Permission::UserManage, Permission::RoleManage,
            ]),
        };

        let operator = Role {
            name: "operator".into(),
            description: "Workspace and runtime management".into(),
            permissions: HashSet::from([
                Permission::WorkspaceCreate, Permission::WorkspaceRead,
                Permission::WorkspaceUpdate, Permission::WorkspaceStart,
                Permission::WorkspaceStop, Permission::ImageImport,
            ]),
        };

        let viewer = Role {
            name: "viewer".into(),
            description: "Read-only access".into(),
            permissions: HashSet::from([Permission::WorkspaceRead]),
        };

        let mut roles = self.roles.write().await;
        roles.insert("admin".into(), admin);
        roles.insert("operator".into(), operator);
        roles.insert("viewer".into(), viewer);
    }

    /// Register a custom role.
    pub async fn create_role(&self, role: Role) -> PlazaResult<()> {
        let mut roles = self.roles.write().await;
        if roles.contains_key(&role.name) {
            return Err(PlazaError::Internal(format!("Role '{}' already exists", role.name)));
        }
        roles.insert(role.name.clone(), role);
        Ok(())
    }

    /// Assign a role to a principal.
    pub async fn assign_role(&self, principal_id: &str, role_name: &str) -> PlazaResult<()> {
        let roles = self.roles.read().await;
        if !roles.contains_key(role_name) {
            return Err(PlazaError::NotFound(format!("Role '{}'", role_name)));
        }
        drop(roles);

        let mut principals = self.principals.write().await;
        let principal = principals.entry(principal_id.to_string()).or_insert_with(|| Principal {
            id: principal_id.to_string(),
            name: principal_id.to_string(),
            roles: Vec::new(),
        });

        if !principal.roles.contains(&role_name.to_string()) {
            principal.roles.push(role_name.to_string());
        }
        Ok(())
    }

    /// Check if a principal has a specific permission.
    pub async fn has_permission(&self, principal_id: &str, permission: &Permission) -> bool {
        let principals = self.principals.read().await;
        let Some(principal) = principals.get(principal_id) else {
            return false;
        };

        let roles = self.roles.read().await;
        for role_name in &principal.roles {
            if let Some(role) = roles.get(role_name) {
                if role.permissions.contains(&Permission::SystemAdmin) || role.permissions.contains(permission) {
                    return true;
                }
            }
        }
        false
    }

    /// Enforce a permission check, returning an error if denied.
    pub async fn require_permission(&self, principal_id: &str, permission: &Permission) -> PlazaResult<()> {
        if self.has_permission(principal_id, permission).await {
            Ok(())
        } else {
            Err(PlazaError::Internal(format!(
                "Principal '{}' lacks permission {:?}", principal_id, permission
            )))
        }
    }
}
