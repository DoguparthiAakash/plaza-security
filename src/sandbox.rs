use plaza_foundation::core::PlazaResult;

pub struct CapabilitySandbox;

impl CapabilitySandbox {
    pub fn new() -> Self {
        Self
    }
    
    pub async fn isolate(&self, _capabilities: &[&str]) -> PlazaResult<()> {
        Ok(()) // DP1 Stub
    }
}
