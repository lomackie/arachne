use serde::Deserialize;
use std::io::Read;
use super::error::CniError;

#[derive(Debug, Deserialize)]
pub struct NetworkConfig {
    #[serde(rename = "cniVersion")]
    pub cni_version: String,
    pub name: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "prevResult")]
    pub prev_result: Option<serde_json::Value>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl NetworkConfig {
    pub fn from_stdin() -> Result<Self, CniError> {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        Ok(serde_json::from_str(&buf)?)
    }
}
