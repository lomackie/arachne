use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CniError {
    #[error("invalid CNI environment: {0}")]
    InvalidEnv(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to decode CNI config: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported CNI version: {0}")]
    UnsupportedVersion(String),
    #[error("IPAM error: {0}")]
    Ipam(String),
    #[error("network setup error: {0}")]
    Netlink(String),
}

impl CniError {
    pub fn code(&self) -> u32 {
        match self {
            CniError::UnsupportedVersion(_) => 1,
            CniError::InvalidEnv(_) => 4,
            CniError::Io(_) => 5,
            CniError::Json(_) => 6,
            CniError::Ipam(_) => 11,
            CniError::Netlink(_) => 100,
        }
    }
}

#[derive(Serialize)]
pub struct CniErrorResponse {
    #[serde(rename = "cniVersion")]
    pub cni_version: String,
    pub code: u32,
    pub msg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}
