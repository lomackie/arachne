mod cni;

use cni::{CniError, CniErrorResponse, CniParams, Command, NetworkConfig};

const CNI_VERSION: &str = "1.1.0";
const SUPPORTED_VERSIONS: &[&str] = &["0.4.0", "1.0.0", "1.1.0"];

fn run() -> Result<(), CniError> {
    let params = CniParams::from_env()?;

    if params.command == Command::Version {
        let resp = serde_json::json!({
            "cniVersion": CNI_VERSION,
            "supportedVersions": SUPPORTED_VERSIONS,
        });
        println!("{resp}");
        return Ok(());
    }

    let config = NetworkConfig::from_stdin()?;

    match params.command {
        Command::Add => {
            todo!("ADD: set up pod networking")
        }
        Command::Del => {
            todo!("DEL: tear down pod networking")
        }
        Command::Check => {
            todo!("CHECK: verify pod networking is as expected")
        }
        Command::Gc => {
            todo!("GC: clean up stale attachments")
        }
        Command::Status => {
            todo!("STATUS: report plugin readiness")
        }
        Command::Version => unreachable!(),
    }
}

fn main() {
    if let Err(e) = run() {
        let resp = CniErrorResponse {
            cni_version: CNI_VERSION.to_string(),
            code: e.code(),
            msg: e.to_string(),
            details: None,
        };
        println!("{}", serde_json::to_string(&resp).unwrap());
        std::process::exit(1);
    }
}
