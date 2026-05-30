mod cni;

use ipnet::IpNet;
use cni::{CniError, CniErrorResponse, CniParams, Command, Interface, IpConfig, NetworkConfig, CniResult, Route};

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
            let container_id = params.container_id
                .ok_or_else(|| CniError::InvalidEnv("missing CNI_CONTAINERID".into()))?;
            let ifname = params.ifname
                .ok_or_else(|| CniError::InvalidEnv("missing CNI_IFNAME".into()))?;
            let netns = params.netns
                .ok_or_else(|| CniError::InvalidEnv("missing CNI_NETNS".into()))?;
            let subnet = config.subnet
                .ok_or_else(|| CniError::InvalidEnv("missing subnet in config".into()))?;

            let net: IpNet = subnet.parse()
                .map_err(|_| CniError::Ipam(format!("invalid subnet: {subnet}")))?;
            let gateway = net.hosts().next()
                .ok_or_else(|| CniError::Ipam("subnet too small".into()))?;

            let ip = cni::ipam::allocate(&subnet, &container_id)?;

            let result = CniResult {
                cni_version: CNI_VERSION.to_string(),
                interfaces: vec![
                    Interface { name: ifname, mac: String::new(), sandbox: netns },
                ],
                ips: vec![
                    IpConfig {
                        address: format!("{}/{}", ip, net.prefix_len()),
                        gateway,
                        interface: 0,
                    },
                ],
                routes: vec![
                    Route { dst: "0.0.0.0/0".to_string(), gw: gateway },
                ],
            };

            println!("{}", serde_json::to_string(&result)?);
            Ok(())
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
