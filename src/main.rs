use arachne::{bpf, cni};

use ipnet::IpNet;
use cni::{CniError, CniErrorResponse, CniParams, Command, Interface, IpConfig, NetworkConfig, CniResult, Route};

const CNI_VERSION: &str = "1.1.0";

fn run() -> Result<(), CniError> {
    let params = CniParams::from_env()?;

    if params.command == Command::Version {
        let resp = serde_json::json!({
            "cniVersion": CNI_VERSION,
            "supportedVersions": [CNI_VERSION],
        });
        println!("{resp}");
        return Ok(());
    }

    let config = NetworkConfig::from_stdin()?;
    if config.cni_version != CNI_VERSION {
        return Err(CniError::UnsupportedVersion(config.cni_version));
    }

    match params.command {
        Command::Add => cmd_add(&params, &config),
        Command::Del => cmd_del(&params),
        Command::Check => todo!("CHECK: verify pod networking is as expected"),
        Command::Gc => todo!("GC: clean up stale attachments"),
        Command::Status => Ok(()),
        Command::Version => unreachable!(),
    }
}

fn cmd_add(params: &CniParams, config: &NetworkConfig) -> Result<(), CniError> {
    let container_id = params.container_id.as_deref()
        .ok_or_else(|| CniError::InvalidEnv("missing CNI_CONTAINERID".into()))?;
    let ifname = params.ifname.clone()
        .ok_or_else(|| CniError::InvalidEnv("missing CNI_IFNAME".into()))?;
    let netns = params.netns.clone()
        .ok_or_else(|| CniError::InvalidEnv("missing CNI_NETNS".into()))?;
    let subnet = config.subnet.as_deref()
        .ok_or_else(|| CniError::InvalidEnv("missing subnet in config".into()))?;

    let net: IpNet = subnet.parse()
        .map_err(|_| CniError::Ipam(format!("invalid subnet: {subnet}")))?;

    let alloc = cni::ipam::allocate(&net, container_id)?;

    cni::veth::setup(container_id, &ifname, &netns, alloc.address, alloc.prefix_len, alloc.gateway)?;
    bpf::attach_pod(&cni::veth::host_veth_name(container_id), container_id)?;

    let result = CniResult {
        cni_version: CNI_VERSION.to_string(),
        interfaces: vec![
            Interface { name: ifname, mac: String::new(), sandbox: netns },
        ],
        ips: vec![
            IpConfig {
                address: format!("{}/{}", alloc.address, alloc.prefix_len),
                gateway: alloc.gateway,
                interface: 0,
            },
        ],
        routes: vec![
            Route { dst: "0.0.0.0/0".to_string(), gw: alloc.gateway },
        ],
    };

    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

fn cmd_del(params: &CniParams) -> Result<(), CniError> {
    let container_id = params.container_id.as_deref()
        .ok_or_else(|| CniError::InvalidEnv("missing CNI_CONTAINERID".into()))?;
    cni::veth::teardown(container_id)?;
    bpf::detach_pod(container_id)?;
    cni::ipam::release(container_id)
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
