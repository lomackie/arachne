use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use ipnet::IpNet;
use super::error::CniError;

const DATA_DIR: &str = "/var/lib/cni/arachne";

pub struct Allocation {
    pub address: IpAddr,
    pub gateway: IpAddr,
    pub prefix_len: u8,
}

pub fn allocate(net: &IpNet, container_id: &str) -> Result<Allocation, CniError> {
    allocate_in(Path::new(DATA_DIR), net, container_id)
}

pub fn release(container_id: &str) -> Result<(), CniError> {
    release_in(Path::new(DATA_DIR), container_id)
}

fn allocate_in(root: &Path, net: &IpNet, container_id: &str) -> Result<Allocation, CniError> {
    let gateway = net.hosts().next()
        .ok_or_else(|| CniError::Ipam("subnet too small".into()))?;
    let prefix_len = net.prefix_len();

    let by_ip = root.join("by-ip");
    let by_container = root.join("by-container");
    std::fs::create_dir_all(&by_ip)?;
    std::fs::create_dir_all(&by_container)?;

    let container_path = by_container.join(container_id);
    if let Ok(existing) = std::fs::read_to_string(&container_path) {
        if let Ok(address) = existing.trim().parse() {
            return Ok(Allocation { address, gateway, prefix_len });
        }
    }

    for address in net.hosts().skip(1) {
        let ip_path = by_ip.join(address.to_string());
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&ip_path) {
            Ok(mut f) => {
                f.write_all(container_id.as_bytes())?;
                std::fs::write(&container_path, address.to_string())?;
                return Ok(Allocation { address, gateway, prefix_len });
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(CniError::Io(e)),
        }
    }

    Err(CniError::Ipam("subnet exhausted".into()))
}

fn release_in(root: &Path, container_id: &str) -> Result<(), CniError> {
    let container_path = root.join("by-container").join(container_id);
    let address = match std::fs::read_to_string(&container_path) {
        Ok(s) => s.trim().to_string(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(CniError::Io(e)),
    };

    remove_if_exists(&root.join("by-ip").join(&address))?;
    remove_if_exists(&container_path)?;
    Ok(())
}

fn remove_if_exists(path: &PathBuf) -> Result<(), CniError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(CniError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn reserves_gateway_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let net = IpNet::from_str("10.244.1.0/24").unwrap();

        let a = allocate_in(dir.path(), &net, "container-a").unwrap();
        assert_eq!(a.gateway.to_string(), "10.244.1.1");
        assert_eq!(a.address.to_string(), "10.244.1.2");
        assert_eq!(a.prefix_len, 24);

        let again = allocate_in(dir.path(), &net, "container-a").unwrap();
        assert_eq!(again.address, a.address);

        let b = allocate_in(dir.path(), &net, "container-b").unwrap();
        assert_eq!(b.address.to_string(), "10.244.1.3");
    }

    #[test]
    fn release_frees_address_for_reuse() {
        let dir = tempfile::tempdir().unwrap();
        let net = IpNet::from_str("10.244.1.0/24").unwrap();

        let a = allocate_in(dir.path(), &net, "container-a").unwrap();
        release_in(dir.path(), "container-a").unwrap();
        release_in(dir.path(), "container-a").unwrap();

        let b = allocate_in(dir.path(), &net, "container-b").unwrap();
        assert_eq!(b.address, a.address);
    }
}
