use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use ipnet::IpNet;
use super::error::CniError;

const DATA_DIR: &str = "/var/lib/cni/arachne";

pub fn allocate(subnet: &str, container_id: &str) -> Result<IpAddr, CniError> {
    let net: IpNet = subnet.parse()
        .map_err(|_| CniError::Ipam(format!("invalid subnet: {subnet}")))?;

    std::fs::create_dir_all(DATA_DIR)?;

    for addr in net.hosts().skip(1) {
        let path = PathBuf::from(DATA_DIR).join(addr.to_string());
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut f) => {
                f.write_all(container_id.as_bytes())?;
                return Ok(addr);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(CniError::Io(e)),
        }
    }

    Err(CniError::Ipam("subnet exhausted".into()))
}

pub fn release(ip: IpAddr) -> Result<(), CniError> {
    let path = PathBuf::from(DATA_DIR).join(ip.to_string());
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(CniError::Io(e)),
    }
}
