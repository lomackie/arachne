use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use aya::{
    EbpfLoader, include_bytes_aligned,
    maps::{HashMap, Map, MapData},
    programs::{links::FdLink, SchedClassifier, TcAttachType},
};
use anyhow::Result;
use nix::mount::MsFlags;

use arachne_common::{Endpoint, ENDPOINTS_MAP, endpoint_key};
use crate::cni::CniError;

static EBPF_BYTES: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/arachne-ebpf"));

const PIN_DIR: &str = "/sys/fs/bpf/arachne";

/// Mount bpffs at /sys/fs/bpf if it isn't already. Must be called by the
/// agent (which has Bidirectional mount propagation) before any pinning,
/// so the CNI plugin running on the host also sees the mount.
pub fn ensure_bpffs() -> Result<()> {
    let mounts = std::fs::read_to_string("/proc/mounts")?;
    let already_mounted = mounts.lines().any(|l| {
        let mut parts = l.split_whitespace();
        let _dev = parts.next();
        let mountpoint = parts.next();
        let fstype = parts.next();
        mountpoint == Some("/sys/fs/bpf") && fstype == Some("bpf")
    });
    if !already_mounted {
        nix::mount::mount(
            Some("bpffs"),
            "/sys/fs/bpf",
            Some("bpf"),
            MsFlags::empty(),
            None::<&str>,
        )?;
    }
    Ok(())
}

pub fn attach_pod(ifname: &str, container_id: &str) -> Result<(), CniError> {
    let suffix = &container_id[..container_id.len().min(8)];
    let pin = PathBuf::from(format!("{PIN_DIR}/tc-{suffix}"));
    attach(ifname, &pin, TcAttachType::Ingress)
        .map_err(|e| CniError::Netlink(e.to_string()))
}

pub fn attach_node(ifname: &str) -> Result<()> {
    let pin = PathBuf::from(format!("{PIN_DIR}/tc-{ifname}"));
    attach(ifname, &pin, TcAttachType::Ingress)
}

pub fn detach_pod(container_id: &str) -> Result<(), CniError> {
    let suffix = &container_id[..container_id.len().min(8)];
    let path = PathBuf::from(format!("{PIN_DIR}/tc-{suffix}"));
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

fn attach(ifname: &str, pin_path: &Path, direction: TcAttachType) -> Result<()> {
    std::fs::create_dir_all(PIN_DIR)?;
    if pin_path.exists() {
        std::fs::remove_file(pin_path)?;
    }

    let mut ebpf = EbpfLoader::new()
        .map_pin_path(PIN_DIR)
        .load(EBPF_BYTES)
        .map_err(|e| anyhow::anyhow!("load eBPF program: {e}"))?;

    let prog: &mut SchedClassifier = ebpf
        .program_mut("tc_forward")
        .ok_or_else(|| anyhow::anyhow!("tc_forward not found in ELF"))?
        .try_into()
        .map_err(|e| anyhow::anyhow!("expected SchedClassifier: {e}"))?;

    prog.load()
        .map_err(|e| anyhow::anyhow!("load tc_forward: {e}"))?;

    let link_id = prog
        .attach(ifname, direction)
        .map_err(|e| anyhow::anyhow!("attach TC to {ifname}: {e}"))?;

    let owned = prog
        .take_link(link_id)
        .map_err(|e| anyhow::anyhow!("take TC link: {e}"))?;

    FdLink::try_from(owned)
        .map_err(|e| anyhow::anyhow!("convert TC link to FdLink: {e}"))?
        .pin(pin_path)
        .map_err(|e| anyhow::anyhow!("pin TC link: {e}"))?;

    Ok(())
}

fn open_endpoints_map() -> Result<HashMap<MapData, u32, Endpoint>, CniError> {
    let path = format!("{PIN_DIR}/{ENDPOINTS_MAP}");
    let map_data = MapData::from_pin(&path)
        .map_err(|e| CniError::Netlink(format!("open ENDPOINTS map: {e}")))?;
    HashMap::try_from(Map::HashMap(map_data))
        .map_err(|e| CniError::Netlink(format!("open ENDPOINTS map: {e}")))
}

pub fn endpoints_insert(pod_ip: Ipv4Addr, ifindex: u32, mac: [u8; 6]) -> Result<(), CniError> {
    let mut map = open_endpoints_map()?;
    map.insert(endpoint_key(pod_ip), Endpoint { ifindex, mac }, 0)
        .map_err(|e| CniError::Netlink(format!("insert ENDPOINTS entry: {e}")))
}

pub fn endpoints_remove(pod_ip: Ipv4Addr) -> Result<(), CniError> {
    let mut map = open_endpoints_map()?;
    map.remove(&endpoint_key(pod_ip))
        .map_err(|e| CniError::Netlink(format!("remove ENDPOINTS entry: {e}")))
}

#[cfg(test)]
mod tests {
    use super::EBPF_BYTES;
    use aya::{Ebpf, programs::SchedClassifier};

    fn is_perm_denied(e: &(dyn std::error::Error + 'static)) -> bool {
        let mut src: Option<&(dyn std::error::Error + 'static)> = Some(e);
        loop {
            match src {
                None => return false,
                Some(s) => {
                    if let Some(io) = s.downcast_ref::<std::io::Error>() {
                        return io.kind() == std::io::ErrorKind::PermissionDenied;
                    }
                    src = s.source();
                }
            }
        }
    }

    fn try_load() -> Option<Ebpf> {
        match Ebpf::load(EBPF_BYTES) {
            Ok(ebpf) => Some(ebpf),
            Err(e) => {
                if is_perm_denied(&e) {
                    eprintln!("skipping: CAP_BPF not available");
                    return None;
                }
                panic!("aya failed to parse embedded eBPF ELF: {e}");
            }
        }
    }

    #[test]
    fn ebpf_bytes_parse() {
        try_load();
    }

    #[test]
    fn ebpf_verifier_accepts() {
        let Some(mut ebpf) = try_load() else { return };
        let prog: &mut SchedClassifier = ebpf
            .program_mut("tc_forward")
            .expect("tc_forward not found")
            .try_into()
            .expect("expected SchedClassifier");
        if let Err(e) = prog.load() {
            if is_perm_denied(&e) {
                eprintln!("skipping: CAP_BPF not available");
                return;
            }
            panic!("kernel verifier rejected tc_forward: {e}");
        }
    }
}
