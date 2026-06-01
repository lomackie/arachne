use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use aya::{
    EbpfLoader, include_bytes_aligned,
    maps::{HashMap, Map, MapData, PerCpuArray, PerCpuValues},
    programs::{links::FdLink, SchedClassifier, TcAttachType},
};
use anyhow::Result;
use nix::mount::MsFlags;

use arachne_common::{
    BackendKey, BackendVal, COUNTER_FIB_MISS, COUNTER_MAP_HIT, COUNTER_REDIRECT,
    COUNTER_SERVICE_DNAT, COUNTER_SERVICE_PUNT, COUNTER_SERVICE_SNAT, Endpoint,
    BACKENDS_MAP, ENDPOINTS_MAP, SERVICES_MAP, ServiceKey, ServiceVal, endpoint_key,
};
use crate::cni::CniError;

static EBPF_BYTES: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/arachne-ebpf"));

const PIN_DIR: &str = "/sys/fs/bpf/arachne";

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

fn open_services_map() -> Result<HashMap<MapData, ServiceKey, ServiceVal>> {
    let path = format!("{PIN_DIR}/{SERVICES_MAP}");
    let map_data = MapData::from_pin(&path)
        .map_err(|e| anyhow::anyhow!("open SERVICES map: {e}"))?;
    HashMap::try_from(Map::HashMap(map_data))
        .map_err(|e| anyhow::anyhow!("open SERVICES map: {e}"))
}

fn open_backends_map() -> Result<HashMap<MapData, BackendKey, BackendVal>> {
    let path = format!("{PIN_DIR}/{BACKENDS_MAP}");
    let map_data = MapData::from_pin(&path)
        .map_err(|e| anyhow::anyhow!("open BACKENDS map: {e}"))?;
    HashMap::try_from(Map::HashMap(map_data))
        .map_err(|e| anyhow::anyhow!("open BACKENDS map: {e}"))
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

pub fn services_upsert(key: ServiceKey, val: ServiceVal) -> Result<()> {
    let mut map = open_services_map()?;
    map.insert(key, val, 0)
        .map_err(|e| anyhow::anyhow!("insert SERVICES entry: {e}"))
}

pub fn services_remove(key: ServiceKey) -> Result<()> {
    let mut map = open_services_map()?;
    // Ignore NotFound: the entry may have been removed already.
    match map.remove(&key) {
        Ok(()) => Ok(()),
        Err(e) if e.to_string().contains("No such file") => Ok(()),
        Err(e) => Err(anyhow::anyhow!("remove SERVICES entry: {e}")),
    }
}

pub fn backends_upsert(key: BackendKey, val: BackendVal) -> Result<()> {
    let mut map = open_backends_map()?;
    map.insert(key, val, 0)
        .map_err(|e| anyhow::anyhow!("insert BACKENDS entry: {e}"))
}

pub struct Counters {
    pub map_hit: u64,
    pub fib_miss: u64,
    pub redirect: u64,
    pub service_punt: u64,
    pub service_dnat: u64,
    pub service_snat: u64,
}

pub fn read_counters() -> Result<Counters> {
    let path = format!("{PIN_DIR}/COUNTERS");
    let map_data = MapData::from_pin(&path)?;
    let map: PerCpuArray<_, u64> = PerCpuArray::try_from(Map::PerCpuArray(map_data))?;

    let sum = |vals: PerCpuValues<u64>| vals.iter().sum::<u64>();

    Ok(Counters {
        map_hit: sum(map.get(&COUNTER_MAP_HIT, 0)?),
        fib_miss: sum(map.get(&COUNTER_FIB_MISS, 0)?),
        redirect: sum(map.get(&COUNTER_REDIRECT, 0)?),
        service_punt: sum(map.get(&COUNTER_SERVICE_PUNT, 0)?),
        service_dnat: sum(map.get(&COUNTER_SERVICE_DNAT, 0)?),
        service_snat: sum(map.get(&COUNTER_SERVICE_SNAT, 0)?),
    })
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
