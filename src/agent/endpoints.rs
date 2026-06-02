use std::collections::HashSet;

/// Reconcile the pinned ENDPOINTS map against the IPAM store and the node's live
/// interfaces, dropping entries left behind by pods whose CNI DEL never ran
/// (e.g. a crashed pod). Logs what it reclaimed; a failure to read either side
/// is logged and skipped rather than aborting agent startup.
pub fn reconcile() {
    let allocated = match crate::cni::ipam::allocated_ips() {
        Ok(ips) => ips,
        Err(e) => {
            eprintln!("endpoints gc: read IPAM store failed: {e}");
            return;
        }
    };
    let live = match live_ifindexes() {
        Ok(idxs) => idxs,
        Err(e) => {
            eprintln!("endpoints gc: list interfaces failed: {e}");
            return;
        }
    };
    match crate::bpf::endpoints_gc(&allocated, &live) {
        Ok(stats) if stats.removed > 0 => {
            eprintln!("endpoints gc: scanned={} removed={}", stats.scanned, stats.removed);
        }
        Ok(_) => {}
        Err(e) => eprintln!("endpoints gc: failed: {e}"),
    }
}

/// Indices of every interface currently present in the agent's network
/// namespace. The agent runs with `hostNetwork: true`, so this includes the
/// host-side veths the CNI plugin records in ENDPOINTS.
fn live_ifindexes() -> std::io::Result<HashSet<u32>> {
    let mut idxs = HashSet::new();
    for entry in std::fs::read_dir("/sys/class/net")? {
        let entry = entry?;
        let idx_path = entry.path().join("ifindex");
        if let Ok(contents) = std::fs::read_to_string(&idx_path) {
            if let Ok(idx) = contents.trim().parse::<u32>() {
                idxs.insert(idx);
            }
        }
    }
    Ok(idxs)
}
