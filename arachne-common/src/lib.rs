#![no_std]

use core::net::Ipv4Addr;

pub const ENDPOINTS_MAP: &str = "ENDPOINTS";
pub const SERVICES_MAP: &str = "SERVICES";
pub const BACKENDS_MAP: &str = "BACKENDS";
pub const CONNTRACK_MAP: &str = "CONNTRACK";

pub const MAX_ENDPOINTS: u32 = 1 << 16;
pub const MAX_SERVICES: u32 = 4096;
pub const MAX_BACKENDS: u32 = 1 << 16;
pub const MAX_CT_ENTRIES: u32 = 1 << 16;

pub const COUNTER_MAP_HIT: u32 = 0;
pub const COUNTER_FIB_MISS: u32 = 1;
pub const COUNTER_REDIRECT: u32 = 2;
pub const COUNTER_SERVICE_PUNT: u32 = 3;
pub const COUNTER_SERVICE_DNAT: u32 = 4;
pub const COUNTER_SERVICE_SNAT: u32 = 5;
pub const COUNTER_CT_EVICT: u32 = 6;
pub const COUNTER_MAX: u32 = 7;

// Per-flow TCP state bits, stored in `NatVal.state` and maintained by the
// datapath. UDP flows leave these unset (the GC always treats UDP as short).
//
// EST     — traffic seen in both directions (the backend replied). Promoted on
//           both halves so the GC can grant the long idle timeout from either.
// FIN_FWD — a FIN crossed client→backend.
// FIN_REV — a FIN crossed backend→client.
//
// The two FIN bits track the close handshake. Each side, on sending its FIN,
// records it on the *partner* entry (so the other direction reads it locally
// with no extra lookup). When the second FIN arrives, both bits are consolidated
// onto whichever entry the final ACK will traverse, so that ACK — a non-FIN
// packet seeing both bits — evicts the flow with a purely local read. The GC
// also treats either FIN bit as "closing" and applies the short timeout.
pub const CT_EST: u8 = 0x01;
pub const CT_FIN_FWD: u8 = 0x02;
pub const CT_FIN_REV: u8 = 0x04;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Endpoint {
    pub ifindex: u32,
    pub mac: [u8; 6],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Endpoint {}

/// Key for the service map: the ClusterIP + service port + IP protocol.
/// Ports are stored in the same byte order as `ctx.load::<u16>` returns on
/// a little-endian host (i.e. network-byte-order bytes interpreted as LE u16).
/// Use `port_key(port)` to convert a host-order port to this representation.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ServiceKey {
    pub vip: u32,
    pub port: u16,
    pub proto: u8,
    pub _pad: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ServiceKey {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ServiceVal {
    pub service_id: u32,
    pub backend_count: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ServiceVal {}

/// Key for the backend map: (service_id, service port + proto, slot index).
/// The port/proto are part of the key because a single service can expose
/// several ports under one `service_id` (e.g. kube-dns: 53/UDP, 53/TCP,
/// 9153/TCP). Without them every port would reuse the same `(service_id, index)`
/// slots and the last port reconciled would clobber the others' backends.
/// `port` is in the `port_key()` representation, matching `ServiceKey.port`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BackendKey {
    pub service_id: u32,
    pub index: u32,
    pub port: u16,
    pub proto: u8,
    pub _pad: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BackendKey {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BackendVal {
    pub pod_ip: u32,
    pub pod_port: u16,
    pub _pad: [u8; 2],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BackendVal {}

/// 5-tuple key for the conntrack map (CONNTRACK). Both directions of a flow are
/// stored under their own key: the forward (client→svc) and reverse
/// (backend→client) tuples are distinct, so they never collide in the one map.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NatKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub _pad: [u8; 3],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NatKey {}

/// Rewritten address+port plus a link to the flow's other half. On the forward
/// entry `ip`/`port` are the DNAT new-dst (the backend); on the reverse entry
/// they are the SNAT new-src (the VIP). `partner` is the other direction's
/// `NatKey`, written at insert time, so eviction and GC delete both halves with
/// a direct read instead of reconstructing the partner tuple from this value.
/// `last_seen` is `bpf_ktime_get_ns()` (CLOCK_MONOTONIC ns) at the most recent
/// packet on the flow, refreshed by the datapath and read by the userspace GC.
/// `state` is a bitset of the `CT_*` flags tracking the flow's TCP lifecycle,
/// which the GC uses to pick a state-aware idle timeout.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NatVal {
    pub ip: u32,
    pub port: u16,
    pub state: u8,
    pub _pad: u8,
    pub last_seen: u64,
    pub partner: NatKey,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NatVal {}

pub const fn endpoint_key(ip: Ipv4Addr) -> u32 {
    u32::from_le_bytes(ip.octets())
}

/// Convert a host-order port to the map-key representation that matches what
/// `ctx.load::<u16>` returns when reading that port from a packet on a
/// little-endian host (i.e. swap the bytes).
pub const fn port_key(port: u16) -> u16 {
    port.swap_bytes()
}

// ClusterIP service range (kube `--service-cluster-ip-range`, 10.96.0.0/12).
const SERVICE_CIDR_BASE: u32 = u32::from_le_bytes([10, 96, 0, 0]);
const SERVICE_CIDR_MASK: u32 = u32::from_le_bytes([255, 240, 0, 0]);

pub const fn is_service_ip(dst: u32) -> bool {
    dst & SERVICE_CIDR_MASK == SERVICE_CIDR_BASE & SERVICE_CIDR_MASK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_layout_is_stable() {
        assert_eq!(core::mem::size_of::<Endpoint>(), 12);
        assert_eq!(core::mem::align_of::<Endpoint>(), 4);
    }

    #[test]
    fn service_key_layout() {
        assert_eq!(core::mem::size_of::<ServiceKey>(), 8);
        assert_eq!(core::mem::size_of::<ServiceVal>(), 8);
        assert_eq!(core::mem::size_of::<BackendKey>(), 12);
        assert_eq!(core::mem::size_of::<BackendVal>(), 8);
        assert_eq!(core::mem::size_of::<NatKey>(), 16);
        assert_eq!(core::mem::size_of::<NatVal>(), 32);
    }

    #[test]
    fn key_matches_network_order_load() {
        let ip = Ipv4Addr::new(10, 244, 1, 5);
        assert_eq!(endpoint_key(ip), u32::from_le_bytes([10, 244, 1, 5]));
    }

    #[test]
    fn port_key_matches_packet_load() {
        // Port 80 in a packet is bytes [0x00, 0x50]; loaded as LE u16 on x86 = 0x5000.
        assert_eq!(port_key(80), 0x5000u16);
        assert_eq!(port_key(53), 53u16.swap_bytes());
    }

    #[test]
    fn service_ips_are_detected() {
        assert!(is_service_ip(endpoint_key(Ipv4Addr::new(10, 96, 0, 1))));
        assert!(is_service_ip(endpoint_key(Ipv4Addr::new(10, 96, 0, 10))));
        assert!(is_service_ip(endpoint_key(Ipv4Addr::new(10, 111, 255, 255))));
        assert!(!is_service_ip(endpoint_key(Ipv4Addr::new(10, 244, 1, 5))));
        assert!(!is_service_ip(endpoint_key(Ipv4Addr::new(10, 95, 255, 255))));
        assert!(!is_service_ip(endpoint_key(Ipv4Addr::new(10, 112, 0, 0))));
    }
}
