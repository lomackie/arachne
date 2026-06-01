#![no_std]
#![no_main]

use core::ffi::c_long;

use arachne_common::{
    BackendKey, BackendVal, COUNTER_FIB_MISS, COUNTER_MAP_HIT, COUNTER_MAX, COUNTER_REDIRECT,
    COUNTER_SERVICE_DNAT, COUNTER_SERVICE_PUNT, COUNTER_SERVICE_SNAT, Endpoint, MAX_BACKENDS,
    MAX_CT_ENTRIES, MAX_ENDPOINTS, MAX_SERVICES, NatKey, NatVal, ServiceKey, ServiceVal,
    is_service_ip,
};
use aya_ebpf::{
    EbpfContext,
    bindings::{TC_ACT_OK, __sk_buff, bpf_fib_lookup as BpfFibLookup},
    helpers::{bpf_fib_lookup, bpf_get_prandom_u32, bpf_redirect},
    macros::{classifier, map},
    maps::{HashMap, LruHashMap, PerCpuArray},
    programs::TcContext,
};

#[map]
static ENDPOINTS: HashMap<u32, Endpoint> = HashMap::pinned(MAX_ENDPOINTS, 0);

#[map]
static SERVICES: HashMap<ServiceKey, ServiceVal> = HashMap::pinned(MAX_SERVICES, 0);

#[map]
static BACKENDS: HashMap<BackendKey, BackendVal> = HashMap::pinned(MAX_BACKENDS, 0);

// Conntrack maps: shared across all TC programs on a node via bpffs pinning.
// CT_DNAT caches the forward-flow backend choice (client→svc → client→backend).
// CT_SNAT caches the reverse SNAT mapping (backend→client → svc→client).
#[map]
static CT_DNAT: LruHashMap<NatKey, NatVal> = LruHashMap::pinned(MAX_CT_ENTRIES, 0);

#[map]
static CT_SNAT: LruHashMap<NatKey, NatVal> = LruHashMap::pinned(MAX_CT_ENTRIES, 0);

#[map]
static COUNTERS: PerCpuArray<u64> = PerCpuArray::pinned(COUNTER_MAX, 0);

const ETH_HLEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const AF_INET: u8 = 2;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

// For l4_csum_replace: indicates the changed field is in the pseudo-header.
const BPF_F_PSEUDO_HDR: u64 = 0x10;

#[inline(always)]
fn bump(index: u32) {
    if let Some(ptr) = COUNTERS.get_ptr_mut(index) {
        unsafe { *ptr += 1 };
    }
}

#[classifier]
pub fn tc_forward(mut ctx: TcContext) -> i32 {
    try_forward(&mut ctx).unwrap_or(TC_ACT_OK as i32)
}

fn try_forward(ctx: &mut TcContext) -> Result<i32, c_long> {
    if u16::from_be(ctx.load::<u16>(12)?) != ETH_P_IP {
        return Ok(TC_ACT_OK as i32);
    }

    let ip_src: u32 = ctx.load(ETH_HLEN + 12)?;
    let ip_proto: u8 = ctx.load(ETH_HLEN + 9)?;
    let ihl = ((ctx.load::<u8>(ETH_HLEN)? & 0x0f) as usize) * 4;
    if ihl < 20 {
        return Ok(TC_ACT_OK as i32);
    }
    let mut ip_dst: u32 = ctx.load(ETH_HLEN + 16)?;

    if ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP {
        let src_port: u16 = ctx.load(ETH_HLEN + ihl)?;
        let dst_port: u16 = ctx.load(ETH_HLEN + ihl + 2)?;
        // TCP checksum at offset 16 from transport header; UDP at offset 6.
        let l4_csum_off = if ip_proto == IPPROTO_TCP {
            ETH_HLEN + ihl + 16
        } else {
            ETH_HLEN + ihl + 6
        };

        // Check CT_SNAT: return packet from a backend we previously DNAT'd to.
        let snat_key = NatKey {
            src_ip: ip_src,
            dst_ip: ip_dst,
            src_port,
            dst_port,
            proto: ip_proto,
            _pad: [0; 3],
        };
        if let Some(snat) = unsafe { CT_SNAT.get(&snat_key) } {
            // Copy values immediately before any further map operations.
            let new_ip = unsafe { (*snat).ip };
            let new_port = unsafe { (*snat).port };

            // SNAT: rewrite src IP and src port, update checksums.
            ctx.store(ETH_HLEN + 12, &new_ip, 0)?;
            ctx.l3_csum_replace(ETH_HLEN + 10, ip_src as u64, new_ip as u64, 4)?;
            ctx.l4_csum_replace(l4_csum_off, ip_src as u64, new_ip as u64, BPF_F_PSEUDO_HDR | 4)?;
            ctx.store(ETH_HLEN + ihl, &new_port, 0)?;
            ctx.l4_csum_replace(l4_csum_off, src_port as u64, new_port as u64, 2)?;

            bump(COUNTER_SERVICE_SNAT);
            // ip_dst is the original destination (client pod); forward normally.
        } else if is_service_ip(ip_dst) {
            // Service DNAT: check if we have a cached backend for this flow.
            let dnat_key = NatKey {
                src_ip: ip_src,
                dst_ip: ip_dst,
                src_port,
                dst_port,
                proto: ip_proto,
                _pad: [0; 3],
            };

            let (new_dst_ip, new_dst_port) =
                if let Some(cached) = unsafe { CT_DNAT.get(&dnat_key) } {
                    (unsafe { (*cached).ip }, unsafe { (*cached).port })
                } else {
                    // First packet of this flow: look up service and pick a backend.
                    let svc_key = ServiceKey { vip: ip_dst, port: dst_port, proto: ip_proto, _pad: 0 };
                    let Some(svc) = (unsafe { SERVICES.get(&svc_key) }) else {
                        bump(COUNTER_SERVICE_PUNT);
                        return Ok(TC_ACT_OK as i32);
                    };
                    // Copy before next map op to avoid pointer invalidation.
                    let count = unsafe { (*svc).backend_count };
                    let svc_id = unsafe { (*svc).service_id };

                    if count == 0 {
                        bump(COUNTER_SERVICE_PUNT);
                        return Ok(TC_ACT_OK as i32);
                    }

                    let idx = unsafe { bpf_get_prandom_u32() } % count;
                    let bk_key = BackendKey { service_id: svc_id, index: idx };
                    let Some(bk) = (unsafe { BACKENDS.get(&bk_key) }) else {
                        bump(COUNTER_SERVICE_PUNT);
                        return Ok(TC_ACT_OK as i32);
                    };
                    let pod_ip = unsafe { (*bk).pod_ip };
                    let pod_port = unsafe { (*bk).pod_port };

                    // Cache the forward DNAT decision for subsequent packets.
                    let _ = CT_DNAT.insert(
                        &dnat_key,
                        &NatVal { ip: pod_ip, port: pod_port, _pad: [0; 2] },
                        0,
                    );
                    // Cache the reverse SNAT for return packets from the backend.
                    let snat_rev = NatKey {
                        src_ip: pod_ip,
                        dst_ip: ip_src,
                        src_port: pod_port,
                        dst_port: src_port,
                        proto: ip_proto,
                        _pad: [0; 3],
                    };
                    let _ = CT_SNAT.insert(
                        &snat_rev,
                        &NatVal { ip: ip_dst, port: dst_port, _pad: [0; 2] },
                        0,
                    );

                    (pod_ip, pod_port)
                };

            // DNAT: rewrite dst IP and dst port, update checksums.
            ctx.store(ETH_HLEN + 16, &new_dst_ip, 0)?;
            ctx.l3_csum_replace(ETH_HLEN + 10, ip_dst as u64, new_dst_ip as u64, 4)?;
            ctx.l4_csum_replace(l4_csum_off, ip_dst as u64, new_dst_ip as u64, BPF_F_PSEUDO_HDR | 4)?;
            ctx.store(ETH_HLEN + ihl + 2, &new_dst_port, 0)?;
            ctx.l4_csum_replace(l4_csum_off, dst_port as u64, new_dst_port as u64, 2)?;

            bump(COUNTER_SERVICE_DNAT);
            ip_dst = new_dst_ip;
        }
    } else if is_service_ip(ip_dst) {
        // Non-TCP/UDP to a ClusterIP (e.g. ICMP): punt to kernel.
        bump(COUNTER_SERVICE_PUNT);
        return Ok(TC_ACT_OK as i32);
    }

    // L2/L3 forwarding: check the endpoint map first, then FIB.
    if let Some(endpoint) = unsafe { ENDPOINTS.get(&ip_dst) } {
        let endpoint = unsafe { &*endpoint };
        ctx.store(0, &endpoint.mac, 0)?;
        bump(COUNTER_MAP_HIT);
        return Ok(unsafe { bpf_redirect(endpoint.ifindex, 0) } as i32);
    }

    let mut fib: BpfFibLookup = unsafe { core::mem::zeroed() };
    fib.family = AF_INET;
    // Re-read src in case it was rewritten by SNAT above.
    fib.__bindgen_anon_3.ipv4_src = ctx.load(ETH_HLEN + 12)?;
    fib.__bindgen_anon_4.ipv4_dst = ip_dst;
    fib.ifindex = unsafe { (*(ctx.as_ptr() as *mut __sk_buff)).ingress_ifindex };

    let rc = unsafe {
        bpf_fib_lookup(
            ctx.as_ptr() as *mut core::ffi::c_void,
            &mut fib as *mut BpfFibLookup,
            core::mem::size_of::<BpfFibLookup>() as i32,
            0u32,
        )
    };

    if rc != 0 {
        bump(COUNTER_FIB_MISS);
        return Ok(TC_ACT_OK as i32);
    }

    ctx.store(0, &fib.dmac, 0)?;
    ctx.store(6, &fib.smac, 0)?;

    bump(COUNTER_REDIRECT);
    Ok(unsafe { bpf_redirect(fib.ifindex, 0) } as i32)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
