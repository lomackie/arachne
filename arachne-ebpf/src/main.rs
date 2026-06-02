#![no_std]
#![no_main]

use core::ffi::c_long;

use arachne_common::{
    BackendKey, BackendVal, CT_EST, CT_FIN_FWD, CT_FIN_REV, COUNTER_CT_EVICT, COUNTER_FIB_MISS,
    COUNTER_MAP_HIT, COUNTER_MAX, COUNTER_REDIRECT, COUNTER_SERVICE_DNAT, COUNTER_SERVICE_PUNT,
    COUNTER_SERVICE_SNAT, Endpoint, MAX_BACKENDS, MAX_CT_ENTRIES, MAX_ENDPOINTS, MAX_SERVICES,
    NatKey, NatVal, ServiceKey, ServiceVal, is_service_ip,
};
use aya_ebpf::{
    EbpfContext,
    bindings::{TC_ACT_OK, __sk_buff, bpf_fib_lookup as BpfFibLookup},
    helpers::{bpf_fib_lookup, bpf_get_prandom_u32, bpf_ktime_get_ns, bpf_redirect},
    macros::{classifier, map},
    maps::{HashMap, PerCpuArray},
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
// Plain HashMaps (not LRU): entries are reclaimed deterministically — on RST in
// the datapath, and by the userspace idle-timeout GC sweep — never by silently
// evicting a live flow. A full table punts new flows to the kernel (see below).
#[map]
static CT_DNAT: HashMap<NatKey, NatVal> = HashMap::pinned(MAX_CT_ENTRIES, 0);

#[map]
static CT_SNAT: HashMap<NatKey, NatVal> = HashMap::pinned(MAX_CT_ENTRIES, 0);

#[map]
static COUNTERS: PerCpuArray<u64> = PerCpuArray::pinned(COUNTER_MAX, 0);

const ETH_HLEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const AF_INET: u8 = 2;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

// TCP flags byte sits at offset 13 within the TCP header; FIN is bit 0, RST bit 2.
const TCP_FLAGS_OFF: usize = 13;
const TCP_FIN: u8 = 0x01;
const TCP_RST: u8 = 0x04;

// Only rewrite a conntrack entry's last_seen if it's older than this, to avoid a
// map write on every packet of a busy flow. The GC idle timeout is far larger.
const CT_REFRESH_NS: u64 = 1_000_000_000; // 1s

// For l4_csum_replace: indicates the changed field is in the pseudo-header.
const BPF_F_PSEUDO_HDR: u64 = 0x10;
// For l4_csum_replace on UDP: the checksum field is optional. A 0 means "no
// checksum" and must be left untouched (not patched into a bogus value); a
// recomputed 0 must be written as 0xffff. TCP must never set this.
const BPF_F_MARK_MANGLED_0: u64 = 0x20;

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
        // UDP checksums are optional: l4_csum_replace must special-case 0 so a
        // checksumless datagram isn't corrupted into a bogus value (TCP never).
        let l4_mangle = if ip_proto == IPPROTO_UDP {
            BPF_F_MARK_MANGLED_0
        } else {
            0
        };
        // RST tears the flow down; UDP has no flags, so treat it as 0.
        let tcp_flags: u8 = if ip_proto == IPPROTO_TCP {
            ctx.load(ETH_HLEN + ihl + TCP_FLAGS_OFF)?
        } else {
            0
        };
        let is_rst = tcp_flags & TCP_RST != 0;
        let is_fin = ip_proto == IPPROTO_TCP && tcp_flags & TCP_FIN != 0;
        let now = unsafe { bpf_ktime_get_ns() };

        // Check CT_SNAT: return packet from a backend we previously DNAT'd to.
        let snat_key = NatKey {
            src_ip: ip_src,
            dst_ip: ip_dst,
            src_port,
            dst_port,
            proto: ip_proto,
            _pad: [0; 3],
        };
        if let Some(snat) = unsafe { CT_SNAT.get_ptr_mut(&snat_key) } {
            // Copy values immediately before any further map operations.
            let new_ip = unsafe { (*snat).ip };
            let new_port = unsafe { (*snat).port };
            let last_seen = unsafe { (*snat).last_seen };
            let snat_state = unsafe { (*snat).state };
            if !is_rst && now.wrapping_sub(last_seen) > CT_REFRESH_NS {
                unsafe { (*snat).last_seen = now };
            }

            // SNAT: rewrite src IP and src port, update checksums.
            ctx.store(ETH_HLEN + 12, &new_ip, 0)?;
            ctx.l3_csum_replace(ETH_HLEN + 10, ip_src as u64, new_ip as u64, 4)?;
            ctx.l4_csum_replace(
                l4_csum_off,
                ip_src as u64,
                new_ip as u64,
                BPF_F_PSEUDO_HDR | l4_mangle | 4,
            )?;
            ctx.store(ETH_HLEN + ihl, &new_port, 0)?;
            ctx.l4_csum_replace(l4_csum_off, src_port as u64, new_port as u64, l4_mangle | 2)?;

            bump(COUNTER_SERVICE_SNAT);

            // The forward (CT_DNAT) key mirrors this reverse flow: the client is
            // this packet's dst, the VIP is the value we just read.
            let dnat_key = NatKey {
                src_ip: ip_dst,
                dst_ip: new_ip,
                src_port: dst_port,
                dst_port: new_port,
                proto: ip_proto,
                _pad: [0; 3],
            };
            if is_rst {
                // Tear down both halves immediately on an abort.
                let _ = CT_SNAT.remove(&snat_key);
                let _ = CT_DNAT.remove(&dnat_key);
                bump(COUNTER_CT_EVICT);
            } else if ip_proto == IPPROTO_TCP && is_fin {
                // Backend's FIN (reverse direction). Record it on the *forward*
                // entry, where the client's path will read it. If the client has
                // already FIN'd (its bit is on our own entry), both sides are now
                // closed: consolidate both bits onto the forward entry, which is
                // the one the final ACK will traverse — so that ACK evicts locally.
                if let Some(dp) = unsafe { CT_DNAT.get_ptr_mut(&dnat_key) } {
                    if snat_state & CT_FIN_FWD != 0 {
                        unsafe { (*dp).state |= CT_FIN_FWD | CT_FIN_REV };
                    } else {
                        unsafe { (*dp).state |= CT_FIN_REV };
                    }
                }
            } else if ip_proto == IPPROTO_TCP
                && snat_state & CT_FIN_FWD != 0
                && snat_state & CT_FIN_REV != 0
            {
                // Non-FIN packet and both bits are set on our own entry: this is
                // the final ACK of a backend-closed-first teardown. Evict both.
                let _ = CT_DNAT.remove(&dnat_key);
                let _ = CT_SNAT.remove(&snat_key);
                bump(COUNTER_CT_EVICT);
            } else if snat_state & CT_EST == 0 {
                // First reply from the backend — traffic now flows both ways, so
                // mark the flow ESTABLISHED on both halves. The GC reads this to
                // grant a long idle timeout (vs. the short one for half-open/UDP).
                if let Some(dp) = unsafe { CT_DNAT.get_ptr_mut(&dnat_key) } {
                    unsafe { (*dp).state |= CT_EST };
                }
                if let Some(sp) = unsafe { CT_SNAT.get_ptr_mut(&snat_key) } {
                    unsafe { (*sp).state |= CT_EST };
                }
            }
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

            let (new_dst_ip, new_dst_port, dnat_state) =
                if let Some(cached) = unsafe { CT_DNAT.get_ptr_mut(&dnat_key) } {
                    let ip = unsafe { (*cached).ip };
                    let port = unsafe { (*cached).port };
                    let last_seen = unsafe { (*cached).last_seen };
                    let state = unsafe { (*cached).state };
                    if !is_rst && now.wrapping_sub(last_seen) > CT_REFRESH_NS {
                        unsafe { (*cached).last_seen = now };
                    }
                    (ip, port, state)
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

                    // Cache the forward DNAT decision for subsequent packets. A full
                    // table means we can't track the flow: punt to the kernel rather
                    // than DNAT uncached (which would re-pick a backend every packet).
                    let fwd =
                        NatVal { ip: pod_ip, port: pod_port, state: 0, _pad: 0, last_seen: now };
                    if CT_DNAT.insert(&dnat_key, &fwd, 0).is_err() {
                        bump(COUNTER_SERVICE_PUNT);
                        return Ok(TC_ACT_OK as i32);
                    }
                    // Cache the reverse SNAT for return packets from the backend. Keep
                    // the two maps consistent: if this fails, drop the forward half too.
                    let snat_rev = NatKey {
                        src_ip: pod_ip,
                        dst_ip: ip_src,
                        src_port: pod_port,
                        dst_port: src_port,
                        proto: ip_proto,
                        _pad: [0; 3],
                    };
                    let rev =
                        NatVal { ip: ip_dst, port: dst_port, state: 0, _pad: 0, last_seen: now };
                    if CT_SNAT.insert(&snat_rev, &rev, 0).is_err() {
                        let _ = CT_DNAT.remove(&dnat_key);
                        bump(COUNTER_SERVICE_PUNT);
                        return Ok(TC_ACT_OK as i32);
                    }

                    (pod_ip, pod_port, 0)
                };

            // DNAT: rewrite dst IP and dst port, update checksums.
            ctx.store(ETH_HLEN + 16, &new_dst_ip, 0)?;
            ctx.l3_csum_replace(ETH_HLEN + 10, ip_dst as u64, new_dst_ip as u64, 4)?;
            ctx.l4_csum_replace(
                l4_csum_off,
                ip_dst as u64,
                new_dst_ip as u64,
                BPF_F_PSEUDO_HDR | l4_mangle | 4,
            )?;
            ctx.store(ETH_HLEN + ihl + 2, &new_dst_port, 0)?;
            ctx.l4_csum_replace(l4_csum_off, dst_port as u64, new_dst_port as u64, l4_mangle | 2)?;

            bump(COUNTER_SERVICE_DNAT);

            // The reverse (CT_SNAT) key mirrors the forward flow: the backend we
            // just DNAT'd to is the src, the client is the dst.
            let snat_rev = NatKey {
                src_ip: new_dst_ip,
                dst_ip: ip_src,
                src_port: new_dst_port,
                dst_port: src_port,
                proto: ip_proto,
                _pad: [0; 3],
            };
            if is_rst {
                // Tear down both halves immediately on an abort.
                let _ = CT_DNAT.remove(&dnat_key);
                let _ = CT_SNAT.remove(&snat_rev);
                bump(COUNTER_CT_EVICT);
            } else if ip_proto == IPPROTO_TCP && is_fin {
                // Client's FIN (forward direction). Record it on the *reverse*
                // entry, where the backend's path will read it. If the backend has
                // already FIN'd (its bit is on our own entry), both sides are now
                // closed: consolidate both bits onto the reverse entry, which is
                // the one the final ACK will traverse — so that ACK evicts locally.
                if let Some(sp) = unsafe { CT_SNAT.get_ptr_mut(&snat_rev) } {
                    if dnat_state & CT_FIN_REV != 0 {
                        unsafe { (*sp).state |= CT_FIN_FWD | CT_FIN_REV };
                    } else {
                        unsafe { (*sp).state |= CT_FIN_FWD };
                    }
                }
            } else if ip_proto == IPPROTO_TCP
                && dnat_state & CT_FIN_FWD != 0
                && dnat_state & CT_FIN_REV != 0
            {
                // Non-FIN packet and both bits are set on our own entry: this is
                // the final ACK of a client-closed-first teardown. Evict both.
                let _ = CT_DNAT.remove(&dnat_key);
                let _ = CT_SNAT.remove(&snat_rev);
                bump(COUNTER_CT_EVICT);
            }

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
