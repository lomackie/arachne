#![no_std]
#![no_main]

use core::ffi::c_long;

use arachne_common::{
    COUNTER_FIB_MISS, COUNTER_MAP_HIT, COUNTER_MAX, COUNTER_REDIRECT, Endpoint, MAX_ENDPOINTS,
};
use aya_ebpf::{
    EbpfContext,
    bindings::{__sk_buff, TC_ACT_OK, bpf_fib_lookup as BpfFibLookup},
    helpers::{bpf_fib_lookup, bpf_redirect},
    macros::{classifier, map},
    maps::{HashMap, PerCpuArray},
    programs::TcContext,
};

#[map]
static ENDPOINTS: HashMap<u32, Endpoint> = HashMap::pinned(MAX_ENDPOINTS, 0);

#[map]
static COUNTERS: PerCpuArray<u64> = PerCpuArray::pinned(COUNTER_MAX, 0);

// Ethernet header: 6 dst + 6 src + 2 type = 14 bytes
const ETH_HLEN: usize = 14;
// IPv4 ethertype in network byte order
const ETH_P_IP: u16 = 0x0800;
// AF_INET
const AF_INET: u8 = 2;

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
    // Check ethertype (bytes 12-13 of the frame)
    if u16::from_be(ctx.load::<u16>(12)?) != ETH_P_IP {
        return Ok(TC_ACT_OK as i32);
    }

    // Read IPv4 src and dst from the IP header (in network byte order)
    // IPv4 saddr is at IP header offset 12, daddr at offset 16
    let ip_src = ctx.load::<u32>(ETH_HLEN + 12)?;
    let ip_dst = ctx.load::<u32>(ETH_HLEN + 16)?;

    if let Some(endpoint) = unsafe { ENDPOINTS.get(&ip_dst) } {
        let endpoint = unsafe { &*endpoint };
        ctx.store(0, &endpoint.mac, 0)?;
        bump(COUNTER_MAP_HIT);
        return Ok(unsafe { bpf_redirect(endpoint.ifindex, 0) } as i32);
    }

    let mut fib: BpfFibLookup = unsafe { core::mem::zeroed() };
    fib.family = AF_INET;
    fib.__bindgen_anon_3.ipv4_src = ip_src;
    fib.__bindgen_anon_4.ipv4_dst = ip_dst;
    // Forwarding lookup from the perspective of the ingress interface
    fib.ifindex = unsafe { (*(ctx.as_ptr() as *mut __sk_buff)).ingress_ifindex };

    let rc = unsafe {
        bpf_fib_lookup(
            ctx.as_ptr() as *mut core::ffi::c_void,
            &mut fib as *mut BpfFibLookup,
            core::mem::size_of::<BpfFibLookup>() as i32,
            0u32,
        )
    };

    // BPF_FIB_LKUP_RET_SUCCESS == 0; anything else means miss or unresolved neighbour
    if rc != 0 {
        bump(COUNTER_FIB_MISS);
        return Ok(TC_ACT_OK as i32);
    }

    // Rewrite Ethernet dst MAC (bytes 0-5) and src MAC (bytes 6-11)
    ctx.store(0, &fib.dmac, 0)?;
    ctx.store(6, &fib.smac, 0)?;

    bump(COUNTER_REDIRECT);
    // Hand the packet to the kernel redirect machinery
    Ok(unsafe { bpf_redirect(fib.ifindex, 0) } as i32)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
