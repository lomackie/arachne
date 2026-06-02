use std::time::Duration;

pub use crate::bpf::CtTimeouts;

// Idle timeout for an ESTABLISHED TCP flow before the GC reaps it. Deliberately
// large: an idle-but-alive connection (e.g. a pooled DB connection) must survive
// a quiet period, so we err toward keeping established entries. Override with
// ARACHNE_CT_IDLE_SECS.
const DEFAULT_CT_IDLE_SECS: u64 = 86_400; // 1 day

// Idle timeout for everything that isn't an established TCP flow: half-open
// (SYN, no reply), closing (post-FIN), and all UDP. These have no business
// lingering, so they age out fast. Clean TCP teardown is evicted in the datapath
// the instant the handshake completes; this short sweep is the safety net for
// flows whose final ACK was lost, abandoned half-open attempts, and UDP. Override
// with ARACHNE_CT_SHORT_SECS.
const DEFAULT_CT_SHORT_SECS: u64 = 60;

const DEFAULT_CT_GC_SECS: u64 = 30;

/// The configured conntrack idle timeouts (env `ARACHNE_CT_IDLE_SECS` for
/// established TCP flows, `ARACHNE_CT_SHORT_SECS` for everything else).
pub fn timeouts() -> CtTimeouts {
    CtTimeouts {
        established_ns: secs_to_ns(env_secs("ARACHNE_CT_IDLE_SECS", DEFAULT_CT_IDLE_SECS)),
        short_ns: secs_to_ns(env_secs("ARACHNE_CT_SHORT_SECS", DEFAULT_CT_SHORT_SECS)),
    }
}

/// How often the GC sweep runs (env `ARACHNE_CT_GC_SECS`, in seconds).
pub fn gc_interval() -> Duration {
    Duration::from_secs(env_secs("ARACHNE_CT_GC_SECS", DEFAULT_CT_GC_SECS))
}

fn secs_to_ns(secs: u64) -> u64 {
    secs.saturating_mul(1_000_000_000)
}

fn env_secs(var: &str, default: u64) -> u64 {
    std::env::var(var)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&s| s > 0)
        .unwrap_or(default)
}

/// Run one conntrack GC sweep, logging what it reclaimed.
pub fn gc_tick(timeouts: CtTimeouts) {
    match crate::bpf::ct_gc(timeouts) {
        Ok(stats) if stats.evicted > 0 => {
            eprintln!("conntrack gc: scanned={} evicted={}", stats.scanned, stats.evicted);
        }
        Ok(_) => {}
        Err(e) => eprintln!("conntrack gc: failed: {e}"),
    }
}
