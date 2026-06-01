use std::time::Duration;

// Idle timeout before a conntrack flow is reaped. Deliberately large: an
// idle-but-alive TCP connection (e.g. a pooled DB connection) must survive a
// quiet period, so we err toward keeping entries. RST teardown handles prompt
// cleanup of aborted flows in the datapath; this sweep is the safety net for
// flows that never close cleanly. Override with ARACHNE_CT_IDLE_SECS.
const DEFAULT_CT_IDLE_SECS: u64 = 86_400; // 1 day
const DEFAULT_CT_GC_SECS: u64 = 30;

/// The configured conntrack idle timeout (env `ARACHNE_CT_IDLE_SECS`, in seconds).
pub fn idle_timeout() -> Duration {
    Duration::from_secs(env_secs("ARACHNE_CT_IDLE_SECS", DEFAULT_CT_IDLE_SECS))
}

/// How often the GC sweep runs (env `ARACHNE_CT_GC_SECS`, in seconds).
pub fn gc_interval() -> Duration {
    Duration::from_secs(env_secs("ARACHNE_CT_GC_SECS", DEFAULT_CT_GC_SECS))
}

fn env_secs(var: &str, default: u64) -> u64 {
    std::env::var(var)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&s| s > 0)
        .unwrap_or(default)
}

/// Run one conntrack GC sweep, logging what it reclaimed.
pub fn gc_tick(idle: Duration) {
    let idle_ns = idle.as_nanos().min(u64::MAX as u128) as u64;
    match crate::bpf::ct_gc(idle_ns) {
        Ok(stats) if stats.evicted > 0 => {
            eprintln!("conntrack gc: scanned={} evicted={}", stats.scanned, stats.evicted);
        }
        Ok(_) => {}
        Err(e) => eprintln!("conntrack gc: failed: {e}"),
    }
}
