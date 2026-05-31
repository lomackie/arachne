#![no_std]

use core::net::Ipv4Addr;

pub const ENDPOINTS_MAP: &str = "ENDPOINTS";
pub const MAX_ENDPOINTS: u32 = 1 << 16;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Endpoint {
    pub ifindex: u32,
    pub mac: [u8; 6],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Endpoint {}

pub const fn endpoint_key(ip: Ipv4Addr) -> u32 {
    u32::from_le_bytes(ip.octets())
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
    fn key_matches_network_order_load() {
        let ip = Ipv4Addr::new(10, 244, 1, 5);
        assert_eq!(endpoint_key(ip), u32::from_le_bytes([10, 244, 1, 5]));
    }
}
