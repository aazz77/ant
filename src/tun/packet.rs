//! IP/TCP/UDP checksums and minimal packet builders.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn recompute_ipv4_checksum(pkt: &mut [u8]) {
    if pkt.len() < 20 {
        return;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl {
        return;
    }
    pkt[10] = 0;
    pkt[11] = 0;
    let c = internet_checksum(&pkt[..ihl]);
    pkt[10] = (c >> 8) as u8;
    pkt[11] = (c & 0xff) as u8;
}

fn pseudo_sum_v4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, len: usize) -> u32 {
    let s = src.octets();
    let d = dst.octets();
    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([s[0], s[1]]) as u32;
    sum += u16::from_be_bytes([s[2], s[3]]) as u32;
    sum += u16::from_be_bytes([d[0], d[1]]) as u32;
    sum += u16::from_be_bytes([d[2], d[3]]) as u32;
    sum += proto as u32;
    sum += len as u32;
    sum
}

fn pseudo_sum_v6(src: Ipv6Addr, dst: Ipv6Addr, proto: u8, len: usize) -> u32 {
    let s = src.octets();
    let d = dst.octets();
    let mut sum: u32 = 0;
    for chunk in s.chunks(2).chain(d.chunks(2)) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += (len as u32) >> 16;
    sum += (len as u32) & 0xffff;
    sum += proto as u32;
    sum
}

fn fold_checksum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn recompute_tcp_checksum_v4(pkt: &mut [u8], ihl: usize) {
    if pkt.len() < ihl + 20 {
        return;
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let tcp = &mut pkt[ihl..];
    tcp[16] = 0;
    tcp[17] = 0;
    let mut sum = pseudo_sum_v4(src, dst, 6, tcp.len());
    let mut i = 0;
    while i + 1 < tcp.len() {
        sum += u16::from_be_bytes([tcp[i], tcp[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp.len() {
        sum += (tcp[i] as u32) << 8;
    }
    let c = fold_checksum(sum);
    tcp[16] = (c >> 8) as u8;
    tcp[17] = (c & 0xff) as u8;
}

pub fn recompute_tcp_checksum_v6(pkt: &mut [u8], tcp_off: usize) {
    if pkt.len() < tcp_off + 20 || pkt.len() < 40 {
        return;
    }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).unwrap());
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).unwrap());
    let tcp_len = pkt.len() - tcp_off;
    pkt[tcp_off + 16] = 0;
    pkt[tcp_off + 17] = 0;
    let mut sum = pseudo_sum_v6(src, dst, 6, tcp_len);
    let tcp = &pkt[tcp_off..];
    let mut i = 0;
    while i + 1 < tcp.len() {
        sum += u16::from_be_bytes([tcp[i], tcp[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp.len() {
        sum += (tcp[i] as u32) << 8;
    }
    let c = fold_checksum(sum);
    pkt[tcp_off + 16] = (c >> 8) as u8;
    pkt[tcp_off + 17] = (c & 0xff) as u8;
}

pub fn recompute_udp_checksum_v4(pkt: &mut [u8], ihl: usize) {
    if pkt.len() < ihl + 8 {
        return;
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let udp = &mut pkt[ihl..];
    udp[6] = 0;
    udp[7] = 0;
    let mut sum = pseudo_sum_v4(src, dst, 17, udp.len());
    let mut i = 0;
    while i + 1 < udp.len() {
        sum += u16::from_be_bytes([udp[i], udp[i + 1]]) as u32;
        i += 2;
    }
    if i < udp.len() {
        sum += (udp[i] as u32) << 8;
    }
    let c = fold_checksum(sum);
    // UDP checksum 0 means no checksum; use 0xffff if computed 0.
    let c = if c == 0 { 0xffff } else { c };
    udp[6] = (c >> 8) as u8;
    udp[7] = (c & 0xff) as u8;
}

pub fn recompute_udp_checksum_v6(pkt: &mut [u8], udp_off: usize) {
    if pkt.len() < udp_off + 8 || pkt.len() < 40 {
        return;
    }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).unwrap());
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).unwrap());
    let udp_len = pkt.len() - udp_off;
    pkt[udp_off + 6] = 0;
    pkt[udp_off + 7] = 0;
    let mut sum = pseudo_sum_v6(src, dst, 17, udp_len);
    let udp = &pkt[udp_off..];
    let mut i = 0;
    while i + 1 < udp.len() {
        sum += u16::from_be_bytes([udp[i], udp[i + 1]]) as u32;
        i += 2;
    }
    if i < udp.len() {
        sum += (udp[i] as u32) << 8;
    }
    let c = fold_checksum(sum);
    let c = if c == 0 { 0xffff } else { c };
    pkt[udp_off + 6] = (c >> 8) as u8;
    pkt[udp_off + 7] = (c & 0xff) as u8;
}

/// Build a simple IPv4 UDP reply (from zero; good enough without template).
pub fn build_udp_reply_v4(
    src: SocketAddrV4,
    dst: SocketAddrV4,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let total = (20 + udp_len as usize) as u16;
    let mut pkt = Vec::with_capacity(total as usize);
    pkt.push(0x45); // v4, ihl=5
    pkt.push(0); // DSCP
    pkt.extend_from_slice(&total.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // id
    pkt.extend_from_slice(&0x4000u16.to_be_bytes()); // DF
    pkt.push(64); // ttl
    pkt.push(17); // UDP
    pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum
    pkt.extend_from_slice(&src.ip().octets());
    pkt.extend_from_slice(&dst.ip().octets());
    pkt.extend_from_slice(&src.port().to_be_bytes());
    pkt.extend_from_slice(&dst.port().to_be_bytes());
    pkt.extend_from_slice(&udp_len.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(payload);
    recompute_udp_checksum_v4(&mut pkt, 20);
    recompute_ipv4_checksum(&mut pkt);
    pkt
}

pub fn build_udp_reply_v6(
    src: SocketAddrV6,
    dst: SocketAddrV6,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let mut pkt = Vec::with_capacity(40 + udp_len as usize);
    pkt.push(0x60); // v6
    pkt.extend_from_slice(&[0, 0, 0]); // traffic class + flow
    pkt.extend_from_slice(&udp_len.to_be_bytes());
    pkt.push(17); // next header UDP
    pkt.push(64); // hop limit
    pkt.extend_from_slice(&src.ip().octets());
    pkt.extend_from_slice(&dst.ip().octets());
    pkt.extend_from_slice(&src.port().to_be_bytes());
    pkt.extend_from_slice(&dst.port().to_be_bytes());
    pkt.extend_from_slice(&udp_len.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(payload);
    recompute_udp_checksum_v6(&mut pkt, 40);
    pkt
}

pub fn build_udp_reply(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => Some(build_udp_reply_v4(s, d, payload)),
        (SocketAddr::V6(s), SocketAddr::V6(d)) => Some(build_udp_reply_v6(s, d, payload)),
        _ => None,
    }
}

pub fn is_global_unicast_v4(addr: Ipv4Addr) -> bool {
    if addr.is_unspecified() || addr.is_broadcast() {
        return false;
    }
    let o = addr.octets();
    // Exclude multicast 224.0.0.0/4
    if o[0] >= 224 && o[0] < 240 {
        return false;
    }
    true
}

pub fn is_global_unicast_v6(addr: Ipv6Addr) -> bool {
    if addr.is_unspecified() || addr.is_loopback() {
        return false;
    }
    let seg0 = addr.segments()[0];
    if (seg0 & 0xffc0) == 0xfe80 {
        return false; // link-local
    }
    if (seg0 & 0xff00) == 0xff00 {
        return false; // multicast
    }
    true
}

pub fn broadcast_addr_v4(network: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let mask = if prefix_len == 0 {
        0u32
    } else {
        !((1u32 << (32 - prefix_len.min(32))) - 1)
    };
    let net = u32::from(network) & mask;
    Ipv4Addr::from(net | !mask)
}
