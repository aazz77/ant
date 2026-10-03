//! System stack: TCP NAT + UDP sessions + accept/dial relay.

use super::nat::TcpNat;
use super::packet::{
    build_udp_reply, broadcast_addr_v4, is_global_unicast_v4, is_global_unicast_v6,
    recompute_ipv4_checksum, recompute_tcp_checksum_v4, recompute_tcp_checksum_v6,
};
use crate::app::router::{Outbound, Router};
use crate::app::stats;
use crate::config::TunConfig;
use crate::inbound::target;
use crate::outbound::{relay, OutboundManager};
use anyhow::{Context, Result};
use bytes::Bytes;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const UDP_IDLE: Duration = Duration::from_secs(300);
const TCP_NAT_TIMEOUT: Duration = Duration::from_secs(300);

/// Channel item: (payload, destination).
type UdpPacket = (Bytes, SocketAddr);

struct UdpEntry {
    packet_tx: mpsc::Sender<UdpPacket>,
    last_seen: Instant,
}

/// Addresses derived from `tun.address` for the system stack.
pub struct StackAddrs {
    pub inet4_server: Option<Ipv4Addr>,
    pub inet4_client: Option<Ipv4Addr>,
    pub inet6_server: Option<Ipv6Addr>,
    pub inet6_client: Option<Ipv6Addr>,
    pub prefixes_v4: Vec<(Ipv4Addr, u8)>,
}

/// Shared runtime handles passed through the packet path.
#[derive(Clone)]
struct StackRuntime {
    writer: Arc<Mutex<tokio::io::WriteHalf<tun::AsyncDevice>>>,
    tcp_nat: Arc<TcpNat>,
    udp_sessions: Arc<Mutex<HashMap<SocketAddr, UdpEntry>>>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    tcp_port_v4: u16,
    tcp_port_v6: u16,
    inet4_server: Option<Ipv4Addr>,
    inet4_client: Option<Ipv4Addr>,
    inet6_server: Option<Ipv6Addr>,
    inet6_client: Option<Ipv6Addr>,
    inet4_broadcast: Option<Ipv4Addr>,
}

pub async fn run_system_stack(
    dev: tun::AsyncDevice,
    if_name: String,
    cfg: TunConfig,
    addrs: StackAddrs,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> Result<()> {
    let tcp_nat = Arc::new(TcpNat::new());
    let (mut reader, writer) = tokio::io::split(dev);
    let writer = Arc::new(Mutex::new(writer));

    let tcp_listener_v4 = match addrs.inet4_server {
        Some(addr) => bind_with_retry(SocketAddr::V4(SocketAddrV4::new(addr, 0))).await,
        None => None,
    };
    let tcp_listener_v6 = match addrs.inet6_server {
        Some(addr) => bind_with_retry(SocketAddr::V6(SocketAddrV6::new(addr, 0, 0, 0))).await,
        None => None,
    };

    let tcp_port_v4 = tcp_listener_v4
        .as_ref()
        .and_then(|l| l.local_addr().ok())
        .map(|a| a.port())
        .unwrap_or(0);
    let tcp_port_v6 = tcp_listener_v6
        .as_ref()
        .and_then(|l| l.local_addr().ok())
        .map(|a| a.port())
        .unwrap_or(0);

    if tcp_port_v4 != 0 {
        info!(interface = %if_name, port = tcp_port_v4, "tun: TCP v4 listener ready");
    }
    if tcp_port_v6 != 0 {
        info!(interface = %if_name, port = tcp_port_v6, "tun: TCP v6 listener ready");
    }

    if let Some(listener) = tcp_listener_v4 {
        let nat = tcp_nat.clone();
        let r = router.clone();
        let o = outbounds.clone();
        tokio::spawn(async move {
            accept_loop(listener, nat, r, o).await;
        });
    }
    if let Some(listener) = tcp_listener_v6 {
        let nat = tcp_nat.clone();
        let r = router.clone();
        let o = outbounds.clone();
        tokio::spawn(async move {
            accept_loop(listener, nat, r, o).await;
        });
    }

    let udp_sessions: Arc<Mutex<HashMap<SocketAddr, UdpEntry>>> =
        Arc::new(Mutex::new(HashMap::new()));

    {
        let nat = tcp_nat.clone();
        let sessions = udp_sessions.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                nat.gc(TCP_NAT_TIMEOUT).await;
                let mut map = sessions.lock().await;
                let now = Instant::now();
                map.retain(|_, e| now.duration_since(e.last_seen) < UDP_IDLE);
            }
        });
    }

    let inet4_broadcast = addrs
        .prefixes_v4
        .first()
        .map(|(net, pl)| broadcast_addr_v4(*net, *pl));

    let rt = StackRuntime {
        writer,
        tcp_nat,
        udp_sessions,
        router,
        outbounds,
        tcp_port_v4,
        tcp_port_v6,
        inet4_server: addrs.inet4_server,
        inet4_client: addrs.inet4_client,
        inet6_server: addrs.inet6_server,
        inet6_client: addrs.inet6_client,
        inet4_broadcast,
    };

    let mut buf = vec![0u8; (cfg.mtu as usize).saturating_add(64).max(2048)];
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => {
                warn!("tun: device EOF");
                break;
            }
            Ok(n) => n,
            Err(e) => {
                warn!(err = %e, "tun: read error");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        if n < 20 {
            continue;
        }
        let pkt = &buf[..n];
        match pkt[0] >> 4 {
            4 => process_ipv4(pkt, &rt).await,
            6 if n >= 40 => process_ipv6(pkt, &rt).await,
            _ => {}
        }
    }

    Ok(())
}

async fn bind_with_retry(addr: SocketAddr) -> Option<TcpListener> {
    for attempt in 0..5u32 {
        match TcpListener::bind(addr).await {
            Ok(l) => return Some(l),
            Err(e) if attempt < 4 => {
                warn!(err = %e, attempt, addr = %addr, "tun: TCP bind failed, retrying");
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            Err(e) => {
                warn!(err = %e, addr = %addr, "tun: failed to bind TCP listener");
                return None;
            }
        }
    }
    None
}

async fn accept_loop(
    listener: TcpListener,
    nat: Arc<TcpNat>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(err = %e, "tun: accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let peer = crate::app::sockopt::canonical(peer);
        let nat_port = peer.port();
        let Some((_orig_src, orig_dst)) = nat.lookup_back(nat_port).await else {
            debug!(nat_port, "tun: unknown NAT port, drop");
            continue;
        };
        let router = router.clone();
        let outbounds = outbounds.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tcp(stream, peer, orig_dst, router, outbounds).await {
                debug!(err = %e, peer = %peer, dest = %orig_dst, "tun: tcp session ended");
            }
        });
    }
}

async fn handle_tcp(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    dest: SocketAddr,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> Result<()> {
    let _ = stream.set_nodelay(true);
    let decided = target::decide(&router, dest, None).await;
    if decided.outbound == Outbound::Block {
        debug!(dest = %dest, "tun: tcp blocked");
        return Ok(());
    }
    let _conn = stats::global().register(stats::ConnectionInfo {
        peer,
        dest: decided.addr,
        dest_host: decided.host.clone(),
        inbound: "tun",
        rule: decided.rule.clone(),
        outbound: decided.outbound.label(),
    });
    let dialer = outbounds.select(decided.outbound).context("no dialer")?;
    let remote = dialer
        .dial_tcp(decided.addr, decided.host.as_deref())
        .await
        .with_context(|| format!("dial {}", decided.addr))?;
    let local: crate::outbound::BoxedStream = Box::new(stream);
    relay(local, remote).await?;
    Ok(())
}

async fn process_ipv4(raw: &[u8], rt: &StackRuntime) {
    if raw.len() < 20 {
        return;
    }
    let ihl = ((raw[0] & 0x0f) as usize) * 4;
    if ihl < 20 || raw.len() < ihl {
        return;
    }
    let flags_frag = u16::from_be_bytes([raw[6], raw[7]]);
    if (flags_frag & 0x1fff) != 0 || (flags_frag & 0x2000) != 0 {
        return; // drop fragments
    }

    let src_ip = Ipv4Addr::from([raw[12], raw[13], raw[14], raw[15]]);
    let dst_ip = Ipv4Addr::from([raw[16], raw[17], raw[18], raw[19]]);
    if Some(dst_ip) == rt.inet4_broadcast {
        return;
    }
    let payload = &raw[ihl..];
    match raw[9] {
        IPPROTO_TCP if rt.tcp_port_v4 != 0 => {
            handle_tcp_v4(raw, payload, src_ip, dst_ip, rt).await;
        }
        IPPROTO_UDP => {
            handle_udp(
                payload,
                SocketAddr::V4(SocketAddrV4::new(src_ip, 0)),
                SocketAddr::V4(SocketAddrV4::new(dst_ip, 0)),
                true,
                rt,
            )
            .await;
        }
        _ => {}
    }
}

async fn process_ipv6(raw: &[u8], rt: &StackRuntime) {
    if raw.len() < 40 {
        return;
    }
    let next = raw[6];
    let src_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[8..24]).unwrap());
    let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[24..40]).unwrap());
    let payload = &raw[40..];
    match next {
        IPPROTO_TCP if rt.tcp_port_v6 != 0 => {
            handle_tcp_v6(raw, payload, src_ip, dst_ip, rt).await;
        }
        IPPROTO_UDP => {
            handle_udp(
                payload,
                SocketAddr::V6(SocketAddrV6::new(src_ip, 0, 0, 0)),
                SocketAddr::V6(SocketAddrV6::new(dst_ip, 0, 0, 0)),
                false,
                rt,
            )
            .await;
        }
        _ => {}
    }
}

async fn handle_tcp_v4(
    raw: &[u8],
    tcp_payload: &[u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    rt: &StackRuntime,
) {
    let (server_addr, client_addr) = match (rt.inet4_server, rt.inet4_client) {
        (Some(s), Some(c)) => (s, c),
        _ => return,
    };
    if tcp_payload.len() < 20 {
        return;
    }
    let ihl = ((raw[0] & 0x0f) as usize) * 4;
    let src_port = u16::from_be_bytes([tcp_payload[0], tcp_payload[1]]);
    let dst_port = u16::from_be_bytes([tcp_payload[2], tcp_payload[3]]);
    let tcp_port = rt.tcp_port_v4;

    if src_ip == server_addr && src_port == tcp_port {
        if let Some((orig_src, orig_dst)) = rt.tcp_nat.lookup_back(dst_port).await {
            let mut pkt = raw.to_vec();
            let (ns, nsp) = match orig_dst {
                SocketAddr::V4(a) => (*a.ip(), a.port()),
                _ => return,
            };
            let (nd, ndp) = match orig_src {
                SocketAddr::V4(a) => (*a.ip(), a.port()),
                _ => return,
            };
            pkt[12..16].copy_from_slice(&ns.octets());
            pkt[16..20].copy_from_slice(&nd.octets());
            pkt[ihl..ihl + 2].copy_from_slice(&nsp.to_be_bytes());
            pkt[ihl + 2..ihl + 4].copy_from_slice(&ndp.to_be_bytes());
            recompute_tcp_checksum_v4(&mut pkt, ihl);
            recompute_ipv4_checksum(&mut pkt);
            tun_write(&rt.writer, &pkt).await;
        }
        return;
    }

    if !is_global_unicast_v4(dst_ip) {
        return;
    }

    let src = SocketAddr::V4(SocketAddrV4::new(src_ip, src_port));
    let dst = SocketAddr::V4(SocketAddrV4::new(dst_ip, dst_port));
    let Some(nat_port) = rt.tcp_nat.lookup_or_insert(src, dst).await else {
        warn!("tun: TCP NAT port space exhausted");
        return;
    };

    let mut pkt = raw.to_vec();
    pkt[12..16].copy_from_slice(&client_addr.octets());
    pkt[16..20].copy_from_slice(&server_addr.octets());
    pkt[ihl..ihl + 2].copy_from_slice(&nat_port.to_be_bytes());
    pkt[ihl + 2..ihl + 4].copy_from_slice(&tcp_port.to_be_bytes());
    recompute_tcp_checksum_v4(&mut pkt, ihl);
    recompute_ipv4_checksum(&mut pkt);
    tun_write(&rt.writer, &pkt).await;
}

async fn handle_tcp_v6(
    raw: &[u8],
    tcp_payload: &[u8],
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    rt: &StackRuntime,
) {
    let (server_addr, client_addr) = match (rt.inet6_server, rt.inet6_client) {
        (Some(s), Some(c)) => (s, c),
        _ => return,
    };
    if tcp_payload.len() < 20 {
        return;
    }
    let tcp_off = 40;
    let src_port = u16::from_be_bytes([tcp_payload[0], tcp_payload[1]]);
    let dst_port = u16::from_be_bytes([tcp_payload[2], tcp_payload[3]]);
    let tcp_port = rt.tcp_port_v6;

    if src_ip == server_addr && src_port == tcp_port {
        if let Some((orig_src, orig_dst)) = rt.tcp_nat.lookup_back(dst_port).await {
            let mut pkt = raw.to_vec();
            let (ns, nsp) = match orig_dst {
                SocketAddr::V6(a) => (*a.ip(), a.port()),
                _ => return,
            };
            let (nd, ndp) = match orig_src {
                SocketAddr::V6(a) => (*a.ip(), a.port()),
                _ => return,
            };
            pkt[8..24].copy_from_slice(&ns.octets());
            pkt[24..40].copy_from_slice(&nd.octets());
            pkt[tcp_off..tcp_off + 2].copy_from_slice(&nsp.to_be_bytes());
            pkt[tcp_off + 2..tcp_off + 4].copy_from_slice(&ndp.to_be_bytes());
            recompute_tcp_checksum_v6(&mut pkt, tcp_off);
            tun_write(&rt.writer, &pkt).await;
        }
        return;
    }

    if !is_global_unicast_v6(dst_ip) {
        return;
    }

    let src = SocketAddr::V6(SocketAddrV6::new(src_ip, src_port, 0, 0));
    let dst = SocketAddr::V6(SocketAddrV6::new(dst_ip, dst_port, 0, 0));
    let Some(nat_port) = rt.tcp_nat.lookup_or_insert(src, dst).await else {
        warn!("tun: TCP NAT port space exhausted (v6)");
        return;
    };

    let mut pkt = raw.to_vec();
    pkt[8..24].copy_from_slice(&client_addr.octets());
    pkt[24..40].copy_from_slice(&server_addr.octets());
    pkt[tcp_off..tcp_off + 2].copy_from_slice(&nat_port.to_be_bytes());
    pkt[tcp_off + 2..tcp_off + 4].copy_from_slice(&tcp_port.to_be_bytes());
    recompute_tcp_checksum_v6(&mut pkt, tcp_off);
    tun_write(&rt.writer, &pkt).await;
}

async fn handle_udp(
    udp_payload: &[u8],
    mut src: SocketAddr,
    mut dst: SocketAddr,
    is_v4: bool,
    rt: &StackRuntime,
) {
    if udp_payload.len() < 8 {
        return;
    }
    let src_port = u16::from_be_bytes([udp_payload[0], udp_payload[1]]);
    let dst_port = u16::from_be_bytes([udp_payload[2], udp_payload[3]]);
    src.set_port(src_port);
    dst.set_port(dst_port);

    if is_v4 {
        if let SocketAddr::V4(a) = dst {
            if !is_global_unicast_v4(*a.ip()) {
                return;
            }
        }
    } else if let SocketAddr::V6(a) = dst {
        if !is_global_unicast_v6(*a.ip()) {
            return;
        }
    }

    let data = Bytes::copy_from_slice(&udp_payload[8..]);
    feed_udp(src, dst, data, rt).await;
}

async fn feed_udp(src: SocketAddr, dst: SocketAddr, data: Bytes, rt: &StackRuntime) {
    {
        let mut map = rt.udp_sessions.lock().await;
        if let Some(e) = map.get_mut(&src) {
            e.last_seen = Instant::now();
            let _ = e.packet_tx.try_send((data, dst));
            return;
        }

        let (tx, rx) = mpsc::channel::<UdpPacket>(64);
        let _ = tx.try_send((data, dst));
        map.insert(
            src,
            UdpEntry {
                packet_tx: tx,
                last_seen: Instant::now(),
            },
        );
        drop(map);

        let writer = rt.writer.clone();
        let sessions = rt.udp_sessions.clone();
        let router = rt.router.clone();
        let outbounds = rt.outbounds.clone();
        tokio::spawn(async move {
            run_udp_session(src, rx, writer, sessions, router, outbounds).await;
        });
    }
}

async fn run_udp_session(
    client: SocketAddr,
    mut rx: mpsc::Receiver<UdpPacket>,
    writer: Arc<Mutex<tokio::io::WriteHalf<tun::AsyncDevice>>>,
    sessions: Arc<Mutex<HashMap<SocketAddr, UdpEntry>>>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) {
    let Some((first_payload, first_dst)) = rx.recv().await else {
        sessions.lock().await.remove(&client);
        return;
    };

    let decided = target::decide(&router, first_dst, None).await;
    if decided.outbound == Outbound::Block {
        sessions.lock().await.remove(&client);
        return;
    }
    let Some(dialer) = outbounds.select(decided.outbound) else {
        sessions.lock().await.remove(&client);
        return;
    };
    let sess = match dialer.dial_udp(Some(client)).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            debug!(err = %e, "tun: udp dial failed");
            sessions.lock().await.remove(&client);
            return;
        }
    };

    let sess_r = sess.clone();
    let writer_r = writer.clone();
    let recv_task = tokio::spawn(async move {
        while let Ok((payload, from)) = sess_r.recv_from().await {
            if let Some(pkt) = build_udp_reply(from, client, &payload) {
                tun_write(&writer_r, &pkt).await;
            }
        }
    });

    if let Err(e) = sess
        .send_to(&first_payload, first_dst, decided.host.as_deref())
        .await
    {
        debug!(err = %e, "tun: udp send failed");
        recv_task.abort();
        sessions.lock().await.remove(&client);
        return;
    }

    while let Ok(Some((payload, dest))) = tokio::time::timeout(UDP_IDLE, rx.recv()).await {
        if let Some(e) = sessions.lock().await.get_mut(&client) {
            e.last_seen = Instant::now();
        }
        if let Err(e) = sess.send_to(&payload, dest, None).await {
            debug!(err = %e, "tun: udp send failed");
            break;
        }
    }

    recv_task.abort();
    sessions.lock().await.remove(&client);
}

async fn tun_write(
    writer: &Arc<Mutex<tokio::io::WriteHalf<tun::AsyncDevice>>>,
    pkt: &[u8],
) {
    let mut w = writer.lock().await;
    if let Err(e) = w.write_all(pkt).await {
        debug!(err = %e, "tun: write failed");
    }
}
