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

pub async fn run_system_stack(
    dev: tun::AsyncDevice,
    if_name: String,
    cfg: TunConfig,
    inet4_server: Option<Ipv4Addr>,
    inet4_client: Option<Ipv4Addr>,
    inet6_server: Option<Ipv6Addr>,
    inet6_client: Option<Ipv6Addr>,
    prefixes_v4: Vec<(Ipv4Addr, u8)>,
    _prefixes_v6: Vec<(Ipv6Addr, u8)>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> Result<()> {
    let tcp_nat = Arc::new(TcpNat::new());
    let (mut reader, writer) = tokio::io::split(dev);
    let writer = Arc::new(Mutex::new(writer));

    let tcp_listener_v4 = match inet4_server {
        Some(addr) => bind_with_retry(SocketAddr::V4(SocketAddrV4::new(addr, 0))).await,
        None => None,
    };
    let tcp_listener_v6 = match inet6_server {
        Some(addr) => bind_with_retry(SocketAddr::V6(SocketAddrV6::new(addr, 0, 0, 0))).await,
        None => None,
    };

    let tcp_port_v4 = tcp_listener_v4
        .as_ref()
        .and_then(|l| l.local_addr().ok())
        .map(|a| a.port());
    let tcp_port_v6 = tcp_listener_v6
        .as_ref()
        .and_then(|l| l.local_addr().ok())
        .map(|a| a.port());

    if let Some(p) = tcp_port_v4 {
        info!(interface = %if_name, port = p, "tun: TCP v4 listener ready");
    }
    if let Some(p) = tcp_port_v6 {
        info!(interface = %if_name, port = p, "tun: TCP v6 listener ready");
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

    let inet4_broadcast = prefixes_v4
        .first()
        .map(|(net, pl)| broadcast_addr_v4(*net, *pl));

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
            4 => {
                process_ipv4(
                    pkt,
                    inet4_server,
                    inet4_client,
                    inet4_broadcast,
                    tcp_port_v4.unwrap_or(0),
                    writer.clone(),
                    tcp_nat.clone(),
                    udp_sessions.clone(),
                    router.clone(),
                    outbounds.clone(),
                )
                .await;
            }
            6 if n >= 40 => {
                process_ipv6(
                    pkt,
                    inet6_server,
                    inet6_client,
                    tcp_port_v6.unwrap_or(0),
                    writer.clone(),
                    tcp_nat.clone(),
                    udp_sessions.clone(),
                    router.clone(),
                    outbounds.clone(),
                )
                .await;
            }
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

async fn process_ipv4(
    raw: &[u8],
    inet4_server: Option<Ipv4Addr>,
    inet4_client: Option<Ipv4Addr>,
    inet4_broadcast: Option<Ipv4Addr>,
    tcp_port: u16,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
    tcp_nat: Arc<TcpNat>,
    udp_sessions: Arc<Mutex<HashMap<SocketAddr, UdpEntry>>>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) {
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
    if Some(dst_ip) == inet4_broadcast {
        return;
    }
    let payload = &raw[ihl..];
    match raw[9] {
        IPPROTO_TCP if tcp_port != 0 => {
            handle_tcp_v4(
                raw, payload, src_ip, dst_ip, inet4_server, inet4_client, tcp_port, writer, tcp_nat,
            )
            .await;
        }
        IPPROTO_UDP => {
            handle_udp(
                payload,
                SocketAddr::V4(SocketAddrV4::new(src_ip, 0)), // ports filled below
                SocketAddr::V4(SocketAddrV4::new(dst_ip, 0)),
                true,
                writer,
                udp_sessions,
                router,
                outbounds,
            )
            .await;
        }
        _ => {}
    }
}

async fn process_ipv6(
    raw: &[u8],
    inet6_server: Option<Ipv6Addr>,
    inet6_client: Option<Ipv6Addr>,
    tcp_port: u16,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
    tcp_nat: Arc<TcpNat>,
    udp_sessions: Arc<Mutex<HashMap<SocketAddr, UdpEntry>>>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) {
    if raw.len() < 40 {
        return;
    }
    let next = raw[6];
    let src_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[8..24]).unwrap());
    let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[24..40]).unwrap());
    let payload = &raw[40..];
    match next {
        IPPROTO_TCP if tcp_port != 0 => {
            handle_tcp_v6(
                raw, payload, src_ip, dst_ip, inet6_server, inet6_client, tcp_port, writer, tcp_nat,
            )
            .await;
        }
        IPPROTO_UDP => {
            handle_udp(
                payload,
                SocketAddr::V6(SocketAddrV6::new(src_ip, 0, 0, 0)),
                SocketAddr::V6(SocketAddrV6::new(dst_ip, 0, 0, 0)),
                false,
                writer,
                udp_sessions,
                router,
                outbounds,
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
    inet4_server: Option<Ipv4Addr>,
    inet4_client: Option<Ipv4Addr>,
    tcp_port: u16,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send>>,
    tcp_nat: Arc<TcpNat>,
) {
    let (server_addr, client_addr) = match (inet4_server, inet4_client) {
        (Some(s), Some(c)) => (s, c),
        _ => return,
    };
    if tcp_payload.len() < 20 {
        return;
    }
    let ihl = ((raw[0] & 0x0f) as usize) * 4;
    let src_port = u16::from_be_bytes([tcp_payload[0], tcp_payload[1]]);
    let dst_port = u16::from_be_bytes([tcp_payload[2], tcp_payload[3]]);

    if src_ip == server_addr && src_port == tcp_port {
        if let Some((orig_src, orig_dst)) = tcp_nat.lookup_back(dst_port).await {
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
            tun_write(&writer, &pkt).await;
        }
        return;
    }

    if !is_global_unicast_v4(dst_ip) {
        return;
    }

    let src = SocketAddr::V4(SocketAddrV4::new(src_ip, src_port));
    let dst = SocketAddr::V4(SocketAddrV4::new(dst_ip, dst_port));
    let Some(nat_port) = tcp_nat.lookup_or_insert(src, dst).await else {
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
    tun_write(&writer, &pkt).await;
}

async fn handle_tcp_v6(
    raw: &[u8],
    tcp_payload: &[u8],
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    inet6_server: Option<Ipv6Addr>,
    inet6_client: Option<Ipv6Addr>,
    tcp_port: u16,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send>>,
    tcp_nat: Arc<TcpNat>,
) {
    let (server_addr, client_addr) = match (inet6_server, inet6_client) {
        (Some(s), Some(c)) => (s, c),
        _ => return,
    };
    if tcp_payload.len() < 20 {
        return;
    }
    let tcp_off = 40;
    let src_port = u16::from_be_bytes([tcp_payload[0], tcp_payload[1]]);
    let dst_port = u16::from_be_bytes([tcp_payload[2], tcp_payload[3]]);

    if src_ip == server_addr && src_port == tcp_port {
        if let Some((orig_src, orig_dst)) = tcp_nat.lookup_back(dst_port).await {
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
            tun_write(&writer, &pkt).await;
        }
        return;
    }

    if !is_global_unicast_v6(dst_ip) {
        return;
    }

    let src = SocketAddr::V6(SocketAddrV6::new(src_ip, src_port, 0, 0));
    let dst = SocketAddr::V6(SocketAddrV6::new(dst_ip, dst_port, 0, 0));
    let Some(nat_port) = tcp_nat.lookup_or_insert(src, dst).await else {
        warn!("tun: TCP NAT port space exhausted (v6)");
        return;
    };

    let mut pkt = raw.to_vec();
    pkt[8..24].copy_from_slice(&client_addr.octets());
    pkt[24..40].copy_from_slice(&server_addr.octets());
    pkt[tcp_off..tcp_off + 2].copy_from_slice(&nat_port.to_be_bytes());
    pkt[tcp_off + 2..tcp_off + 4].copy_from_slice(&tcp_port.to_be_bytes());
    recompute_tcp_checksum_v6(&mut pkt, tcp_off);
    tun_write(&writer, &pkt).await;
}

async fn handle_udp(
    udp_payload: &[u8],
    mut src: SocketAddr,
    mut dst: SocketAddr,
    is_v4: bool,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
    udp_sessions: Arc<Mutex<HashMap<SocketAddr, UdpEntry>>>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
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
    feed_udp(src, dst, data, writer, udp_sessions, router, outbounds).await;
}

async fn feed_udp(
    src: SocketAddr,
    dst: SocketAddr,
    data: Bytes,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
    udp_sessions: Arc<Mutex<HashMap<SocketAddr, UdpEntry>>>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) {
    {
        let mut map = udp_sessions.lock().await;
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

        let sessions = udp_sessions.clone();
        tokio::spawn(async move {
            run_udp_session(src, rx, writer, sessions, router, outbounds).await;
        });
    }
}

async fn run_udp_session(
    client: SocketAddr,
    mut rx: mpsc::Receiver<UdpPacket>,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
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
        loop {
            match sess_r.recv_from().await {
                Ok((payload, from)) => {
                    if let Some(pkt) = build_udp_reply(from, client, &payload) {
                        tun_write(&writer_r, &pkt).await;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // First packet
    if let Err(e) = sess
        .send_to(&first_payload, first_dst, decided.host.as_deref())
        .await
    {
        debug!(err = %e, "tun: udp send failed");
        recv_task.abort();
        sessions.lock().await.remove(&client);
        return;
    }

    loop {
        match tokio::time::timeout(UDP_IDLE, rx.recv()).await {
            Ok(Some((payload, dest))) => {
                if let Some(e) = sessions.lock().await.get_mut(&client) {
                    e.last_seen = Instant::now();
                }
                if let Err(e) = sess.send_to(&payload, dest, None).await {
                    debug!(err = %e, "tun: udp send failed");
                    break;
                }
            }
            Ok(None) | Err(_) => break,
        }
    }

    recv_task.abort();
    sessions.lock().await.remove(&client);
}

async fn tun_write(writer: &Arc<Mutex<impl AsyncWriteExt + Unpin>>, pkt: &[u8]) {
    let mut w = writer.lock().await;
    if let Err(e) = w.write_all(pkt).await {
        debug!(err = %e, "tun: write failed");
    }
}
