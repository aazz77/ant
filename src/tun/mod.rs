//! TUN inbound (system stack only).
//!
//! Creates a virtual NIC via the `tun` crate, runs a kernel-assisted system
//! stack (TCP NAT + UDP sessions). Does **not** install routes (no auto_route)
//! and does **not** hijack DNS.
//!
//! Platforms: Linux + Windows. Address configuration uses `ip` (Linux) or
//! `netsh` (Windows).

mod device;
mod nat;
mod packet;
mod stack;

use crate::app::router::Router;
use crate::config::TunConfig;
use crate::outbound::OutboundManager;
use anyhow::{bail, Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tracing::{info, warn};

/// Entry point used by `main`.
pub async fn run_tun(
    cfg: TunConfig,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> Result<()> {
    if !cfg.enable {
        bail!("tun disabled");
    }
    if cfg.address.is_empty() {
        bail!("tun.address is required (e.g. [\"198.18.0.1/30\"])");
    }

    // Parse prefixes and derive server/client addresses (sing-tun / system stack).
    let mut inet4_server: Option<Ipv4Addr> = None;
    let mut inet4_client: Option<Ipv4Addr> = None;
    let mut inet6_server: Option<Ipv6Addr> = None;
    let mut inet6_client: Option<Ipv6Addr> = None;
    let mut prefixes_v4: Vec<(Ipv4Addr, u8)> = Vec::new();
    let mut prefixes_v6: Vec<(Ipv6Addr, u8)> = Vec::new();

    for s in &cfg.address {
        let (ip, pl) = parse_addr_prefix(s)
            .with_context(|| format!("invalid tun.address entry: {s}"))?;
        match ip {
            IpAddr::V4(v4) => {
                prefixes_v4.push((v4, pl));
                if inet4_server.is_none() {
                    if !has_next_addr_v4(v4, pl) {
                        bail!(
                            "tun: first IPv4 address {v4}/{pl} has no next address in prefix \
                             (system stack needs server=addr, client=addr+1; use e.g. /30)"
                        );
                    }
                    inet4_server = Some(v4);
                    inet4_client = Some(next_v4(v4));
                }
            }
            IpAddr::V6(v6) => {
                prefixes_v6.push((v6, pl));
                if inet6_server.is_none() {
                    if !has_next_addr_v6(v6, pl) {
                        bail!(
                            "tun: first IPv6 address {v6}/{pl} has no next address in prefix \
                             (system stack needs server=addr, client=addr+1)"
                        );
                    }
                    inet6_server = Some(v6);
                    inet6_client = Some(next_v6(v6));
                }
            }
        }
    }

    if inet4_server.is_none() && inet6_server.is_none() {
        bail!("tun.address must contain at least one IPv4 or IPv6 prefix");
    }

    info!(
        device = ?cfg.device,
        mtu = cfg.mtu,
        v4_server = ?inet4_server,
        v4_client = ?inet4_client,
        v6_server = ?inet6_server,
        v6_client = ?inet6_client,
        "tun: starting system stack (no auto_route, no dns hijack)"
    );

    let (dev, if_name) = device::create_device(&cfg).await?;
    info!(interface = %if_name, "tun: device ready");

    // Configure addresses / MTU via platform tools (no routes).
    device::configure_addresses(&if_name, &cfg, &prefixes_v4, &prefixes_v6).await?;

    // Brief wait so the OS registers the address before we bind listeners.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    stack::run_system_stack(
        dev,
        if_name,
        cfg,
        inet4_server,
        inet4_client,
        inet6_server,
        inet6_client,
        prefixes_v4,
        prefixes_v6,
        router,
        outbounds,
    )
    .await
}

fn parse_addr_prefix(s: &str) -> Result<(IpAddr, u8)> {
    let (ip_str, pl_str) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("expected addr/prefix, got `{s}`"))?;
    let ip: IpAddr = ip_str.parse().context("parse IP")?;
    let pl: u8 = pl_str.parse().context("parse prefix length")?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if pl > max {
        bail!("prefix length {pl} > {max}");
    }
    Ok((ip, pl))
}

fn next_v4(ip: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(ip).wrapping_add(1))
}

fn next_v6(ip: Ipv6Addr) -> Ipv6Addr {
    Ipv6Addr::from(u128::from(ip).wrapping_add(1))
}

fn has_next_addr_v4(ip: Ipv4Addr, pl: u8) -> bool {
    let cur = u32::from(ip);
    if cur == u32::MAX {
        return false;
    }
    let next = cur + 1;
    let mask = if pl == 0 {
        0u32
    } else {
        !((1u32 << (32 - pl.min(32))) - 1)
    };
    (cur & mask) == (next & mask)
}

fn has_next_addr_v6(ip: Ipv6Addr, pl: u8) -> bool {
    let cur = u128::from(ip);
    if cur == u128::MAX {
        return false;
    }
    let next = cur + 1;
    let mask = if pl == 0 {
        0u128
    } else {
        !((1u128 << (128 - pl.min(128))) - 1)
    };
    (cur & mask) == (next & mask)
}

#[allow(dead_code)]
fn warn_once(msg: &str) {
    warn!("{msg}");
}
