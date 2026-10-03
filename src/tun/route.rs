//! auto-route / strict-route — **faithful port of sing-tun NativeTun.rules()**.
//!
//! Classic mode (no auto-redirect) uses the mihomo topology that keeps the host
//! reachable without ESTABLISHED hacks:
//!
//! 1. non-DNS → lookup main with suppress_prefixlength 0 (skip default routes)
//! 2. iif TUN → nop
//! 3. **not iif lo** → TUN table   (forwarded only; local SSH replies stay local)
//! 4. iif lo from 0.0.0.0/32 → TUN (unbound local clients)
//! 5. iif lo from <tun-addrs> → TUN
//! 6. fall through → main (bound local replies e.g. SSH)
//!
//! AutoRedirectMarkMode uses dual fwmark like sing-tun.

use crate::config::TunConfig;
use crate::tun::marks::{
    TunMarks, DEFAULT_FALLBACK_RULE_PRIORITY, DEFAULT_RULE_PRIORITY, DEFAULT_TABLE,
};
use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use tracing::{info, warn};

pub struct RouteGuard {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    linux: Option<LinuxInstalled>,
    #[cfg(target_os = "windows")]
    win: Vec<(bool, String, String)>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
struct LinuxInstalled {
    #[allow(dead_code)]
    if_index: u32,
    table: u32,
    routes: Vec<(bool, String)>,
    rules: Vec<(u32, bool)>,
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            if let Some(ref inst) = self.linux {
                for (v6, dest) in &inst.routes {
                    let fam = if *v6 { "-6" } else { "-4" };
                    let _ = Command::new("ip")
                        .args([
                            fam,
                            "route",
                            "del",
                            dest,
                            "table",
                            &inst.table.to_string(),
                        ])
                        .output();
                }
                for (prio, v6) in &inst.rules {
                    let mut cmd = Command::new("ip");
                    if *v6 {
                        cmd.arg("-6");
                    } else {
                        cmd.arg("-4");
                    }
                    let _ = cmd
                        .args(["rule", "del", "priority", &prio.to_string()])
                        .output();
                }
            }
        }
        #[cfg(target_os = "windows")]
        {
            for (v6, dest, if_name) in &self.win {
                let family = if *v6 { "ipv6" } else { "ipv4" };
                let _ = Command::new("netsh")
                    .args([
                        "interface",
                        family,
                        "delete",
                        "route",
                        dest,
                        &format!("interface={if_name}"),
                    ])
                    .output();
            }
        }
        info!("tun: auto-route cleaned up");
    }
}

fn prefixes(cfg: &TunConfig) -> Result<Vec<(String, bool)>> {
    let mut out = Vec::new();
    if cfg.route_address.is_empty() {
        for (s, v6) in [
            ("0.0.0.0/1", false),
            ("128.0.0.0/1", false),
            ("::/1", true),
            ("8000::/1", true),
        ] {
            if !cfg.route_exclude_address.iter().any(|e| e == s) {
                out.push((s.into(), v6));
            }
        }
    } else {
        for s in &cfg.route_address {
            if cfg.route_exclude_address.iter().any(|e| e == s) {
                continue;
            }
            let (ip, pl) = s
                .split_once('/')
                .ok_or_else(|| anyhow::anyhow!("route-address CIDR required: {s}"))?;
            let _: IpAddr = ip.parse().context("route-address")?;
            let pl: u8 = pl.parse().context("prefix")?;
            let v6 = s.contains(':');
            if pl > if v6 { 128 } else { 32 } {
                anyhow::bail!("bad prefix {pl}");
            }
            out.push((s.clone(), v6));
        }
    }
    Ok(out)
}

/// Parse TUN interface address CIDRs from config for lo-src rules.
fn tun_address_prefixes(cfg: &TunConfig) -> (Vec<(Ipv4Addr, u8)>, Vec<(Ipv6Addr, u8)>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for s in &cfg.address {
        let Some((ip_s, pl_s)) = s.split_once('/') else {
            continue;
        };
        let Ok(pl) = pl_s.parse::<u8>() else {
            continue;
        };
        if let Ok(ip) = ip_s.parse::<Ipv4Addr>() {
            // Masked network like sing-tun address.Masked()
            let mask = if pl == 0 {
                0u32
            } else {
                !0u32 << (32 - pl)
            };
            let net = Ipv4Addr::from(u32::from(ip) & mask);
            v4.push((net, pl));
            v4.push((ip, 32)); // also host address
        } else if let Ok(ip) = ip_s.parse::<Ipv6Addr>() {
            v6.push((ip, pl.min(128)));
        }
    }
    (v4, v6)
}

#[allow(clippy::needless_return)]
pub async fn install_routes(
    if_name: &str,
    cfg: &TunConfig,
    marks: TunMarks,
    has_v4: bool,
    has_v6: bool,
) -> Result<RouteGuard> {
    let pfx = prefixes(cfg)?;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let linux = install_linux(if_name, cfg, marks, has_v4, has_v6, &pfx).await?;
        return Ok(RouteGuard { linux: Some(linux) });
    }

    #[cfg(target_os = "windows")]
    {
        let _ = (marks, has_v4, has_v6);
        let win = install_windows(if_name, cfg, &pfx)?;
        return Ok(RouteGuard { win });
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "windows"
    )))]
    {
        let _ = (if_name, cfg, marks, has_v4, has_v6, pfx);
        Ok(RouteGuard {})
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
async fn install_linux(
    if_name: &str,
    cfg: &TunConfig,
    marks: TunMarks,
    has_v4: bool,
    has_v6: bool,
    pfx: &[(String, bool)],
) -> Result<LinuxInstalled> {
    use futures::stream::TryStreamExt;
    use rtnetlink::new_connection;

    let (conn, handle, _) = new_connection().context("rtnetlink connect")?;
    tokio::spawn(conn);

    let mut links = handle.link().get().match_name(if_name.to_string()).execute();
    let link = links
        .try_next()
        .await
        .context("link get")?
        .ok_or_else(|| anyhow::anyhow!("interface {if_name} not found"))?;
    let if_index = link.header.index;

    let table = if cfg.iproute2_table_index != 0 {
        cfg.iproute2_table_index as u32
    } else {
        DEFAULT_TABLE as u32
    };
    let rule_start = if cfg.iproute2_rule_index != 0 {
        cfg.iproute2_rule_index as u32
    } else {
        DEFAULT_RULE_PRIORITY as u32
    };

    let mut installed = LinuxInstalled {
        if_index,
        table,
        routes: Vec::new(),
        rules: Vec::new(),
    };

    for (dest, v6) in pfx {
        if (*v6 && !has_v6) || (!*v6 && !has_v4) {
            continue;
        }
        match add_route(&handle, if_index, table, dest, *v6).await {
            Ok(()) => installed.routes.push((*v6, dest.clone())),
            Err(e) => warn!(dest = %dest, err = %e, "route add failed"),
        }
    }

    if marks.redirect_mode {
        add_rules_redirect_mark(
            &handle,
            marks,
            has_v4,
            has_v6,
            table,
            rule_start,
            &mut installed,
        )
        .await;
    } else {
        add_rules_classic_mihomo(
            &handle,
            if_name,
            cfg,
            has_v4,
            has_v6,
            table,
            rule_start,
            &mut installed,
        )
        .await;
    }

    info!(
        interface = %if_name,
        if_index,
        table,
        redirect_mode = marks.redirect_mode,
        routes = installed.routes.len(),
        rules = installed.rules.len(),
        "tun: auto-route installed (sing-tun / mihomo topology)"
    );
    Ok(installed)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
async fn add_route(
    handle: &rtnetlink::Handle,
    if_index: u32,
    table: u32,
    dest: &str,
    v6: bool,
) -> Result<()> {
    let (ip_s, pl_s) = dest
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("bad CIDR {dest}"))?;
    let pl: u8 = pl_s.parse()?;
    if v6 {
        let ip: Ipv6Addr = ip_s.parse()?;
        handle
            .route()
            .add()
            .v6()
            .destination_prefix(ip, pl)
            .output_interface(if_index)
            .table_id(table)
            .execute()
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    } else {
        let ip: Ipv4Addr = ip_s.parse()?;
        handle
            .route()
            .add()
            .v4()
            .destination_prefix(ip, pl)
            .output_interface(if_index)
            .table_id(table)
            .execute()
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    Ok(())
}

/// sing-tun AutoRedirectMarkMode
#[cfg(any(target_os = "linux", target_os = "android"))]
async fn add_rules_redirect_mark(
    handle: &rtnetlink::Handle,
    marks: TunMarks,
    has_v4: bool,
    has_v6: bool,
    table: u32,
    rule_start: u32,
    inst: &mut LinuxInstalled,
) {
    use netlink_packet_route::rule::{RuleAction, RuleAttribute};

    let mut prio4 = rule_start;
    let mut prio6 = rule_start;

    if has_v4 {
        // output mark → goto +2
        {
            let prio = prio4;
            let mut req = handle
                .rule()
                .add()
                .v4()
                .priority(prio)
                .fw_mark(marks.output)
                .action(RuleAction::Goto);
            req.message_mut()
                .attributes
                .push(RuleAttribute::Goto(prio + 2));
            match req.execute().await {
                Ok(()) => inst.rules.push((prio, false)),
                Err(e) => warn!(err = %e, "v4 output goto"),
            }
        }
        prio4 += 1;
        // input mark → TUN
        {
            let prio = prio4;
            match handle
                .rule()
                .add()
                .v4()
                .priority(prio)
                .fw_mark(marks.input)
                .table_id(table)
                .action(RuleAction::ToTable)
                .execute()
                .await
            {
                Ok(()) => inst.rules.push((prio, false)),
                Err(e) => warn!(err = %e, "v4 input→tun"),
            }
        }
        prio4 += 1;
        // empty / nop separator
        {
            let prio = prio4;
            match handle
                .rule()
                .add()
                .v4()
                .priority(prio)
                .action(RuleAction::Unspec)
                .execute()
                .await
            {
                Ok(()) => inst.rules.push((prio, false)),
                Err(e) => warn!(err = %e, "v4 nop"),
            }
        }
    }
    if has_v6 {
        {
            let prio = prio6;
            let mut req = handle
                .rule()
                .add()
                .v6()
                .priority(prio)
                .fw_mark(marks.output)
                .action(RuleAction::Goto);
            req.message_mut()
                .attributes
                .push(RuleAttribute::Goto(prio + 2));
            match req.execute().await {
                Ok(()) => inst.rules.push((prio, true)),
                Err(e) => warn!(err = %e, "v6 output goto"),
            }
        }
        prio6 += 1;
        {
            let prio = prio6;
            match handle
                .rule()
                .add()
                .v6()
                .priority(prio)
                .fw_mark(marks.input)
                .table_id(table)
                .action(RuleAction::ToTable)
                .execute()
                .await
            {
                Ok(()) => inst.rules.push((prio, true)),
                Err(e) => warn!(err = %e, "v6 input→tun"),
            }
        }
        prio6 += 1;
        {
            let prio = prio6;
            match handle
                .rule()
                .add()
                .v6()
                .priority(prio)
                .action(RuleAction::Unspec)
                .execute()
                .await
            {
                Ok(()) => inst.rules.push((prio, true)),
                Err(e) => warn!(err = %e, "v6 nop"),
            }
        }
    }

    let fb = DEFAULT_FALLBACK_RULE_PRIORITY as u32;
    if has_v4 {
        match handle
            .rule()
            .add()
            .v4()
            .priority(fb)
            .table_id(table)
            .action(RuleAction::ToTable)
            .execute()
            .await
        {
            Ok(()) => inst.rules.push((fb, false)),
            Err(e) => warn!(err = %e, "fallback v4"),
        }
    }
    if has_v6 {
        match handle
            .rule()
            .add()
            .v6()
            .priority(fb)
            .table_id(table)
            .action(RuleAction::ToTable)
            .execute()
            .await
        {
            Ok(()) => inst.rules.push((fb, true)),
            Err(e) => warn!(err = %e, "fallback v6"),
        }
    }
}

/// Classic auto-route — full sing-tun / mihomo topology (non-Android).
#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(clippy::too_many_arguments)]
async fn add_rules_classic_mihomo(
    handle: &rtnetlink::Handle,
    if_name: &str,
    cfg: &TunConfig,
    has_v4: bool,
    has_v6: bool,
    table: u32,
    rule_start: u32,
    inst: &mut LinuxInstalled,
) {
    use netlink_packet_route::rule::{
        RuleAction, RuleAttribute, RuleFlag, RulePortRange,
    };

    let nop = rule_start + 10;
    let mut prio4 = rule_start;
    let mut prio6 = rule_start;
    let (tun_v4, tun_v6) = tun_address_prefixes(cfg);

    // --- strict-route: unreachable for missing family ---
    if cfg.strict_route {
        if !has_v4 {
            match handle
                .rule()
                .add()
                .v4()
                .priority(prio4)
                .action(RuleAction::Unreachable)
                .execute()
                .await
            {
                Ok(()) => inst.rules.push((prio4, false)),
                Err(e) => warn!(err = %e, "strict v4"),
            }
            prio4 += 1;
        }
        if !has_v6 {
            match handle
                .rule()
                .add()
                .v6()
                .priority(prio6)
                .action(RuleAction::Unreachable)
                .execute()
                .await
            {
                Ok(()) => inst.rules.push((prio6, true)),
                Err(e) => warn!(err = %e, "strict v6"),
            }
            prio6 += 1;
        }
    }

    // --- dst = tun addresses → TUN table ---
    if has_v4 {
        for (ip, pl) in &tun_v4 {
            match handle
                .rule()
                .add()
                .v4()
                .priority(prio4)
                .destination_prefix(*ip, *pl)
                .table_id(table)
                .action(RuleAction::ToTable)
                .execute()
                .await
            {
                Ok(()) => inst.rules.push((prio4, false)),
                Err(e) => warn!(err = %e, "dst tun v4"),
            }
        }
        prio4 += 1;
    }

    // --- invert dport 53, table main, suppress_prefixlength 0 ---
    // Non-DNS: try main without default routes; DNS skips this rule.
    if has_v4 {
        let prio = prio4;
        let mut req = handle
            .rule()
            .add()
            .v4()
            .priority(prio)
            .table_id(254)
            .action(RuleAction::ToTable);
        {
            let msg = req.message_mut();
            msg.header.flags.push(RuleFlag::Invert);
            msg.attributes.push(RuleAttribute::DestinationPortRange(
                RulePortRange {
                    start: 53,
                    end: 53,
                },
            ));
            msg.attributes
                .push(RuleAttribute::SuppressPrefixLen(0));
        }
        match req.execute().await {
            Ok(()) => inst.rules.push((prio, false)),
            Err(e) => warn!(err = %e, "suppress dns v4"),
        }
        prio4 += 1;
    }
    if has_v6 {
        let prio = prio6;
        let mut req = handle
            .rule()
            .add()
            .v6()
            .priority(prio)
            .table_id(254)
            .action(RuleAction::ToTable);
        {
            let msg = req.message_mut();
            msg.header.flags.push(RuleFlag::Invert);
            msg.attributes.push(RuleAttribute::DestinationPortRange(
                RulePortRange {
                    start: 53,
                    end: 53,
                },
            ));
            msg.attributes
                .push(RuleAttribute::SuppressPrefixLen(0));
        }
        match req.execute().await {
            Ok(()) => inst.rules.push((prio, true)),
            Err(e) => warn!(err = %e, "suppress dns v6"),
        }
        prio6 += 1;
    }

    // --- iif TUN → goto nop ---
    if has_v4 {
        let prio = prio4;
        let mut req = handle
            .rule()
            .add()
            .v4()
            .priority(prio)
            .input_interface(if_name.to_string())
            .action(RuleAction::Goto);
        req.message_mut()
            .attributes
            .push(RuleAttribute::Goto(nop));
        match req.execute().await {
            Ok(()) => inst.rules.push((prio, false)),
            Err(e) => warn!(err = %e, "iif tun v4"),
        }
        prio4 += 1;
    }
    if has_v6 {
        let prio = prio6;
        let mut req = handle
            .rule()
            .add()
            .v6()
            .priority(prio)
            .input_interface(if_name.to_string())
            .action(RuleAction::Goto);
        req.message_mut()
            .attributes
            .push(RuleAttribute::Goto(nop));
        match req.execute().await {
            Ok(()) => inst.rules.push((prio, true)),
            Err(e) => warn!(err = %e, "iif tun v6"),
        }
        prio6 += 1;
    }

    // --- not iif lo → TUN table  (FORWARDED only; local SSH replies are iif=lo) ---
    if has_v4 {
        let prio = prio4;
        let mut req = handle
            .rule()
            .add()
            .v4()
            .priority(prio)
            .input_interface("lo".into())
            .table_id(table)
            .action(RuleAction::ToTable);
        req.message_mut()
            .header
            .flags
            .push(RuleFlag::Invert);
        match req.execute().await {
            Ok(()) => inst.rules.push((prio, false)),
            Err(e) => warn!(err = %e, "not iif lo v4"),
        }
        // same priority for lo-src rules below (sing-tun shares priority)
    }
    if has_v6 {
        let prio = prio6;
        let mut req = handle
            .rule()
            .add()
            .v6()
            .priority(prio)
            .input_interface("lo".into())
            .table_id(table)
            .action(RuleAction::ToTable);
        req.message_mut()
            .header
            .flags
            .push(RuleFlag::Invert);
        match req.execute().await {
            Ok(()) => inst.rules.push((prio, true)),
            Err(e) => warn!(err = %e, "not iif lo v6"),
        }
    }

    // --- iif lo from 0.0.0.0/32 → TUN ---
    if has_v4 {
        let prio = prio4;
        match handle
            .rule()
            .add()
            .v4()
            .priority(prio)
            .input_interface("lo".into())
            .source_prefix(Ipv4Addr::UNSPECIFIED, 32)
            .table_id(table)
            .action(RuleAction::ToTable)
            .execute()
            .await
        {
            Ok(()) => inst.rules.push((prio, false)),
            Err(e) => warn!(err = %e, "lo from 0.0.0.0/32"),
        }
        // --- iif lo from tun addresses → TUN ---
        for (ip, pl) in &tun_v4 {
            match handle
                .rule()
                .add()
                .v4()
                .priority(prio)
                .input_interface("lo".into())
                .source_prefix(*ip, *pl)
                .table_id(table)
                .action(RuleAction::ToTable)
                .execute()
                .await
            {
                Ok(()) => inst.rules.push((prio, false)),
                Err(e) => warn!(err = %e, "lo from tun v4"),
            }
        }
        prio4 += 1;
    }

    if has_v6 {
        // iif lo from ::/1 and 8000::/1 → goto nop (sing-tun)
        for (ip, pl) in [
            (Ipv6Addr::UNSPECIFIED, 1u8),
            (Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0), 1u8),
        ] {
            let prio = prio6;
            let mut req = handle
                .rule()
                .add()
                .v6()
                .priority(prio)
                .input_interface("lo".into())
                .source_prefix(ip, pl)
                .action(RuleAction::Goto);
            req.message_mut()
                .attributes
                .push(RuleAttribute::Goto(nop));
            match req.execute().await {
                Ok(()) => inst.rules.push((prio, true)),
                Err(e) => warn!(err = %e, "lo from v6 half"),
            }
        }
        prio6 += 1;
        for (ip, pl) in &tun_v6 {
            let prio = prio6;
            match handle
                .rule()
                .add()
                .v6()
                .priority(prio)
                .input_interface("lo".into())
                .source_prefix(*ip, *pl)
                .table_id(table)
                .action(RuleAction::ToTable)
                .execute()
                .await
            {
                Ok(()) => inst.rules.push((prio, true)),
                Err(e) => warn!(err = %e, "lo from tun v6"),
            }
        }
        prio6 += 1;
        // v6 catch-all → TUN (sing-tun has this for v6 only)
        {
            let prio = prio6;
            match handle
                .rule()
                .add()
                .v6()
                .priority(prio)
                .table_id(table)
                .action(RuleAction::ToTable)
                .execute()
                .await
            {
                Ok(()) => inst.rules.push((prio, true)),
                Err(e) => warn!(err = %e, "v6 catch-all"),
            }
        }
    }

    // --- user route-exclude → main (higher priority than rule_start) ---
    let ex_prio = rule_start.saturating_sub(5);
    for s in &cfg.route_exclude_address {
        if let Ok((ip, pl)) = parse_v4_cidr(s) {
            match handle
                .rule()
                .add()
                .v4()
                .priority(ex_prio)
                .destination_prefix(ip, pl)
                .table_id(254)
                .action(RuleAction::ToTable)
                .execute()
                .await
            {
                Ok(()) => inst.rules.push((ex_prio, false)),
                Err(e) => warn!(err = %e, "exclude"),
            }
        }
    }

    // --- nop anchors ---
    if has_v4 {
        match handle
            .rule()
            .add()
            .v4()
            .priority(nop)
            .action(RuleAction::Nop)
            .execute()
            .await
        {
            Ok(()) => inst.rules.push((nop, false)),
            Err(e) => warn!(err = %e, "nop4"),
        }
    }
    if has_v6 {
        match handle
            .rule()
            .add()
            .v6()
            .priority(nop)
            .action(RuleAction::Nop)
            .execute()
            .await
        {
            Ok(()) => inst.rules.push((nop, true)),
            Err(e) => warn!(err = %e, "nop6"),
        }
    }

    let _ = prio4;
    let _ = prio6;
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn parse_v4_cidr(s: &str) -> Result<(Ipv4Addr, u8)> {
    let (ip, pl) = s.split_once('/').ok_or_else(|| anyhow::anyhow!("cidr"))?;
    Ok((ip.parse()?, pl.parse()?))
}

#[cfg(target_os = "windows")]
fn install_windows(
    if_name: &str,
    cfg: &TunConfig,
    pfx: &[(String, bool)],
) -> Result<Vec<(bool, String, String)>> {
    let mut win = Vec::new();
    for (dest, v6) in pfx {
        let family = if *v6 { "ipv6" } else { "ipv4" };
        let st = Command::new("netsh")
            .args([
                "interface",
                family,
                "add",
                "route",
                dest,
                &format!("interface={if_name}"),
            ])
            .status();
        if st.map(|s| s.success()).unwrap_or(false) {
            win.push((*v6, dest.clone(), if_name.into()));
        }
    }
    if cfg.strict_route {
        info!("tun: strict-route Windows best-effort");
    }
    info!(interface = %if_name, "tun: auto-route (netsh)");
    Ok(win)
}
