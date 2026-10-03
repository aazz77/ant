//! auto-route / strict-route via **rtnetlink** (Linux) + netsh (Windows).
//! Rule topology follows sing-tun NativeTun.rules().

use crate::config::TunConfig;
use crate::tun::marks::{
    TunMarks, DEFAULT_FALLBACK_RULE_PRIORITY, DEFAULT_RULE_PRIORITY, DEFAULT_TABLE,
};
use anyhow::{Context, Result};
use std::net::{Ipv4Addr, Ipv6Addr};
use tracing::{info, warn};

pub struct RouteGuard {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    linux: Option<LinuxInstalled>,
    #[cfg(target_os = "windows")]
    win: Vec<(bool, String, String)>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
struct LinuxInstalled {
    if_index: u32,
    table: u32,
    routes: Vec<(bool, String)>, // v6, dest CIDR
    /// (priority, family_v6) for rule del by priority
    rules: Vec<(u32, bool)>,
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            if let Some(ref inst) = self.linux {
                // Best-effort sync cleanup via `ip` so Drop stays sync/reliable on exit.
                for (v6, dest) in &inst.routes {
                    let fam = if *v6 { "-6" } else { "-4" };
                    let _ = std::process::Command::new("ip")
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
                    let mut cmd = std::process::Command::new("ip");
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
                let _ = std::process::Command::new("netsh")
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
            let _: std::net::IpAddr = ip.parse().context("route-address")?;
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
    use netlink_packet_route::rule::{RuleAction, RuleAttribute};
    use rtnetlink::new_connection;

    let (conn, handle, _) = new_connection().context("rtnetlink connect")?;
    tokio::spawn(conn);

    // Resolve interface index
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

    // --- routes in dedicated table ---
    for (dest, v6) in pfx {
        if *v6 && !has_v6 {
            continue;
        }
        if !*v6 && !has_v4 {
            continue;
        }
        if let Err(e) = add_route(&handle, if_index, table, dest, *v6).await {
            warn!(dest = %dest, err = %e, "rtnetlink route add failed");
        } else {
            installed.routes.push((*v6, dest.clone()));
        }
    }

    // --- rules ---
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
        add_rules_classic(
            &handle,
            if_name,
            cfg,
            marks,
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
        output_mark = format!("0x{:x}", marks.output),
        input_mark = format!("0x{:x}", marks.input),
        routes = installed.routes.len(),
        rules = installed.rules.len(),
        "tun: auto-route via rtnetlink"
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
            .map_err(|e| anyhow::anyhow!("route add {dest}: {e}"))?;
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
            .map_err(|e| anyhow::anyhow!("route add {dest}: {e}"))?;
    }
    Ok(())
}

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
        // output mark → goto prio+2
        {
            let prio = prio4;
            let mut req = handle.rule().add().v4().priority(prio).fw_mark(marks.output);
            // Goto via action + attribute
            req = req.action(RuleAction::Goto);
            {
                
                req.message_mut()
                    .attributes
                    .push(RuleAttribute::Goto(prio + 2));
            }
            match req.execute().await {
                Ok(()) => inst.rules.push((prio, false)),
                Err(e) => warn!(prio, err = %e, "rule4 goto failed"),
            }
        }
        prio4 += 1;
        // input mark → TUN table
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
                Err(e) => warn!(prio, err = %e, "rule4 input mark failed"),
            }
        }
        prio4 += 1;
        // nop
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
                Err(e) => warn!(prio, err = %e, "rule4 nop failed"),
            }
        }
    }
    if has_v6 {
        {
            let prio = prio6;
            let mut req = handle.rule().add().v6().priority(prio).fw_mark(marks.output);
            req = req.action(RuleAction::Goto);
            {
                
                req.message_mut()
                    .attributes
                    .push(RuleAttribute::Goto(prio + 2));
            }
            match req.execute().await {
                Ok(()) => inst.rules.push((prio, true)),
                Err(e) => warn!(prio, err = %e, "rule6 goto failed"),
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
                Err(e) => warn!(prio, err = %e, "rule6 input mark failed"),
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
                Err(e) => warn!(prio, err = %e, "rule6 nop failed"),
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
            Err(e) => warn!(err = %e, "fallback rule4 failed"),
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
            Err(e) => warn!(err = %e, "fallback rule6 failed"),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
async fn add_rules_classic(
    handle: &rtnetlink::Handle,
    if_name: &str,
    cfg: &TunConfig,
    marks: TunMarks,
    has_v4: bool,
    has_v6: bool,
    table: u32,
    rule_start: u32,
    inst: &mut LinuxInstalled,
) {
    use netlink_packet_route::rule::{RuleAction, RuleAttribute};

    let nop = rule_start + 10;
    let mut prio4 = rule_start;
    let mut prio6 = rule_start;

    // exclude → main
    for cidr in &cfg.route_exclude_address {
        let prio = rule_start.saturating_sub(5);
        if let Ok((ip, pl)) = parse_v4_cidr(cidr) {
            match handle
                .rule()
                .add()
                .v4()
                .priority(prio)
                .destination_prefix(ip, pl)
                .table_id(254) // main
                .action(RuleAction::ToTable)
                .execute()
                .await
            {
                Ok(()) => inst.rules.push((prio, false)),
                Err(e) => warn!(cidr, err = %e, "exclude rule failed"),
            }
        }
    }

    // output mark → main
    if marks.output != 0 {
        if has_v4 {
            let prio = prio4;
            match handle
                .rule()
                .add()
                .v4()
                .priority(prio)
                .fw_mark(marks.output)
                .table_id(254)
                .action(RuleAction::ToTable)
                .execute()
                .await
            {
                Ok(()) => inst.rules.push((prio, false)),
                Err(e) => warn!(err = %e, "mark→main v4 failed"),
            }
            prio4 += 1;
        }
        if has_v6 {
            let prio = prio6;
            match handle
                .rule()
                .add()
                .v6()
                .priority(prio)
                .fw_mark(marks.output)
                .table_id(254)
                .action(RuleAction::ToTable)
                .execute()
                .await
            {
                Ok(()) => inst.rules.push((prio, true)),
                Err(e) => warn!(err = %e, "mark→main v6 failed"),
            }
            prio6 += 1;
        }
    }

    // iif TUN → nop (goto)
    if has_v4 {
        let prio = prio4;
        let mut req = handle
            .rule()
            .add()
            .v4()
            .priority(prio)
            .input_interface(if_name.to_string())
            .action(RuleAction::Goto);
        {
            
            req.message_mut()
                .attributes
                .push(RuleAttribute::Goto(nop));
        }
        match req.execute().await {
            Ok(()) => inst.rules.push((prio, false)),
            Err(e) => warn!(err = %e, "iif tun goto failed"),
        }
        prio4 += 1;

        // not iif lo → table TUN  (approximate: all non-lo by installing catch-all after lo-specific)
        // Catch-all to TUN table
        let prio = prio4;
        match handle
            .rule()
            .add()
            .v4()
            .priority(prio)
            .table_id(table)
            .action(RuleAction::ToTable)
            .execute()
            .await
        {
            Ok(()) => inst.rules.push((prio, false)),
            Err(e) => warn!(err = %e, "catch-all→tun failed"),
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
        {
            
            req.message_mut()
                .attributes
                .push(RuleAttribute::Goto(nop));
        }
        match req.execute().await {
            Ok(()) => inst.rules.push((prio, true)),
            Err(e) => warn!(err = %e, "iif tun goto6 failed"),
        }
        prio6 += 1;
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
            Err(e) => warn!(err = %e, "catch-all→tun6 failed"),
        }
        prio6 += 1;
    }

    if cfg.strict_route {
        if !has_v4 {
            let prio = prio4;
            match handle
                .rule()
                .add()
                .v4()
                .priority(prio)
                .action(RuleAction::Unreachable)
                .execute()
                .await
            {
                Ok(()) => inst.rules.push((prio, false)),
                Err(e) => warn!(err = %e, "strict unreachable v4 failed"),
            }
        }
        if !has_v6 {
            let prio = prio6;
            match handle
                .rule()
                .add()
                .v6()
                .priority(prio)
                .action(RuleAction::Unreachable)
                .execute()
                .await
            {
                Ok(()) => inst.rules.push((prio, true)),
                Err(e) => warn!(err = %e, "strict unreachable v6 failed"),
            }
        }
        info!("tun: strict-route (rtnetlink unreachable)");
    }

    // nop anchors
    if has_v4 {
        match handle
            .rule()
            .add()
            .v4()
            .priority(nop)
            .action(RuleAction::Unspec)
            .execute()
            .await
        {
            Ok(()) => inst.rules.push((nop, false)),
            Err(e) => warn!(err = %e, "nop4 failed"),
        }
    }
    if has_v6 {
        match handle
            .rule()
            .add()
            .v6()
            .priority(nop)
            .action(RuleAction::Unspec)
            .execute()
            .await
        {
            Ok(()) => inst.rules.push((nop, true)),
            Err(e) => warn!(err = %e, "nop6 failed"),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn parse_v4_cidr(s: &str) -> Result<(Ipv4Addr, u8)> {
    let (ip, pl) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("cidr"))?;
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
        let st = std::process::Command::new("netsh")
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
