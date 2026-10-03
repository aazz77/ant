//! auto-route / strict-route via rtnetlink (Linux) + netsh (Windows).
//!
//! Critical for servers: ESTABLISHED/RELATED OUTPUT packets are marked with the
//! outbound fwmark so SSH and other inbound-service replies stay on the main
//! table and are not blackholed into TUN.

use crate::config::TunConfig;
use crate::tun::marks::{
    TunMarks, DEFAULT_FALLBACK_RULE_PRIORITY, DEFAULT_RULE_PRIORITY, DEFAULT_TABLE,
};
use anyhow::{Context, Result};
use std::net::{Ipv4Addr, Ipv6Addr};
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
    output_mark: u32,
    routes: Vec<(bool, String)>,
    /// (priority, is_v6)
    rules: Vec<(u32, bool)>,
    /// mangle OUTPUT ESTABLISHED protect installed
    mangle_protect: bool,
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
                if inst.mangle_protect {
                    remove_established_protect(inst.output_mark);
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

/// Mark ESTABLISHED/RELATED OUTPUT so inbound-service replies (SSH, etc.) use
/// main table via the fwmark→main rule. Without this, replies match
/// "unmarked → TUN" and the host becomes unreachable.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn install_established_protect(mark: u32) -> bool {
    let mark_s = mark.to_string();
    let mut ok = false;
    for bin in ["iptables", "ip6tables"] {
        let st = Command::new(bin)
            .args([
                "-t",
                "mangle",
                "-C",
                "OUTPUT",
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "MARK",
                "--set-mark",
                &mark_s,
            ])
            .status();
        // -C succeeds if rule already exists
        if st.map(|s| s.success()).unwrap_or(false) {
            ok = true;
            continue;
        }
        let st = Command::new(bin)
            .args([
                "-t",
                "mangle",
                "-I",
                "OUTPUT",
                "1",
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "MARK",
                "--set-mark",
                &mark_s,
            ])
            .status();
        if st.map(|s| s.success()).unwrap_or(false) {
            ok = true;
            info!(bin, mark = format!("0x{mark:x}"), "tun: ESTABLISHED/RELATED OUTPUT mark protect");
        } else {
            warn!(bin, "tun: failed to install ESTABLISHED protect — SSH may break");
        }
    }
    ok
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn remove_established_protect(mark: u32) {
    let mark_s = mark.to_string();
    for bin in ["iptables", "ip6tables"] {
        // Delete repeatedly in case duplicates
        for _ in 0..4 {
            let st = Command::new(bin)
                .args([
                    "-t",
                    "mangle",
                    "-D",
                    "OUTPUT",
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "ESTABLISHED,RELATED",
                    "-j",
                    "MARK",
                    "--set-mark",
                    &mark_s,
                ])
                .status();
            if !st.map(|s| s.success()).unwrap_or(false) {
                break;
            }
        }
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
    // Rule priorities: protect (private) < mark→main < unmarked→TUN
    // Leave room below rule_start for protect rules.
    let rule_start = if cfg.iproute2_rule_index != 0 {
        cfg.iproute2_rule_index as u32
    } else {
        DEFAULT_RULE_PRIORITY as u32
    };

    let mut installed = LinuxInstalled {
        if_index,
        table,
        output_mark: marks.output,
        routes: Vec::new(),
        rules: Vec::new(),
        mangle_protect: false,
    };

    // Routes only in dedicated table (never replace main default).
    for (dest, v6) in pfx {
        if *v6 && !has_v6 {
            continue;
        }
        if !*v6 && !has_v4 {
            continue;
        }
        match add_route(&handle, if_index, table, dest, *v6).await {
            Ok(()) => installed.routes.push((*v6, dest.clone())),
            Err(e) => warn!(dest = %dest, err = %e, "rtnetlink route add failed"),
        }
    }

    // MUST run before traffic hits TUN policy: replies get output_mark → main.
    if marks.output != 0 {
        installed.mangle_protect = install_established_protect(marks.output);
        if !installed.mangle_protect {
            warn!(
                "tun: ESTABLISHED protect missing — remote access (SSH) will likely break with auto-route"
            );
        }
    }

    // Private / link-local → main (high priority, below local=0)
    let protect_prio = rule_start.saturating_sub(20);
    add_private_protect_rules(&handle, has_v4, has_v6, protect_prio, cfg, &mut installed).await;

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
            marks,
            has_v4,
            has_v6,
            table,
            rule_start,
            cfg.strict_route,
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
        mangle_protect = installed.mangle_protect,
        routes = installed.routes.len(),
        rules = installed.rules.len(),
        "tun: auto-route installed (SSH replies protected via ESTABLISHED mark)"
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
async fn add_private_protect_rules(
    handle: &rtnetlink::Handle,
    has_v4: bool,
    has_v6: bool,
    prio: u32,
    cfg: &TunConfig,
    inst: &mut LinuxInstalled,
) {
    use netlink_packet_route::rule::RuleAction;

    let mut cidrs_v4: Vec<(Ipv4Addr, u8)> = vec![
        (Ipv4Addr::new(10, 0, 0, 0), 8),
        (Ipv4Addr::new(172, 16, 0, 0), 12),
        (Ipv4Addr::new(192, 168, 0, 0), 16),
        (Ipv4Addr::new(169, 254, 0, 0), 16),
        (Ipv4Addr::new(127, 0, 0, 0), 8),
    ];
    for s in &cfg.route_exclude_address {
        if let Ok((ip, pl)) = parse_v4_cidr(s) {
            cidrs_v4.push((ip, pl));
        }
    }

    if has_v4 {
        for (ip, pl) in cidrs_v4 {
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
                Err(e) => warn!(?ip, pl, err = %e, "protect rule v4 failed"),
            }
        }
    }
    if has_v6 {
        // fc00::/7 ULA, fe80::/10 link-local, ::1/128
        for (ip, pl) in [
            ("fc00::", 7u8),
            ("fe80::", 10u8),
            ("::1", 128u8),
        ] {
            let ip: Ipv6Addr = ip.parse().expect("static");
            match handle
                .rule()
                .add()
                .v6()
                .priority(prio)
                .destination_prefix(ip, pl)
                .table_id(254)
                .action(RuleAction::ToTable)
                .execute()
                .await
            {
                Ok(()) => inst.rules.push((prio, true)),
                Err(e) => warn!(?ip, err = %e, "protect rule v6 failed"),
            }
        }
    }
}

/// Dual-mark topology when auto-redirect is on (sing-tun AutoRedirectMarkMode).
/// Unmarked traffic uses main (32766) first — safer for servers.
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

    // Explicit: output mark → main (proxy dialer, ESTABLISHED replies)
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
            Err(e) => warn!(err = %e, "redirect-mode output→main v4 failed"),
        }
        prio4 += 1;

        // input mark → TUN table
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
            Err(e) => warn!(err = %e, "redirect-mode input→tun v4 failed"),
        }
        prio4 += 1;
        let _ = prio4;
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
            Err(e) => warn!(err = %e, "redirect-mode output→main v6 failed"),
        }
        prio6 += 1;
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
            Err(e) => warn!(err = %e, "redirect-mode input→tun v6 failed"),
        }
        let _ = prio6;
    }

    // Fallback after main/default — only if main has no route
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

    // silence unused import warning if Goto not used in this mode
    let _ = RuleAttribute::Goto(0);
}

/// Classic auto-route (no auto-redirect): unmarked NEW traffic → TUN table;
/// marked (proxy + ESTABLISHED replies) → main.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(clippy::too_many_arguments)]
async fn add_rules_classic(
    handle: &rtnetlink::Handle,
    if_name: &str,
    marks: TunMarks,
    has_v4: bool,
    has_v6: bool,
    table: u32,
    rule_start: u32,
    strict_route: bool,
    inst: &mut LinuxInstalled,
) {
    use netlink_packet_route::rule::{RuleAction, RuleAttribute};

    let nop = rule_start + 10;
    let mut prio4 = rule_start;
    let mut prio6 = rule_start;

    // 1) output mark → main (proxy outbound + ESTABLISHED replies)
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

    // 2) packets arriving from TUN → nop (do not re-apply TUN policy)
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
            Err(e) => warn!(err = %e, "iif tun goto failed"),
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
            Err(e) => warn!(err = %e, "iif tun goto6 failed"),
        }
        prio6 += 1;
    }

    // 3) unmarked → TUN table (client outbound). Replies are marked in step 0 (mangle).
    if has_v4 {
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
            Err(e) => warn!(err = %e, "unmarked→tun v4 failed"),
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
            .table_id(table)
            .action(RuleAction::ToTable)
            .execute()
            .await
        {
            Ok(()) => inst.rules.push((prio, true)),
            Err(e) => warn!(err = %e, "unmarked→tun v6 failed"),
        }
        prio6 += 1;
    }

    if strict_route {
        // Unreachable for disabled family only — do NOT pin 0.0.0.0/1 on main
        // (that is what made the whole host unreachable before).
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
        info!("tun: strict-route (unreachable only, no main-table pin)");
    }

    // nop anchors
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
            Err(e) => warn!(err = %e, "nop4 failed"),
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
