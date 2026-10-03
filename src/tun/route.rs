//! auto-route / strict-route (Linux + Windows).
//!
//! Installs split-default (or custom) routes into the TUN device and optional
//! policy-routing so fwmark-ed proxy traffic stays on the main table.

use crate::config::TunConfig;
use anyhow::{Context, Result};
use std::process::Command;
use tracing::{info, warn};

/// RAII guard: removes installed routes/rules on drop.
pub struct RouteGuard {
    cleanup: Vec<CleanupAction>,
}

enum CleanupAction {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    LinuxRoute {
        v6: bool,
        dest: String,
        dev: String,
        table: Option<i32>,
    },
    #[cfg(any(target_os = "linux", target_os = "android"))]
    LinuxRule { args: Vec<String> },
    #[cfg(target_os = "windows")]
    WinRoute {
        v6: bool,
        dest: String,
        if_name: String,
    },
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        while let Some(action) = self.cleanup.pop() {
            match action {
                #[cfg(any(target_os = "linux", target_os = "android"))]
                CleanupAction::LinuxRoute {
                    v6,
                    dest,
                    dev,
                    table,
                } => {
                    let mut args: Vec<String> = vec![
                        if v6 { "-6".into() } else { "-4".into() },
                        "route".into(),
                        "del".into(),
                        dest,
                        "dev".into(),
                        dev,
                    ];
                    if let Some(t) = table {
                        args.push("table".into());
                        args.push(t.to_string());
                    }
                    let r: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                    run_ip(&r);
                }
                #[cfg(any(target_os = "linux", target_os = "android"))]
                CleanupAction::LinuxRule { args } => {
                    let mut full = vec!["rule".to_string(), "del".to_string()];
                    full.extend(args);
                    let r: Vec<&str> = full.iter().map(|s| s.as_str()).collect();
                    run_ip(&r);
                }
                #[cfg(target_os = "windows")]
                CleanupAction::WinRoute { v6, dest, if_name } => {
                    let family = if v6 { "ipv6" } else { "ipv4" };
                    run_cmd(
                        "netsh",
                        &[
                            "interface",
                            family,
                            "delete",
                            "route",
                            &dest,
                            &format!("interface={if_name}"),
                        ],
                    );
                }
            }
        }
        info!("tun: auto-route cleaned up");
    }
}

fn route_prefixes(cfg: &TunConfig) -> Result<Vec<(String, bool)>> {
    let mut out = Vec::new();
    if cfg.route_address.is_empty() {
        for (s, v6) in [
            ("0.0.0.0/1", false),
            ("128.0.0.0/1", false),
            ("::/1", true),
            ("8000::/1", true),
        ] {
            if !cfg.route_exclude_address.iter().any(|e| e == s) {
                out.push((s.to_string(), v6));
            }
        }
    } else {
        for s in &cfg.route_address {
            if cfg.route_exclude_address.iter().any(|e| e == s) {
                continue;
            }
            let (ip_s, pl_s) = s
                .split_once('/')
                .ok_or_else(|| anyhow::anyhow!("route-address: expected CIDR, got `{s}`"))?;
            let _: std::net::IpAddr = ip_s.parse().context("route-address IP")?;
            let pl: u8 = pl_s.parse().context("route-address prefix")?;
            let v6 = s.contains(':');
            let max = if v6 { 128 } else { 32 };
            if pl > max {
                anyhow::bail!("route-address prefix {pl} > {max}");
            }
            out.push((s.clone(), v6));
        }
    }
    Ok(out)
}

/// Install routes according to `cfg`. Returns a guard that undoes them on drop.
pub fn install_routes(if_name: &str, cfg: &TunConfig, fwmark: u32) -> Result<RouteGuard> {
    let mut guard = RouteGuard {
        cleanup: Vec::new(),
    };
    let prefixes = route_prefixes(cfg)?;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    install_linux(if_name, cfg, fwmark, &prefixes, &mut guard)?;

    #[cfg(target_os = "windows")]
    {
        let _ = fwmark;
        install_windows(if_name, cfg, &prefixes, &mut guard)?;
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "windows"
    )))]
    {
        let _ = (if_name, cfg, fwmark, &prefixes);
        warn!("tun: auto-route not supported on this platform");
    }

    Ok(guard)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn install_linux(
    if_name: &str,
    cfg: &TunConfig,
    fwmark: u32,
    prefixes: &[(String, bool)],
    guard: &mut RouteGuard,
) -> Result<()> {
    let table = cfg.iproute2_table_index;
    let rule_prio = cfg.iproute2_rule_index;
    let use_table = fwmark != 0;
    let table_opt = if use_table { Some(table) } else { None };

    for (dest, v6) in prefixes {
        let mut args: Vec<String> = vec![
            if *v6 { "-6".into() } else { "-4".into() },
            "route".into(),
            "replace".into(),
            dest.clone(),
            "dev".into(),
            if_name.into(),
        ];
        if let Some(t) = table_opt {
            args.push("table".into());
            args.push(t.to_string());
        }
        let r: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        run_ip(&r);
        guard.cleanup.push(CleanupAction::LinuxRoute {
            v6: *v6,
            dest: dest.clone(),
            dev: if_name.into(),
            table: table_opt,
        });
    }

    if use_table {
        let rule_not = vec![
            "not".into(),
            "fwmark".into(),
            fwmark.to_string(),
            "table".into(),
            table.to_string(),
            "priority".into(),
            rule_prio.to_string(),
        ];
        {
            let mut full = vec!["rule".into(), "add".into()];
            full.extend(rule_not.iter().cloned());
            let r: Vec<&str> = full.iter().map(|s| s.as_str()).collect();
            run_ip(&r);
        }
        guard.cleanup.push(CleanupAction::LinuxRule {
            args: rule_not,
        });

        let rule_mark = vec![
            "fwmark".into(),
            fwmark.to_string(),
            "table".into(),
            "main".into(),
            "priority".into(),
            (rule_prio - 1).to_string(),
        ];
        {
            let mut full = vec!["rule".into(), "add".into()];
            full.extend(rule_mark.iter().cloned());
            let r: Vec<&str> = full.iter().map(|s| s.as_str()).collect();
            run_ip(&r);
        }
        guard.cleanup.push(CleanupAction::LinuxRule {
            args: rule_mark,
        });
    }

    if cfg.strict_route {
        for (dest, v6) in [
            ("0.0.0.0/1", false),
            ("128.0.0.0/1", false),
            ("::/1", true),
            ("8000::/1", true),
        ] {
            if prefixes.iter().any(|(d, _)| d == dest) {
                continue;
            }
            let args = [
                if v6 { "-6" } else { "-4" },
                "route",
                "replace",
                dest,
                "dev",
                if_name,
            ];
            run_ip(&args);
            guard.cleanup.push(CleanupAction::LinuxRoute {
                v6,
                dest: dest.into(),
                dev: if_name.into(),
                table: None,
            });
        }
        info!("tun: strict-route enabled");
    }

    info!(
        interface = %if_name,
        table = ?table_opt,
        routes = prefixes.len(),
        "tun: auto-route installed"
    );
    Ok(())
}

#[cfg(target_os = "windows")]
fn install_windows(
    if_name: &str,
    cfg: &TunConfig,
    prefixes: &[(String, bool)],
    guard: &mut RouteGuard,
) -> Result<()> {
    for (dest, v6) in prefixes {
        let family = if *v6 { "ipv6" } else { "ipv4" };
        run_cmd(
            "netsh",
            &[
                "interface",
                family,
                "add",
                "route",
                dest,
                &format!("interface={if_name}"),
            ],
        );
        guard.cleanup.push(CleanupAction::WinRoute {
            v6: *v6,
            dest: dest.clone(),
            if_name: if_name.into(),
        });
    }
    if cfg.strict_route {
        info!("tun: strict-route on Windows is best-effort (split default only)");
    }
    info!(interface = %if_name, routes = prefixes.len(), "tun: auto-route installed");
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn run_ip(args: &[&str]) {
    match Command::new("ip").args(args).output() {
        Ok(out) if out.status.success() => {}
        Ok(out) => warn!(
            cmd = ?args,
            stderr = %String::from_utf8_lossy(&out.stderr).trim(),
            "ip command failed"
        ),
        Err(e) => warn!(cmd = ?args, err = %e, "failed to run ip"),
    }
}

#[cfg(target_os = "windows")]
fn run_cmd(bin: &str, args: &[&str]) {
    match Command::new(bin).args(args).output() {
        Ok(out) if out.status.success() => {}
        Ok(out) => warn!(
            cmd = %bin,
            args = ?args,
            stderr = %String::from_utf8_lossy(&out.stderr).trim(),
            "command failed"
        ),
        Err(e) => warn!(cmd = %bin, err = %e, "failed to run command"),
    }
}
