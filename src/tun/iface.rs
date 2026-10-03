//! Default physical interface detection for auto-detect-interface.

use std::sync::RwLock;
use tracing::{info, warn};

static BIND_IFACE: RwLock<Option<String>> = RwLock::new(None);

/// Currently selected outbound bind interface (if any).
pub fn bind_interface() -> Option<String> {
    BIND_IFACE.read().ok().and_then(|g| g.clone())
}

pub fn set_bind_interface(name: Option<String>) {
    if let Ok(mut g) = BIND_IFACE.write() {
        *g = name;
    }
}

/// Detect the current default IPv4 outbound interface name (excluding `exclude`).
pub fn detect_default_interface(exclude: &str) -> Option<String> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        detect_linux(exclude)
    }
    #[cfg(target_os = "windows")]
    {
        detect_windows(exclude)
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "windows"
    )))]
    {
        let _ = exclude;
        None
    }
}

/// Refresh global bind interface; spawns a background refresher if `monitor`.
pub fn start_monitor(exclude: String, monitor: bool) {
    refresh(&exclude);
    if !monitor {
        return;
    }
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            refresh(&exclude);
        }
    });
}

fn refresh(exclude: &str) {
    match detect_default_interface(exclude) {
        Some(name) => {
            let prev = bind_interface();
            if prev.as_deref() != Some(name.as_str()) {
                info!(interface = %name, "tun: default interface => {name}");
                set_bind_interface(Some(name));
            }
        }
        None => {
            if bind_interface().is_some() {
                warn!("tun: default interface lost");
                set_bind_interface(None);
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn detect_linux(exclude: &str) -> Option<String> {
    let out = std::process::Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // default via x.x.x.x dev eth0 ...
    for line in text.lines() {
        let mut dev: Option<&str> = None;
        let mut parts = line.split_whitespace();
        while let Some(p) = parts.next() {
            if p == "dev" {
                dev = parts.next();
                break;
            }
        }
        if let Some(d) = dev {
            if d != exclude && !d.starts_with("tun") && d != "lo" {
                return Some(d.to_string());
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn detect_windows(exclude: &str) -> Option<String> {
    // Parse `route print -4` for default 0.0.0.0 gateway interface index, then
    // map via `netsh interface ipv4 show interfaces`. Best-effort.
    let out = std::process::Command::new("route")
        .args(["print", "-4"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // Look for active routes line starting with 0.0.0.0
    let mut if_index: Option<u32> = None;
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 5 && cols[0] == "0.0.0.0" && cols[1] == "0.0.0.0" {
            if let Ok(idx) = cols[cols.len() - 1].parse::<u32>() {
                if_index = Some(idx);
                break;
            }
        }
    }
    let idx = if_index?;
    let out = std::process::Command::new("netsh")
        .args(["interface", "ipv4", "show", "interfaces"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // Idx Met MTU State Name...
        if cols.len() >= 5 {
            if cols[0].parse::<u32>().ok() == Some(idx) {
                let name = cols[4..].join(" ");
                if name != exclude {
                    return Some(name);
                }
            }
        }
    }
    None
}
