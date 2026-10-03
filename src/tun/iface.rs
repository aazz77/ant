//! Default interface monitor — event-driven via `ip monitor` when available,
//! with periodic fallback (sing-tun uses netlink; we approximate with iproute2).

use std::process::{Command, Stdio};
use std::sync::RwLock;
use tracing::{info, warn};

static BIND_IFACE: RwLock<Option<String>> = RwLock::new(None);

pub fn bind_interface() -> Option<String> {
    BIND_IFACE.read().ok().and_then(|g| g.clone())
}

pub fn set_bind_interface(name: Option<String>) {
    if let Ok(mut g) = BIND_IFACE.write() {
        *g = name;
    }
}

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

pub fn start_monitor(exclude: String, enable: bool) {
    if !enable {
        return;
    }
    refresh(&exclude);
    // Fast poll + optional `ip monitor` wakeups
    let ex = exclude.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            refresh(&ex);
        }
    });
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let ex2 = exclude;
        tokio::task::spawn_blocking(move || {
            // Blocks; each line triggers refresh.
            let _ = Command::new("ip")
                .args(["-o", "monitor", "route", "link"])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .and_then(|mut child| {
                    use std::io::{BufRead, BufReader};
                    if let Some(out) = child.stdout.take() {
                        let reader = BufReader::new(out);
                        for line in reader.lines().flatten() {
                            if line.contains("default") || line.contains("link") {
                                refresh(&ex2);
                            }
                        }
                    }
                    let _ = child.wait();
                    Ok(())
                });
        });
    }
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
    let out = Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        while let Some(p) = parts.next() {
            if p == "dev" {
                if let Some(d) = parts.next() {
                    if d != exclude && !d.starts_with("tun") && d != "lo" {
                        return Some(d.to_string());
                    }
                }
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn detect_windows(exclude: &str) -> Option<String> {
    let out = Command::new("route").args(["print", "-4"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut if_index = None;
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
    let out = Command::new("netsh")
        .args(["interface", "ipv4", "show", "interfaces"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
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
