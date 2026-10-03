//! auto-redirect (Linux only): nftables/iptables REDIRECT to redir-port.

use anyhow::{bail, Result};
use std::process::Command;
use tracing::{info, warn};

/// RAII guard that removes redirect rules on drop.
pub struct RedirectGuard {
    backend: Backend,
    redir_port: u16,
    fwmark: u32,
}

enum Backend {
    Nft,
    Iptables,
    None,
}

impl Drop for RedirectGuard {
    fn drop(&mut self) {
        match self.backend {
            Backend::Nft => {
                let _ = run_cmd("nft", &["delete", "table", "inet", "ant"]);
            }
            Backend::Iptables => {
                let port = self.redir_port.to_string();
                let mark = self.fwmark.to_string();
                // Best-effort deletes (ignore failures).
                let _ = run_cmd(
                    "iptables",
                    &[
                        "-t",
                        "nat",
                        "-D",
                        "OUTPUT",
                        "-p",
                        "tcp",
                        "!",
                        "-m",
                        "mark",
                        "--mark",
                        &mark,
                        "-j",
                        "REDIRECT",
                        "--to-ports",
                        &port,
                    ],
                );
                let _ = run_cmd(
                    "iptables",
                    &[
                        "-t",
                        "nat",
                        "-D",
                        "PREROUTING",
                        "-p",
                        "tcp",
                        "-j",
                        "REDIRECT",
                        "--to-ports",
                        &port,
                    ],
                );
                #[cfg(any(target_os = "linux", target_os = "android"))]
                {
                    let _ = run_cmd(
                        "ip6tables",
                        &[
                            "-t",
                            "nat",
                            "-D",
                            "OUTPUT",
                            "-p",
                            "tcp",
                            "!",
                            "-m",
                            "mark",
                            "--mark",
                            &mark,
                            "-j",
                            "REDIRECT",
                            "--to-ports",
                            &port,
                        ],
                    );
                    let _ = run_cmd(
                        "ip6tables",
                        &[
                            "-t",
                            "nat",
                            "-D",
                            "PREROUTING",
                            "-p",
                            "tcp",
                            "-j",
                            "REDIRECT",
                            "--to-ports",
                            &port,
                        ],
                    );
                }
            }
            Backend::None => {}
        }
        info!("tun: auto-redirect cleaned up");
    }
}

/// Install redirect rules. `redir_port` must be > 0.
/// `fwmark` packets (proxy outbound) are excluded from OUTPUT redirect.
pub fn install_redirect(redir_port: u16, fwmark: u32) -> Result<RedirectGuard> {
    if redir_port == 0 {
        bail!("auto-redirect requires redir-port > 0");
    }
    let mark = if fwmark == 0 { 255 } else { fwmark };

    // Prefer nftables.
    if try_nft(redir_port, mark) {
        info!(redir_port, mark, "tun: auto-redirect installed (nftables)");
        return Ok(RedirectGuard {
            backend: Backend::Nft,
            redir_port,
            fwmark: mark,
        });
    }

    if try_iptables(redir_port, mark) {
        info!(redir_port, mark, "tun: auto-redirect installed (iptables)");
        return Ok(RedirectGuard {
            backend: Backend::Iptables,
            redir_port,
            fwmark: mark,
        });
    }

    warn!("tun: auto-redirect failed (nftables and iptables unavailable)");
    Ok(RedirectGuard {
        backend: Backend::None,
        redir_port,
        fwmark: mark,
    })
}

fn try_nft(redir_port: u16, mark: u32) -> bool {
    // Remove stale table if any.
    let _ = run_cmd("nft", &["delete", "table", "inet", "ant"]);
    let script = format!(
        r#"
table inet ant {{
  chain output {{
    type nat hook output priority -100; policy accept;
    meta mark {mark} return
    meta l4proto tcp redirect to :{redir_port}
  }}
  chain prerouting {{
    type nat hook prerouting priority -100; policy accept;
    meta l4proto tcp redirect to :{redir_port}
  }}
}}
"#
    );
    match Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(script.as_bytes());
            }
            matches!(child.wait(), Ok(st) if st.success())
        }
        Err(_) => false,
    }
}

fn try_iptables(redir_port: u16, mark: u32) -> bool {
    let port = redir_port.to_string();
    let mark_s = mark.to_string();
    // OUTPUT: skip marked, redirect other TCP.
    let ok1 = run_cmd(
        "iptables",
        &[
            "-t",
            "nat",
            "-A",
            "OUTPUT",
            "-p",
            "tcp",
            "!",
            "-m",
            "mark",
            "--mark",
            &mark_s,
            "-j",
            "REDIRECT",
            "--to-ports",
            &port,
        ],
    );
    let ok2 = run_cmd(
        "iptables",
        &[
            "-t",
            "nat",
            "-A",
            "PREROUTING",
            "-p",
            "tcp",
            "-j",
            "REDIRECT",
            "--to-ports",
            &port,
        ],
    );
    let _ = run_cmd(
        "ip6tables",
        &[
            "-t",
            "nat",
            "-A",
            "OUTPUT",
            "-p",
            "tcp",
            "!",
            "-m",
            "mark",
            "--mark",
            &mark_s,
            "-j",
            "REDIRECT",
            "--to-ports",
            &port,
        ],
    );
    let _ = run_cmd(
        "ip6tables",
        &[
            "-t",
            "nat",
            "-A",
            "PREROUTING",
            "-p",
            "tcp",
            "-j",
            "REDIRECT",
            "--to-ports",
            &port,
        ],
    );
    ok1 && ok2
}

fn run_cmd(bin: &str, args: &[&str]) -> bool {
    match Command::new(bin).args(args).output() {
        Ok(out) if out.status.success() => true,
        Ok(out) => {
            warn!(
                cmd = %bin,
                args = ?args,
                stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                "redirect command failed"
            );
            false
        }
        Err(e) => {
            warn!(cmd = %bin, err = %e, "redirect command missing");
            false
        }
    }
}
