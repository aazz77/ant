//! auto-redirect (Linux only): nftables/iptables REDIRECT → internal TCP listener.
//!
//! Same idea as mihomo/sing-tun: no user `redir-port` required. We bind an
//! ephemeral local port, install REDIRECT rules to it, accept with
//! SO_ORIGINAL_DST, then hand the stream to the shared redir handler (router).

use crate::app::router::Router;
use crate::outbound::OutboundManager;
use anyhow::{Context, Result};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{info, warn};

/// RAII guard: removes redirect rules and aborts the accept task on drop.
pub struct RedirectGuard {
    backend: Backend,
    redir_port: u16,
    fwmark: u32,
    accept_task: Option<tokio::task::JoinHandle<()>>,
}

enum Backend {
    Nft,
    Iptables,
    None,
}

impl Drop for RedirectGuard {
    fn drop(&mut self) {
        if let Some(t) = self.accept_task.take() {
            t.abort();
        }
        match self.backend {
            Backend::Nft => {
                let _ = run_cmd("nft", &["delete", "table", "inet", "ant"]);
            }
            Backend::Iptables => {
                let port = self.redir_port.to_string();
                let mark = self.fwmark.to_string();
                for (bin, chain, extra) in [
                    (
                        "iptables",
                        "OUTPUT",
                        vec![
                            "-p",
                            "tcp",
                            "!",
                            "-m",
                            "mark",
                            "--mark",
                            mark.as_str(),
                            "-j",
                            "REDIRECT",
                            "--to-ports",
                            port.as_str(),
                        ],
                    ),
                    (
                        "iptables",
                        "PREROUTING",
                        vec![
                            "-p",
                            "tcp",
                            "-j",
                            "REDIRECT",
                            "--to-ports",
                            port.as_str(),
                        ],
                    ),
                    (
                        "ip6tables",
                        "OUTPUT",
                        vec![
                            "-p",
                            "tcp",
                            "!",
                            "-m",
                            "mark",
                            "--mark",
                            mark.as_str(),
                            "-j",
                            "REDIRECT",
                            "--to-ports",
                            port.as_str(),
                        ],
                    ),
                    (
                        "ip6tables",
                        "PREROUTING",
                        vec![
                            "-p",
                            "tcp",
                            "-j",
                            "REDIRECT",
                            "--to-ports",
                            port.as_str(),
                        ],
                    ),
                ] {
                    let mut args = vec!["-t", "nat", "-D", chain];
                    args.extend(extra);
                    let _ = run_cmd(bin, &args);
                }
            }
            Backend::None => {}
        }
        info!("tun: auto-redirect cleaned up");
    }
}

/// Bind internal listener, install REDIRECT rules, accept → router.
/// Does **not** require user `redir-port`.
pub async fn start_auto_redirect(
    fwmark: u32,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> Result<RedirectGuard> {
    let mark = if fwmark == 0 { 255 } else { fwmark };

    // IPv4: 0.0.0.0 so PREROUTING REDIRECT (router) and OUTPUT both work.
    let listener_v4 = TcpListener::bind("0.0.0.0:0")
        .await
        .context("auto-redirect bind 0.0.0.0:0")?;
    let port = listener_v4
        .local_addr()
        .context("auto-redirect local_addr")?
        .port();

    // IPv6 best-effort on the same port.
    let listener_v6 = match TcpListener::bind(("::", port)).await {
        Ok(l) => Some(l),
        Err(e) => {
            warn!("tun: auto-redirect IPv6 bind [::]:{port}: {e}");
            None
        }
    };

    info!(
        port,
        mark, "tun: auto-redirect internal listener ready (no redir-port required)"
    );

    let accept_task = {
        let router = router.clone();
        let outbounds = outbounds.clone();
        tokio::spawn(async move {
            accept_loop(listener_v4, router.clone(), outbounds.clone()).await;
        })
    };
    if let Some(l6) = listener_v6 {
        let router = router.clone();
        let outbounds = outbounds.clone();
        tokio::spawn(async move {
            accept_loop(l6, router, outbounds).await;
        });
    }

    // Install rules after listen so the port is open.
    let backend = if try_nft(port, mark) {
        info!(port, mark, "tun: auto-redirect installed (nftables)");
        Backend::Nft
    } else if try_iptables(port, mark) {
        info!(port, mark, "tun: auto-redirect installed (iptables)");
        Backend::Iptables
    } else {
        warn!("tun: auto-redirect rules failed (nftables and iptables unavailable)");
        Backend::None
    };

    Ok(RedirectGuard {
        backend,
        redir_port: port,
        fwmark: mark,
        accept_task: Some(accept_task),
    })
}

async fn accept_loop(
    listener: TcpListener,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok((s, p)) => (s, crate::app::sockopt::canonical(p)),
            Err(e) => {
                warn!("tun: auto-redirect accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let router = router.clone();
        let outbounds = outbounds.clone();
        tokio::spawn(async move {
            if let Err(e) =
                crate::inbound::handle_redir_connection(stream, peer, router, outbounds).await
            {
                tracing::debug!("tun auto-redirect {peer}: {e:#}");
            }
        });
    }
}

fn try_nft(redir_port: u16, mark: u32) -> bool {
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
