//! auto-redirect via **nftables** crate (JSON API) + iptables fallback.
//! Internal TCP listener — no user redir-port (sing-tun style).

use crate::app::router::Router;
use crate::outbound::OutboundManager;
use crate::tun::marks::TunMarks;
use anyhow::{Context, Result};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{info, warn};

pub struct RedirectGuard {
    backend: Backend,
    port: u16,
    marks: TunMarks,
    accept: Option<tokio::task::JoinHandle<()>>,
}

enum Backend {
    Nftables,
    Iptables,
    None,
}

impl Drop for RedirectGuard {
    fn drop(&mut self) {
        if let Some(t) = self.accept.take() {
            t.abort();
        }
        match self.backend {
            Backend::Nftables => {
                // Delete table via nft JSON API or CLI
                let _ = delete_nft_table();
            }
            Backend::Iptables => {
                let p = self.port.to_string();
                let om = self.marks.output.to_string();
                for bin in ["iptables", "ip6tables"] {
                    for args in [
                        vec![
                            "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "!", "-m", "mark", "--mark",
                            om.as_str(), "-j", "REDIRECT", "--to-ports", p.as_str(),
                        ],
                        vec![
                            "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "-j", "REDIRECT",
                            "--to-ports", p.as_str(),
                        ],
                    ] {
                        let _ = Command::new(bin).args(&args).output();
                    }
                }
            }
            Backend::None => {}
        }
        info!("tun: auto-redirect cleaned up");
    }
}

pub async fn start_auto_redirect(
    marks: TunMarks,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> Result<RedirectGuard> {
    let listener = TcpListener::bind("0.0.0.0:0")
        .await
        .context("auto-redirect bind")?;
    let port = listener.local_addr()?.port();
    let listener6 = TcpListener::bind(("::", port)).await.ok();

    info!(
        port,
        input_mark = format!("0x{:x}", marks.input),
        output_mark = format!("0x{:x}", marks.output),
        "tun: auto-redirect internal listener"
    );

    let accept = {
        let r = router.clone();
        let o = outbounds.clone();
        tokio::spawn(async move { accept_loop(listener, r, o).await })
    };
    if let Some(l6) = listener6 {
        let r = router.clone();
        let o = outbounds.clone();
        tokio::spawn(async move { accept_loop(l6, r, o).await });
    }

    let backend = match apply_nftables(port, marks) {
        Ok(()) => {
            info!(port, "tun: auto-redirect via nftables crate");
            Backend::Nftables
        }
        Err(e) => {
            warn!(err = %e, "nftables apply failed, trying iptables");
            if try_iptables(port, marks) {
                info!(port, "tun: auto-redirect via iptables");
                Backend::Iptables
            } else {
                warn!("tun: auto-redirect firewall rules failed");
                Backend::None
            }
        }
    };

    Ok(RedirectGuard {
        backend,
        port,
        marks,
        accept: Some(accept),
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
                warn!("auto-redirect accept: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let router = router.clone();
        let outbounds = outbounds.clone();
        tokio::spawn(async move {
            if let Err(e) =
                crate::inbound::handle_redir_connection(stream, peer, router, outbounds).await
            {
                tracing::debug!("auto-redirect {peer}: {e:#}");
            }
        });
    }
}


fn apply_nftables(port: u16, marks: TunMarks) -> Result<()> {
    // Remove old table (crate + CLI fallback)
    let _ = delete_nft_table();

    // Full ruleset via nft (expression coverage in nftables-rs varies by version;
    // kernel/nft CLI remains the reliable apply path after structured delete).
    let script = format!(
        r#"
table inet ant {{
  chain output {{
    type nat hook output priority -100; policy accept;
    meta mark {out} return
    meta l4proto tcp redirect to :{port}
  }}
  chain prerouting {{
    type nat hook prerouting priority -100; policy accept;
    meta l4proto tcp redirect to :{port}
  }}
}}
"#,
        out = marks.output,
        port = port,
    );
    match Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(mut c) => {
            use std::io::Write;
            if let Some(mut s) = c.stdin.take() {
                let _ = s.write_all(script.as_bytes());
            }
            match c.wait() {
                Ok(st) if st.success() => Ok(()),
                Ok(st) => Err(anyhow::anyhow!("nft -f exit {st}")),
                Err(e) => Err(anyhow::anyhow!("nft wait: {e}")),
            }
        }
        Err(e) => Err(anyhow::anyhow!("nft spawn: {e}")),
    }
}

fn delete_nft_table() -> Result<()> {
    use nftables::batch::Batch;
    use nftables::helper;
    use nftables::schema::{NfListObject, Table};
    use nftables::types::NfFamily;
    use std::borrow::Cow;

    let mut batch = Batch::new();
    batch.delete(NfListObject::Table(Table {
        family: NfFamily::INet,
        name: Cow::Borrowed("ant"),
        handle: None,
    }));
    match helper::apply_ruleset(&batch.to_nftables()) {
        Ok(()) => Ok(()),
        Err(_) => {
            let _ = Command::new("nft")
                .args(["delete", "table", "inet", "ant"])
                .output();
            Ok(())
        }
    }
}

fn try_iptables(port: u16, marks: TunMarks) -> bool {
    let p = port.to_string();
    let om = marks.output.to_string();
    let run = |bin: &str, args: &[&str]| -> bool {
        Command::new(bin)
            .args(args)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };
    let ok1 = run(
        "iptables",
        &[
            "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "!", "-m", "mark", "--mark", &om, "-j",
            "REDIRECT", "--to-ports", &p,
        ],
    );
    let ok2 = run(
        "iptables",
        &[
            "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "-j", "REDIRECT", "--to-ports", &p,
        ],
    );
    let _ = run(
        "ip6tables",
        &[
            "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "!", "-m", "mark", "--mark", &om, "-j",
            "REDIRECT", "--to-ports", &p,
        ],
    );
    let _ = run(
        "ip6tables",
        &[
            "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "-j", "REDIRECT", "--to-ports", &p,
        ],
    );
    ok1 && ok2
}
