//! Routing: sniff first, then sequential RULE-SET match, MATCH last.

use crate::config::Config;
use crate::dns::cache::DnsCache;
use crate::dns::fakeip::FakeIpPool;
use crate::dns::{parse_nameserver, DnsUpstream};
use crate::ruleset::{self, RuleSet};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outbound {
    Direct,
    /// A named proxy node; resolved to its dialer by OutboundManager.
    Node(String),
    /// Reject connection; DNS answers with NOERROR empty (rcode://success).
    Block,
}

impl Outbound {
    /// Parse a route outbound value: `direct`/`DIRECT` and `block`/`REJECT`
    /// are reserved; anything else is a proxy node name (validated by config).
    pub fn from_str(s: &str) -> Self {
        match crate::config::normalize_outbound_name(s).as_str() {
            "direct" => Outbound::Direct,
            "block" => Outbound::Block,
            other => Outbound::Node(other.to_string()),
        }
    }

    /// Display label: `direct` / `block` / the node name.
    pub fn label(&self) -> String {
        match self {
            Outbound::Direct => "direct".into(),
            Outbound::Block => "block".into(),
            Outbound::Node(name) => name.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RouteMatch {
    pub outbound: Outbound,
    /// Ruleset name, or `"MATCH"`.
    pub rule: String,
}

/// DNS 上游决策：`Upstream` 正常转发；`Block` 回 NOERROR 空应答（rcode://success）。
#[derive(Debug, Clone)]
pub enum DnsAction {
    Upstream(DnsUpstream),
    Block,
}

/// DNS 上游选择策略（`dns.rule-follow-route`）。
enum DnsRoute {
    /// true（默认）：域名复用顶层 `route:` 匹配——direct → direct-nameserver、
    /// 节点 → proxy-nameserver、block/reject → rcode://success。
    FollowRoute {
        direct: DnsAction,
        proxy: DnsAction,
    },
    /// false：`dns.rules` 自定义表（`None` key = MATCH 兜底）。
    Rules(Vec<(Option<String>, DnsAction)>),
}

pub struct Router {
    rulesets: HashMap<String, RuleSet>,
    routes: Vec<RouteEntry>,
    final_outbound: Outbound,
    fakeip: bool,
    fakeip_pool: Option<FakeIpPool>,
    fakeip_filter: Vec<String>,
    fakeip_whitelist: bool,
    /// Protocol sniffing (TLS/HTTP/QUIC) enabled via top-level `sniff: true`.
    sniff: bool,
    // Read by the DNS-hijack path in tproxy/redir inbounds (linux/android only).
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        allow(dead_code)
    )]
    hijack_dns: bool,
    dns_route: DnsRoute,
    ipv6: bool,
    dns_cache: Option<Arc<DnsCache>>,
}

struct RouteEntry {
    ruleset: String,
    outbound: Outbound,
}

impl Router {
    pub fn from_config(cfg: &Config) -> Result<Arc<Self>> {
        let ruleset_list = cfg.ruleset_list()?;
        let mut rulesets = HashMap::new();
        for rs in &ruleset_list {
            let loaded = ruleset::load_ars(&rs.name, &rs.path)?;
            tracing::info!(
                "loaded ruleset {} ({}) from {:?}",
                rs.name,
                rs.ty,
                rs.path
            );
            rulesets.insert(rs.name.clone(), loaded);
        }

        let parsed = cfg.parsed_rules()?;
        let mut routes = Vec::new();
        let mut final_outbound = Outbound::Node("__unset__".into());
        for (i, r) in parsed.iter().enumerate() {
            if r.is_match {
                final_outbound = Outbound::from_str(&r.outbound);
                continue;
            }
            let name = r.ruleset.as_ref().unwrap();
            if !rulesets.contains_key(name) {
                anyhow::bail!("rules[{}] references unknown rule-provider {}", i, name);
            }
            routes.push(RouteEntry {
                ruleset: name.clone(),
                outbound: Outbound::from_str(&r.outbound),
            });
        }

        // DNS 模块总开关：无 `dns:` 块或 enable=false → 完全不启用
        // （无监听、无劫持、无 fakeip/缓存；内部解析走系统 resolver）。
        let dns_enabled = cfg.dns.enable;
        let ipv6 = dns_enabled && cfg.dns.ipv6;
        let fakeip = dns_enabled && cfg.dns.mode == "fakeip";
        let fakeip_pool = if fakeip {
            let v6_range = if ipv6 {
                cfg.dns.fakeip6_range.as_deref()
            } else {
                None
            };
            Some(FakeIpPool::new(cfg.dns.fakeip_range.as_deref(), v6_range)?)
        } else {
            None
        };
        if fakeip {
            tracing::info!(
                "fake-ip enabled v4={:?} v6={:?} ipv6={} mode={} filter={:?}",
                cfg.dns.fakeip_range,
                if ipv6 {
                    cfg.dns.fakeip6_range.clone()
                } else {
                    None
                },
                ipv6,
                cfg.dns.fakeip_filter_mode,
                cfg.dns.fakeip_filter
            );
        }

        let dns_cache = if dns_enabled && cfg.dns.cache_size > 0 {
            tracing::info!("dns cache size={}", cfg.dns.cache_size);
            Some(Arc::new(DnsCache::new(cfg.dns.cache_size)))
        } else {
            None
        };

        let dns_route = if !dns_enabled {
            // 模块关闭：不出上游；answer_query 在此状态下不可能被调用
            // （监听未启动、劫持路径已被 hijack_dns=false 关闭）。
            DnsRoute::Rules(Vec::new())
        } else if cfg.dns.rule_follow_route {
            let direct = parse_nameserver(
                cfg.dns
                    .direct_nameserver
                    .as_deref()
                    .context("rule-follow-route=true requires dns.direct-nameserver")?,
            )?;
            let proxy = parse_nameserver(
                cfg.dns
                    .proxy_nameserver
                    .as_deref()
                    .context("rule-follow-route=true requires dns.proxy-nameserver")?,
            )?;
            tracing::info!("dns rule-follow-route=true direct={direct} proxy={proxy}");
            DnsRoute::FollowRoute {
                direct: DnsAction::Upstream(direct),
                proxy: DnsAction::Upstream(proxy),
            }
        } else {
            let mut entries: Vec<(Option<String>, DnsAction)> = Vec::new();
            if cfg.dns.rules.is_empty() {
                // 无 dns.rules：nameserver 即默认上游（配置校验已强制存在）。
                let ns = cfg
                    .dns
                    .nameserver
                    .as_deref()
                    .context("rule-follow-route=false without dns.rules requires dns.nameserver")?;
                let up = parse_nameserver(ns)?;
                tracing::info!("dns rule-follow-route=false rules=0 nameserver={up}");
                entries.push((None, DnsAction::Upstream(up)));
            } else {
                for (i, line) in cfg.dns.rules.iter().enumerate() {
                    let r = crate::config::parse_dns_rule_line(line)
                        .with_context(|| format!("dns.rules[{i}]"))?;
                    let action = if r.upstream.eq_ignore_ascii_case("rcode://success") {
                        DnsAction::Block
                    } else {
                        DnsAction::Upstream(parse_nameserver(&r.upstream)?)
                    };
                    tracing::info!("dns rule {} -> {}", line.trim(), match &action {
                        DnsAction::Upstream(u) => u.to_string(),
                        DnsAction::Block => "rcode://success".into(),
                    });
                    entries.push((r.ruleset, action));
                }
            }
            DnsRoute::Rules(entries)
        };

        Ok(Arc::new(Router {
            rulesets,
            routes,
            final_outbound,
            fakeip,
            fakeip_pool,
            fakeip_filter: cfg.dns.fakeip_filter.clone(),
            fakeip_whitelist: cfg.dns.fakeip_filter_mode == "whitelist",
            sniff: cfg.global.sniff,
            hijack_dns: dns_enabled && cfg.dns.route_hijack,
            dns_route,
            ipv6,
            dns_cache,
        }))
    }

    /// DNS 上游决策：`None` → block（NOERROR 空应答，rcode://success）。
    pub fn dns_action_for_domain(&self, domain: &str) -> Option<&DnsAction> {
        match &self.dns_route {
            DnsRoute::FollowRoute { direct, proxy } => {
                match self.dns_outbound_for_domain(domain) {
                    Outbound::Direct => Some(direct),
                    Outbound::Node(_) => Some(proxy),
                    Outbound::Block => None,
                }
            }
            DnsRoute::Rules(entries) => entries
                .iter()
                .find(|(name, _)| match name {
                    None => true, // MATCH 兜底（校验保证存在且在最后）
                    Some(n) => self.rulesets.get(n).is_some_and(|rs| rs.match_domain(domain)),
                })
                .map(|(_, action)| action),
        }
    }

    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        allow(dead_code)
    )]
    pub fn hijack_dns(&self) -> bool {
        self.hijack_dns
    }

    pub fn sniff(&self) -> bool {
        self.sniff
    }

    pub fn ipv6_enabled(&self) -> bool {
        self.ipv6
    }

    pub fn dns_cache(&self) -> Option<&DnsCache> {
        self.dns_cache.as_deref()
    }

    pub fn fakeip_enabled(&self) -> bool {
        self.fakeip
    }

    /// Blacklist mode (default): matched domains stay real-IP, everything
    /// else gets fake-ip. Whitelist mode: only matched domains get fake-ip.
    pub fn use_fakeip(&self, domain: &str) -> bool {
        if !self.fakeip || domain.is_empty() {
            return false;
        }
        let d = domain.trim_end_matches('.').to_ascii_lowercase();
        let hit = self
            .fakeip_filter
            .iter()
            .any(|name| self.rulesets.get(name).is_some_and(|rs| rs.match_domain(&d)));
        if self.fakeip_whitelist {
            hit
        } else {
            !hit
        }
    }

    pub fn allocate_fakeip(&self, domain: &str, v6: bool) -> Option<std::net::IpAddr> {
        if v6 && !self.ipv6 {
            return None;
        }
        self.fakeip_pool.as_ref()?.allocate(domain, v6)
    }

    pub fn has_fakeip_v4(&self) -> bool {
        self.fakeip_pool.as_ref().map(|p| p.has_v4()).unwrap_or(false)
    }

    pub fn has_fakeip_v6(&self) -> bool {
        self.ipv6
            && self
                .fakeip_pool
                .as_ref()
                .map(|p| p.has_v6())
                .unwrap_or(false)
    }

    /// Map a destination fake-ip back to the domain that was answered.
    pub fn domain_for_fakeip(&self, ip: std::net::IpAddr) -> Option<String> {
        let pool = self.fakeip_pool.as_ref()?;
        if !pool.contains(ip) {
            return None;
        }
        pool.domain_of(ip)
    }

    /// Match by domain (preferred after sniff) and/or destination IP.
    pub fn match_outbound(&self, domain: Option<&str>, ip: Option<IpAddr>) -> Outbound {
        self.match_route(domain, ip).outbound
    }

    pub fn match_route(&self, domain: Option<&str>, ip: Option<IpAddr>) -> RouteMatch {
        // Fake-ip addresses must not hit ip rulesets; route by the mapped domain.
        let ip = ip.filter(|addr| self.domain_for_fakeip(*addr).is_none());
        for entry in &self.routes {
            if let Some(rs) = self.rulesets.get(&entry.ruleset) {
                let hit = match (domain, ip) {
                    (Some(d), _) if rs.match_domain(d) => true,
                    (_, Some(addr)) if rs.match_ip(addr) => true,
                    _ => false,
                };
                if hit {
                    tracing::debug!(
                        "route hit ruleset={} -> {}",
                        entry.ruleset,
                        entry.outbound.label()
                    );
                    return RouteMatch {
                        outbound: entry.outbound.clone(),
                        rule: entry.ruleset.clone(),
                    };
                }
            }
        }
        tracing::debug!("route MATCH -> {}", self.final_outbound.label());
        RouteMatch {
            outbound: self.final_outbound.clone(),
            rule: "MATCH".into(),
        }
    }

    /// For DNS (rule-follow-route=true): decide which upstream (or block) for a
    /// domain query by reusing the top-level `route:` match.
    fn dns_outbound_for_domain(&self, domain: &str) -> Outbound {
        for entry in &self.routes {
            if let Some(rs) = self.rulesets.get(&entry.ruleset) {
                if rs.match_domain(domain) {
                    return entry.outbound.clone();
                }
            }
        }
        self.final_outbound.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::parse_nameserver;
    use std::net::IpAddr;

    fn domain_ruleset(name: &str, yaml: &str) -> RuleSet {
        let compiled = crate::ruleset::compile_mihomo_ruleset(
            yaml,
            Some(crate::ruleset::ProviderBehavior::Classical),
        )
        .unwrap();
        let mut buf = Vec::new();
        crate::ruleset::write_ars(&compiled, &mut buf).unwrap();
        RuleSet::from_bytes(name, &buf).unwrap()
    }

    fn router_with_filter(whitelist: bool) -> Router {
        let cn = domain_ruleset(
            "cn",
            "payload:
  - DOMAIN-SUFFIX,cn
",
        );
        let mut rulesets = HashMap::new();
        rulesets.insert("cn".to_string(), cn);
        Router {
            rulesets,
            routes: vec![],
            final_outbound: Outbound::Node("main".into()),
            fakeip: true,
            fakeip_pool: Some(FakeIpPool::new(Some("198.18.0.0/15"), None).unwrap()),
            fakeip_filter: vec!["cn".to_string()],
            fakeip_whitelist: whitelist,
            sniff: false,
            hijack_dns: false,
            dns_route: DnsRoute::FollowRoute {
                direct: DnsAction::Upstream(parse_nameserver("223.5.5.5:53").unwrap()),
                proxy: DnsAction::Upstream(parse_nameserver("223.5.5.5:53").unwrap()),
            },
            ipv6: true,
            dns_cache: None,
        }
    }

    #[test]
    fn fakeip_blacklist_matched_stays_real_ip() {
        let r = router_with_filter(false);
        assert!(r.use_fakeip("google.com"));
        assert!(!r.use_fakeip("www.baidu.cn"));
        // trailing dot tolerated: still matches the filter ruleset
        assert!(!r.use_fakeip("www.baidu.cn."));
        assert!(!r.use_fakeip(""));
    }

    #[test]
    fn fakeip_whitelist_only_matched_gets_fake_ip() {
        let r = router_with_filter(true);
        assert!(!r.use_fakeip("google.com"));
        assert!(r.use_fakeip("www.baidu.cn"));
    }

    #[test]
    fn outbound_node_label_roundtrip() {
        assert_eq!(Outbound::from_str("direct"), Outbound::Direct);
        assert_eq!(Outbound::from_str("DIRECT"), Outbound::Direct);
        assert_eq!(Outbound::from_str("block"), Outbound::Block);
        assert_eq!(Outbound::from_str("REJECT"), Outbound::Block);
        assert_eq!(
            Outbound::from_str("hy2-main"),
            Outbound::Node("hy2-main".into())
        );
        assert_eq!(Outbound::Node("hy2-main".into()).label(), "hy2-main");
        assert!(Outbound::Node("x".into()) != Outbound::Node("y".into()));
        let _ = IpAddr::from([127, 0, 0, 1]); // silence unused import if cfg changes
    }

    #[test]
    fn dns_action_rules_mode() {
        let cn = domain_ruleset("cn", "payload:\n  - DOMAIN-SUFFIX,cn\n");
        let mut rulesets = HashMap::new();
        rulesets.insert("cn".to_string(), cn);
        let r = Router {
            rulesets,
            routes: vec![],
            final_outbound: Outbound::Node("main".into()),
            fakeip: false,
            fakeip_pool: None,
            fakeip_filter: vec![],
            fakeip_whitelist: false,
            sniff: false,
            hijack_dns: false,
            dns_route: DnsRoute::Rules(vec![
                (
                    Some("cn".into()),
                    DnsAction::Upstream(parse_nameserver("223.5.5.5:53").unwrap()),
                ),
                (None, DnsAction::Block),
            ]),
            ipv6: true,
            dns_cache: None,
        };
        match r.dns_action_for_domain("www.baidu.cn") {
            Some(DnsAction::Upstream(u)) => assert_eq!(u.to_string(), "udp://223.5.5.5:53"),
            other => panic!("expected upstream, got {other:?}"),
        }
        // 未命中 → MATCH 兜底 → rcode://success
        assert!(matches!(
            r.dns_action_for_domain("google.com"),
            Some(DnsAction::Block)
        ));
    }

    #[test]
    fn dns_action_follow_route_block_and_node() {
        let cn = domain_ruleset("cn", "payload:\n  - DOMAIN-SUFFIX,cn\n");
        let mut rulesets = HashMap::new();
        rulesets.insert("cn".to_string(), cn);
        let r = Router {
            rulesets,
            routes: vec![
                RouteEntry {
                    ruleset: "cn".into(),
                    outbound: Outbound::Block,
                },
            ],
            final_outbound: Outbound::Node("main".into()),
            fakeip: false,
            fakeip_pool: None,
            fakeip_filter: vec![],
            fakeip_whitelist: false,
            sniff: false,
            hijack_dns: false,
            dns_route: DnsRoute::FollowRoute {
                direct: DnsAction::Upstream(parse_nameserver("223.5.5.5:53").unwrap()),
                proxy: DnsAction::Upstream(parse_nameserver("8.8.8.8:53").unwrap()),
            },
            ipv6: true,
            dns_cache: None,
        };
        // route 出站 block → None（rcode://success）
        assert!(r.dns_action_for_domain("www.baidu.cn").is_none());
        // route 出站节点 → proxy-nameserver
        match r.dns_action_for_domain("google.com") {
            Some(DnsAction::Upstream(u)) => assert_eq!(u.to_string(), "udp://8.8.8.8:53"),
            other => panic!("expected proxy upstream, got {other:?}"),
        }
    }
}
