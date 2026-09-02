use async_trait::async_trait;
use hickory_proto::rr::rdata::opt::ClientSubnet;
use hickory_proto::rr::RecordType;
use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use crate::context::QueryContext;
use crate::dnsutil;
use crate::error::{Error, Result};
use crate::plugin::{Action, Executable};

/// mosdns-x `ecs` plugin: attach EDNS Client Subnet (RFC 7871) to the query.
pub struct Ecs {
    tag: String,
    auto: bool,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    force_overwrite: bool,
    mask4: u8,
    mask6: u8,
}

impl Ecs {
    pub fn from_args(tag: &str, args: &serde_yaml::Value) -> Result<Arc<Self>> {
        let auto = args.get("auto").and_then(|v| v.as_bool()).unwrap_or(false);
        let ipv4 = args
            .get("ipv4")
            .and_then(|v| v.as_str())
            .map(|s| s.parse::<Ipv4Addr>())
            .transpose()
            .map_err(|e| Error::config(format!("ecs ipv4: {e}")))?;
        let ipv6 = args
            .get("ipv6")
            .and_then(|v| v.as_str())
            .map(|s| s.parse::<Ipv6Addr>())
            .transpose()
            .map_err(|e| Error::config(format!("ecs ipv6: {e}")))?;
        if !auto && ipv4.is_none() && ipv6.is_none() {
            return Err(Error::config(
                "ecs plugin needs `ipv4`/`ipv6` or `auto: true`",
            ));
        }
        let mask4 = args
            .get("mask4")
            .and_then(|v| v.as_u64())
            .unwrap_or(24)
            .clamp(1, 32) as u8;
        let mask6 = args
            .get("mask6")
            .and_then(|v| v.as_u64())
            .unwrap_or(48)
            .clamp(1, 128) as u8;
        Ok(Arc::new(Self {
            tag: tag.to_string(),
            auto,
            ipv4,
            ipv6,
            force_overwrite: args
                .get("force_overwrite")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            mask4,
            mask6,
        }))
    }

    fn pick(&self, ctx: &QueryContext) -> Option<(IpAddr, u8)> {
        if self.auto {
            let ip = ctx.client_addr?;
            if !is_public_ip(ip) {
                return None;
            }
            let mask = if ip.is_ipv4() { self.mask4 } else { self.mask6 };
            return Some((ip, mask));
        }
        let prefer_v4 = ctx.qtype() != RecordType::AAAA;
        if prefer_v4 {
            if let Some(ip) = self.ipv4 {
                return Some((IpAddr::V4(ip), self.mask4));
            }
            if let Some(ip) = self.ipv6 {
                return Some((IpAddr::V6(ip), self.mask6));
            }
        } else {
            if let Some(ip) = self.ipv6 {
                return Some((IpAddr::V6(ip), self.mask6));
            }
            if let Some(ip) = self.ipv4 {
                return Some((IpAddr::V4(ip), self.mask4));
            }
        }
        None
    }
}

#[async_trait]
impl Executable for Ecs {
    async fn exec(&self, ctx: &mut QueryContext) -> Result<Action> {
        let existing = dnsutil::ecs_of(ctx.query());
        if existing.is_some() && !self.force_overwrite {
            ctx.push_trace(&self.tag, "keep", &dnsutil::ecs_label(existing.as_ref()));
            return Ok(Action::Continue);
        }
        let Some((ip, mask)) = self.pick(ctx) else {
            ctx.push_trace(&self.tag, "skip", "no public address");
            return Ok(Action::Continue);
        };
        let (net, mask) = masked(ip, mask);
        if existing.is_none() {
            ctx.strip_ecs_on_reply = true;
        }
        dnsutil::set_ecs(ctx.query_mut(), ClientSubnet::new(net, mask, 0));
        ctx.push_trace(&self.tag, "attach", &format!("{net}/{mask}"));
        Ok(Action::Continue)
    }
}

/// mosdns-x `_no_ecs`: drop ECS on the query and the eventual reply.
pub struct NoEcs {
    tag: String,
}

impl NoEcs {
    pub fn new(tag: impl Into<String>) -> Arc<Self> {
        Arc::new(Self { tag: tag.into() })
    }
}

#[async_trait]
impl Executable for NoEcs {
    async fn exec(&self, ctx: &mut QueryContext) -> Result<Action> {
        dnsutil::remove_ecs(ctx.query_mut());
        ctx.strip_ecs_on_reply = true;
        ctx.push_trace(&self.tag, "strip", "query");
        Ok(Action::Continue)
    }
}

pub fn masked(ip: IpAddr, prefix: u8) -> (IpAddr, u8) {
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = prefix.min(max);
    match IpNet::new(ip, prefix) {
        Ok(n) => (n.network(), prefix),
        Err(_) => (ip, prefix),
    }
}

pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            if v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_broadcast()
                || v.is_documentation()
                || v.is_multicast()
            {
                return false;
            }
            let o = v.octets();
            // CGNAT 100.64.0.0/10
            if o[0] == 100 && (o[1] & 0xc0) == 64 {
                return false;
            }
            if o[0] == 0 || o[0] >= 224 {
                return false;
            }
            true
        }
        IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(v4));
            }
            let s = v.segments();
            !v.is_loopback()
                && !v.is_unspecified()
                && !v.is_multicast()
                && (s[0] & 0xfe00) != 0xfc00 // unique local
                && (s[0] & 0xffc0) != 0xfe80 // link local
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{build_query, ClientProto, QueryContext};
    use hickory_proto::rr::RecordType;

    fn plugin(yaml: &str) -> Arc<Ecs> {
        let args: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        Ecs::from_args("ecs", &args).unwrap()
    }

    #[tokio::test]
    async fn attaches_masked_v4() {
        let ecs = plugin("ipv4: 203.0.113.9\nmask4: 24");
        let q = build_query("ecs.test.", RecordType::A).unwrap();
        let mut ctx = QueryContext::new(q, None, ClientProto::Udp);
        ctx.trace_enabled = true;
        ecs.exec(&mut ctx).await.unwrap();
        let got = dnsutil::ecs_of(ctx.query()).unwrap();
        assert_eq!(got.addr(), "203.0.113.0".parse::<IpAddr>().unwrap());
        assert_eq!(got.source_prefix(), 24);
        assert_eq!(got.scope_prefix(), 0);
        assert!(ctx.strip_ecs_on_reply);
        assert!(ctx.trace.iter().any(|t| t.event == "attach"));
    }

    #[tokio::test]
    async fn prefers_ipv6_on_aaaa() {
        let ecs = plugin("ipv4: 203.0.113.9\nipv6: \"2001:db8:1::9\"\nmask6: 48");
        let q = build_query("ecs.test.", RecordType::AAAA).unwrap();
        let mut ctx = QueryContext::new(q, None, ClientProto::Udp);
        ecs.exec(&mut ctx).await.unwrap();
        let got = dnsutil::ecs_of(ctx.query()).unwrap();
        assert_eq!(got.addr(), "2001:db8:1::".parse::<IpAddr>().unwrap());
        assert_eq!(got.source_prefix(), 48);
    }

    #[tokio::test]
    async fn keeps_existing_without_overwrite() {
        let ecs = plugin("ipv4: 203.0.113.9\nforce_overwrite: false");
        let mut q = build_query("ecs.test.", RecordType::A).unwrap();
        dnsutil::set_ecs(
            &mut q,
            ClientSubnet::new("198.51.100.0".parse().unwrap(), 24, 0),
        );
        let mut ctx = QueryContext::new(q, None, ClientProto::Udp);
        ctx.trace_enabled = true;
        ecs.exec(&mut ctx).await.unwrap();
        let got = dnsutil::ecs_of(ctx.query()).unwrap();
        assert_eq!(got.addr(), "198.51.100.0".parse::<IpAddr>().unwrap());
        assert!(!ctx.strip_ecs_on_reply);
        assert!(ctx.trace.iter().any(|t| t.event == "keep"));
    }

    #[tokio::test]
    async fn force_overwrite_replaces() {
        let ecs = plugin("ipv4: 203.0.113.9\nmask4: 24\nforce_overwrite: true");
        let mut q = build_query("ecs.test.", RecordType::A).unwrap();
        dnsutil::set_ecs(
            &mut q,
            ClientSubnet::new("198.51.100.0".parse().unwrap(), 24, 0),
        );
        let mut ctx = QueryContext::new(q, None, ClientProto::Udp);
        ecs.exec(&mut ctx).await.unwrap();
        let got = dnsutil::ecs_of(ctx.query()).unwrap();
        assert_eq!(got.addr(), "203.0.113.0".parse::<IpAddr>().unwrap());
        assert!(!ctx.strip_ecs_on_reply, "client already sent ECS");
    }

    #[tokio::test]
    async fn auto_skips_private_client() {
        let ecs = plugin("auto: true");
        let q = build_query("ecs.test.", RecordType::A).unwrap();
        let mut ctx = QueryContext::new(q, Some("192.168.1.10".parse().unwrap()), ClientProto::Udp);
        ctx.trace_enabled = true;
        ecs.exec(&mut ctx).await.unwrap();
        assert!(dnsutil::ecs_of(ctx.query()).is_none());
        assert!(ctx.trace.iter().any(|t| t.event == "skip"));
    }

    #[tokio::test]
    async fn auto_uses_public_client() {
        let ecs = plugin("auto: true\nmask4: 24");
        let q = build_query("ecs.test.", RecordType::A).unwrap();
        let mut ctx = QueryContext::new(q, Some("8.8.8.8".parse().unwrap()), ClientProto::Udp);
        ecs.exec(&mut ctx).await.unwrap();
        let got = dnsutil::ecs_of(ctx.query()).unwrap();
        assert_eq!(got.addr(), "8.8.8.0".parse::<IpAddr>().unwrap());
        assert!(ctx.strip_ecs_on_reply);
    }

    #[tokio::test]
    async fn no_ecs_strips() {
        let mut q = build_query("ecs.test.", RecordType::A).unwrap();
        dnsutil::set_ecs(
            &mut q,
            ClientSubnet::new("8.8.8.0".parse().unwrap(), 24, 0),
        );
        let mut ctx = QueryContext::new(q, None, ClientProto::Udp);
        NoEcs::new("no_ecs").exec(&mut ctx).await.unwrap();
        assert!(dnsutil::ecs_of(ctx.query()).is_none());
        assert!(ctx.strip_ecs_on_reply);
    }

    #[test]
    fn public_ip_filter() {
        assert!(is_public_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_public_ip("10.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("100.64.1.1".parse().unwrap()));
        assert!(!is_public_ip("::1".parse().unwrap()));
        assert!(is_public_ip("2001:4860:4860::8888".parse().unwrap()));
        assert!(!is_public_ip("fc00::1".parse().unwrap()));
        assert!(!is_public_ip("::ffff:192.168.1.1".parse().unwrap()));
        assert!(!is_public_ip("::ffff:100.64.1.1".parse().unwrap()));
        assert!(is_public_ip("::ffff:1.1.1.1".parse().unwrap()));
    }
}
