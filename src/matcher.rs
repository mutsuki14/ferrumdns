use ipnet::IpNet;
use parking_lot::RwLock;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use crate::context::QueryContext;
use crate::dnsutil;
use crate::error::{Error, Result};

/// Domain matcher supporting suffix, full, keyword and regexp rules
/// (mosdns domain-set syntax).
#[derive(Default)]
pub struct DomainSet {
    /// Reverse-label suffix tree: empty-string key at a node means "this domain
    /// itself is a match"; other keys are child labels.
    suffix: SuffixNode,
    full: HashSet<String>,
    keywords: Vec<String>,
    regexes: Vec<Regex>,
}

#[derive(Default)]
struct SuffixNode {
    children: HashMap<String, SuffixNode>,
    terminal: bool,
}

impl DomainSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_args(args: &serde_yaml::Value, base: &Path) -> Result<Self> {
        let mut set = Self::new();
        if let Some(exps) = args.get("exps").and_then(|v| v.as_sequence()) {
            for e in exps {
                if let Some(s) = e.as_str() {
                    set.add_rule(s)?;
                }
            }
        }
        if let Some(files) = args.get("files").and_then(|v| v.as_sequence()) {
            for f in files {
                if let Some(p) = f.as_str() {
                    set.load_file(&crate::config::resolve_path(base, p))?;
                }
            }
        }
        Ok(set)
    }

    pub fn load_file(&mut self, path: &Path) -> Result<()> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::config(format!("domain_set file {}: {e}", path.display())))?;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            self.add_rule(line)?;
        }
        Ok(())
    }

    pub fn add_rule(&mut self, raw: &str) -> Result<()> {
        let raw = raw.trim();
        if raw.is_empty() || raw.starts_with('#') {
            return Ok(());
        }
        if let Some(rest) = raw.strip_prefix("full:") {
            self.full.insert(normalize_domain(rest));
        } else if let Some(rest) = raw.strip_prefix("keyword:") {
            self.keywords.push(rest.to_ascii_lowercase());
        } else if let Some(rest) = raw.strip_prefix("regexp:") {
            let re = Regex::new(rest)
                .map_err(|e| Error::config(format!("bad regexp `{rest}`: {e}")))?;
            self.regexes.push(re);
        } else if let Some(rest) = raw.strip_prefix("domain:") {
            self.insert_suffix(&normalize_domain(rest));
        } else {
            // default: suffix / subdomain match
            self.insert_suffix(&normalize_domain(raw));
        }
        Ok(())
    }

    fn insert_suffix(&mut self, domain: &str) {
        let labels: Vec<&str> = domain.split('.').rev().filter(|s| !s.is_empty()).collect();
        let mut node = &mut self.suffix;
        for lab in labels {
            node = node.children.entry(lab.to_string()).or_default();
        }
        node.terminal = true;
    }

    pub fn contains(&self, domain: &str) -> bool {
        let d = normalize_domain(domain);
        if self.full.contains(&d) {
            return true;
        }
        if self.suffix_match(&d) {
            return true;
        }
        for kw in &self.keywords {
            if d.contains(kw) {
                return true;
            }
        }
        for re in &self.regexes {
            if re.is_match(&d) {
                return true;
            }
        }
        false
    }

    fn suffix_match(&self, domain: &str) -> bool {
        let labels: Vec<&str> = domain.split('.').rev().filter(|s| !s.is_empty()).collect();
        let mut node = &self.suffix;
        for lab in labels {
            match node.children.get(lab) {
                Some(next) => {
                    node = next;
                    if node.terminal {
                        return true;
                    }
                }
                None => return false,
            }
        }
        node.terminal
    }

    pub fn len(&self) -> usize {
        self.full.len() + self.keywords.len() + self.regexes.len() + count_terminals(&self.suffix)
    }
}

fn count_terminals(n: &SuffixNode) -> usize {
    let mut c = if n.terminal { 1 } else { 0 };
    for child in n.children.values() {
        c += count_terminals(child);
    }
    c
}

fn normalize_domain(s: &str) -> String {
    s.trim()
        .trim_end_matches('.')
        .trim_start_matches('.')
        .to_ascii_lowercase()
}

/// CIDR / IP matcher.
#[derive(Default)]
pub struct IpSet {
    nets: Vec<IpNet>,
}

impl IpSet {
    pub fn from_args(args: &serde_yaml::Value, base: &Path) -> Result<Self> {
        let mut set = Self::default();
        if let Some(exps) = args.get("exps").and_then(|v| v.as_sequence()) {
            for e in exps {
                if let Some(s) = e.as_str() {
                    set.add(s)?;
                }
            }
        }
        if let Some(files) = args.get("files").and_then(|v| v.as_sequence()) {
            for f in files {
                if let Some(p) = f.as_str() {
                    set.load_file(&crate::config::resolve_path(base, p))?;
                }
            }
        }
        Ok(set)
    }

    pub fn load_file(&mut self, path: &Path) -> Result<()> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::config(format!("ip_set file {}: {e}", path.display())))?;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            self.add(line)?;
        }
        Ok(())
    }

    pub fn add(&mut self, raw: &str) -> Result<()> {
        let raw = raw.trim();
        let net = if raw.contains('/') {
            IpNet::from_str(raw).map_err(|e| Error::config(format!("bad cidr `{raw}`: {e}")))?
        } else {
            let ip: IpAddr = raw
                .parse()
                .map_err(|e| Error::config(format!("bad ip `{raw}`: {e}")))?;
            IpNet::from(ip)
        };
        self.nets.push(net);
        Ok(())
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.nets.iter().any(|n| n.contains(&ip))
    }

    pub fn len(&self) -> usize {
        self.nets.len()
    }
}

pub enum Matcher {
    Qname(Arc<RwLock<DomainSet>>),
    Qtype(Vec<hickory_proto::rr::RecordType>),
    ClientIp(Arc<RwLock<IpSet>>),
    RespIp(Arc<RwLock<IpSet>>),
    HasResp,
    HasWantedAns,
    Rcode(u16),
    Mark(u32),
    Neg(Box<Matcher>),
}

impl Matcher {
    pub fn matches(&self, ctx: &QueryContext) -> bool {
        match self {
            Matcher::Qname(set) => {
                let name = ctx.qname_str();
                set.read().contains(&name)
            }
            Matcher::Qtype(types) => types.contains(&ctx.qtype()),
            Matcher::ClientIp(set) => ctx
                .client_addr
                .map(|ip| set.read().contains(ip))
                .unwrap_or(false),
            Matcher::RespIp(set) => {
                let guard = set.read();
                ctx.answer_ips().iter().any(|ip| guard.contains(*ip))
            }
            Matcher::HasResp => ctx.has_resp(),
            Matcher::HasWantedAns => ctx.has_wanted_ans(),
            Matcher::Rcode(code) => ctx
                .response()
                .map(|r| dnsutil::rcode_to_u16(r.response_code()) == *code)
                .unwrap_or(false),
            Matcher::Mark(m) => ctx.has_mark(*m),
            Matcher::Neg(inner) => !inner.matches(ctx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_and_full() {
        let mut s = DomainSet::new();
        s.add_rule("example.com").unwrap();
        s.add_rule("full:exact.test").unwrap();
        s.add_rule("keyword:ads").unwrap();
        assert!(s.contains("example.com"));
        assert!(s.contains("www.example.com"));
        assert!(s.contains("a.b.example.com"));
        assert!(!s.contains("example.org"));
        assert!(s.contains("exact.test"));
        assert!(!s.contains("www.exact.test"));
        assert!(s.contains("tracker.ads.cdn.net"));
    }

    #[test]
    fn ip_cidr() {
        let mut s = IpSet::default();
        s.add("10.0.0.0/8").unwrap();
        s.add("1.1.1.1").unwrap();
        assert!(s.contains("10.1.2.3".parse().unwrap()));
        assert!(s.contains("1.1.1.1".parse().unwrap()));
        assert!(!s.contains("8.8.8.8".parse().unwrap()));
    }
}
