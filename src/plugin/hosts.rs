use async_trait::async_trait;
use hickory_proto::rr::{Name, Record, RecordType};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use crate::context::{build_hosts_response, QueryContext};
use crate::dnsutil;
use crate::error::{Error, Result};
use crate::plugin::{Action, Executable};

#[derive(Default)]
struct HostTable {
    /// ascii-lowercase name (no trailing dot) -> records
    by_name: HashMap<String, Vec<HostRec>>,
}

#[derive(Clone)]
struct HostRec {
    ip: IpAddr,
}

pub struct Hosts {
    tag: String,
    table: RwLock<HostTable>,
    ttl: u32,
}

impl Hosts {
    pub fn from_args(tag: &str, args: &serde_yaml::Value, base: &Path) -> Result<Arc<Self>> {
        let mut table = HostTable::default();
        let ttl = args.get("ttl").and_then(|v| v.as_u64()).unwrap_or(60) as u32;
        if let Some(entries) = args.get("entries").and_then(|v| v.as_sequence()) {
            for e in entries {
                if let Some(s) = e.as_str() {
                    parse_hosts_line(&mut table, s)?;
                }
            }
        }
        if let Some(files) = args.get("files").and_then(|v| v.as_sequence()) {
            for f in files {
                if let Some(p) = f.as_str() {
                    load_file(&mut table, &crate::config::resolve_path(base, p))?;
                }
            }
        }
        // also accept map form: { "example.com": "1.2.3.4" }
        if let Some(map) = args.get("hosts").and_then(|v| v.as_mapping()) {
            for (k, v) in map {
                if let (Some(name), Some(ip)) = (k.as_str(), v.as_str()) {
                    parse_hosts_line(&mut table, &format!("{ip} {name}"))?;
                }
            }
        }
        Ok(Arc::new(Self {
            tag: tag.to_string(),
            table: RwLock::new(table),
            ttl,
        }))
    }

    fn lookup(&self, name: &str, qtype: RecordType) -> Vec<Record> {
        let key = name.trim_end_matches('.').to_ascii_lowercase();
        let table = self.table.read();
        let Some(recs) = table.by_name.get(&key) else {
            return Vec::new();
        };
        let n = match Name::from_str(&format!("{key}.")) {
            Ok(n) => n,
            Err(_) => return Vec::new(),
        };
        recs.iter()
            .filter_map(|r| match (qtype, r.ip) {
                (RecordType::A, IpAddr::V4(ip)) => Some(dnsutil::record_a(n.clone(), self.ttl, ip)),
                (RecordType::AAAA, IpAddr::V6(ip)) => {
                    Some(dnsutil::record_aaaa(n.clone(), self.ttl, ip))
                }
                (RecordType::A | RecordType::AAAA, _) => None,
                (_, IpAddr::V4(ip)) if qtype == RecordType::ANY => {
                    Some(dnsutil::record_a(n.clone(), self.ttl, ip))
                }
                (_, IpAddr::V6(ip)) if qtype == RecordType::ANY => {
                    Some(dnsutil::record_aaaa(n.clone(), self.ttl, ip))
                }
                _ => None,
            })
            .collect()
    }
}

fn load_file(table: &mut HostTable, path: &Path) -> Result<()> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| Error::config(format!("hosts file {}: {e}", path.display())))?;
    for line in text.lines() {
        parse_hosts_line(table, line)?;
    }
    Ok(())
}

fn parse_hosts_line(table: &mut HostTable, line: &str) -> Result<()> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(());
    }
    let mut parts = line.split_whitespace();
    let first = parts.next().unwrap_or("");
    // support both "ip name [name...]" and "name ip"
    let (ip_s, names): (String, Vec<String>) = if dnsutil::parse_ip(first).is_some() {
        (first.to_string(), parts.map(|s| s.to_string()).collect())
    } else {
        let rest: Vec<&str> = parts.collect();
        if rest.len() == 1 && dnsutil::parse_ip(rest[0]).is_some() {
            (rest[0].to_string(), vec![first.to_string()])
        } else {
            return Err(Error::config(format!("bad hosts line: {line}")));
        }
    };
    let ip: IpAddr = ip_s
        .parse()
        .map_err(|e| Error::config(format!("bad ip in hosts `{ip_s}`: {e}")))?;
    for n in names {
        let key = n.trim_end_matches('.').to_ascii_lowercase();
        table.by_name.entry(key).or_default().push(HostRec { ip });
    }
    Ok(())
}

#[async_trait]
impl Executable for Hosts {
    async fn exec(&self, ctx: &mut QueryContext) -> Result<Action> {
        let name = ctx.qname_str();
        let recs = self.lookup(&name, ctx.qtype());
        if !recs.is_empty() {
            ctx.push_trace(&self.tag, "hit", &name);
            ctx.set_response(build_hosts_response(ctx.query(), recs));
        }
        Ok(Action::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{build_query, ClientProto};

    #[test]
    fn hosts_a_record() {
        let args: serde_yaml::Value = serde_yaml::from_str(
            r#"
entries:
  - "10.0.0.1 router.lan"
  - "app.lan 10.0.0.2"
"#,
        )
        .unwrap();
        let h = Hosts::from_args("hosts", &args, Path::new(".")).unwrap();
        let q = build_query("router.lan.", RecordType::A).unwrap();
        let mut ctx = QueryContext::new(q, None, ClientProto::Udp);
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(h.exec(&mut ctx))
            .unwrap();
        assert!(ctx.has_resp());
        assert_eq!(ctx.answer_ips()[0], "10.0.0.1".parse::<IpAddr>().unwrap());
    }
}
