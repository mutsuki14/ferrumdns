use hickory_proto::op::ResponseCode;

use crate::context::QueryContext;
use crate::dnsutil;
use crate::error::{Error, Result};
use crate::plugin::Action;

#[derive(Clone, Debug)]
pub enum Builtin {
    Accept,
    Return,
    Reject(ResponseCode),
    DropResp,
    Ttl { min: u32, max: u32 },
    PreferV4,
    PreferV6,
    Mark(u32),
    Goto(String),
}

impl Builtin {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let mut parts = s.split_whitespace();
        let head = parts.next().unwrap_or("");
        match head {
            "accept" => Ok(Self::Accept),
            "return" => Ok(Self::Return),
            "drop_resp" | "drop" => Ok(Self::DropResp),
            "prefer_ipv4" => Ok(Self::PreferV4),
            "prefer_ipv6" => Ok(Self::PreferV6),
            "reject" => {
                let code = parts.next().unwrap_or("REFUSED");
                Ok(Self::Reject(dnsutil::rcode_from_str(code)))
            }
            "ttl" => {
                let spec = parts.next().unwrap_or("0-0");
                let (min, max) = parse_ttl_range(spec)?;
                Ok(Self::Ttl { min, max })
            }
            "mark" => {
                let n = parts
                    .next()
                    .unwrap_or("0")
                    .parse()
                    .map_err(|_| Error::config("bad mark"))?;
                Ok(Self::Mark(n))
            }
            "goto" | "jump" => {
                let tag = parts
                    .next()
                    .ok_or_else(|| Error::config("goto needs a tag"))?
                    .trim_start_matches('$')
                    .to_string();
                Ok(Self::Goto(tag))
            }
            other => Err(Error::config(format!(
                "unknown builtin exec `{other}` (did you forget `$` for a plugin tag?)"
            ))),
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::Accept => "accept".into(),
            Self::Return => "return".into(),
            Self::Reject(c) => format!("reject {c}"),
            Self::DropResp => "drop_resp".into(),
            Self::Ttl { min, max } => format!("ttl {min}-{max}"),
            Self::PreferV4 => "prefer_ipv4".into(),
            Self::PreferV6 => "prefer_ipv6".into(),
            Self::Mark(m) => format!("mark {m}"),
            Self::Goto(t) => format!("goto {t}"),
        }
    }

    pub fn apply(&self, ctx: &mut QueryContext) -> Result<Action> {
        match self {
            Self::Accept => Ok(Action::Accept),
            Self::Return => Ok(Action::Return),
            Self::Reject(c) => {
                ctx.reject(*c);
                Ok(Action::Accept)
            }
            Self::DropResp => {
                ctx.drop_response();
                Ok(Action::Continue)
            }
            Self::Ttl { min, max } => {
                ctx.apply_ttl_clamp(*min, *max);
                Ok(Action::Continue)
            }
            Self::PreferV4 => {
                ctx.prefer_ipv4();
                Ok(Action::Continue)
            }
            Self::PreferV6 => {
                ctx.prefer_ipv6();
                Ok(Action::Continue)
            }
            Self::Mark(m) => {
                ctx.add_mark(*m);
                Ok(Action::Continue)
            }
            Self::Goto(t) => Ok(Action::Goto(t.clone())),
        }
    }
}

fn parse_ttl_range(spec: &str) -> Result<(u32, u32)> {
    if let Some((a, b)) = spec.split_once('-') {
        let min: u32 = a.trim().parse().unwrap_or(0);
        let max: u32 = b.trim().parse().unwrap_or(u32::MAX);
        Ok((min, max))
    } else {
        let v: u32 = spec.parse().map_err(|_| Error::config("bad ttl"))?;
        Ok((v, v))
    }
}

use async_trait::async_trait;
use crate::plugin::Executable;

pub struct Blackhole {
    rcode: ResponseCode,
}

impl Blackhole {
    pub fn from_args(args: &serde_yaml::Value) -> Self {
        let rcode = args
            .get("rcode")
            .and_then(|v| v.as_str())
            .map(dnsutil::rcode_from_str)
            .unwrap_or(ResponseCode::NXDomain);
        Self { rcode }
    }
}

#[async_trait]
impl Executable for Blackhole {
    async fn exec(&self, ctx: &mut QueryContext) -> Result<Action> {
        ctx.reject(self.rcode);
        Ok(Action::Continue)
    }
}

pub struct Redirect {
    rules: Vec<(String, String)>,
}

impl Redirect {
    pub fn from_args(args: &serde_yaml::Value) -> Result<Self> {
        let mut rules = Vec::new();
        if let Some(map) = args.get("rules").and_then(|v| v.as_mapping()) {
            for (k, v) in map {
                if let (Some(from), Some(to)) = (k.as_str(), v.as_str()) {
                    rules.push((from.to_ascii_lowercase(), to.to_string()));
                }
            }
        }
        if let Some(seq) = args.get("rules").and_then(|v| v.as_sequence()) {
            for item in seq {
                if let Some(s) = item.as_str() {
                    if let Some((a, b)) = s.split_once(' ') {
                        rules.push((a.to_ascii_lowercase(), b.to_string()));
                    }
                }
            }
        }
        Ok(Self { rules })
    }
}

#[async_trait]
impl Executable for Redirect {
    async fn exec(&self, ctx: &mut QueryContext) -> Result<Action> {
        let qn = ctx.qname_str().trim_end_matches('.').to_ascii_lowercase();
        for (from, to) in &self.rules {
            let from = from.trim_end_matches('.');
            if qn == from || qn.ends_with(&format!(".{from}")) {
                if let Ok(name) = hickory_proto::rr::Name::from_ascii(to) {
                    if let Some(q) = ctx.query_mut().queries_mut().first_mut() {
                        q.set_name(name);
                    }
                    ctx.push_trace("redirect", "rewrite", &format!("{qn} -> {to}"));
                }
                break;
            }
        }
        Ok(Action::Continue)
    }
}
