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
    NoEcs,
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
                let spec = parts
                    .next()
                    .ok_or_else(|| Error::config("ttl needs a value or range"))?;
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
            "no_ecs" | "_no_ecs" => Ok(Self::NoEcs),
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
            Self::NoEcs => "no_ecs".into(),
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
                if min > max {
                    return Err(Error::config("ttl minimum must not exceed maximum"));
                }
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
            Self::NoEcs => {
                dnsutil::remove_ecs(ctx.query_mut());
                ctx.strip_ecs_on_reply = true;
                Ok(Action::Continue)
            }
        }
    }
}

fn parse_ttl_range(spec: &str) -> Result<(u32, u32)> {
    if let Some((a, b)) = spec.split_once('-') {
        let min: u32 = a
            .trim()
            .parse()
            .map_err(|_| Error::config("bad ttl minimum"))?;
        let max: u32 = b
            .trim()
            .parse()
            .map_err(|_| Error::config("bad ttl maximum"))?;
        if min > max {
            return Err(Error::config("ttl minimum must not exceed maximum"));
        }
        Ok((min, max))
    } else {
        let v: u32 = spec.parse().map_err(|_| Error::config("bad ttl"))?;
        Ok((v, v))
    }
}

use crate::plugin::Executable;
use async_trait::async_trait;

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
    rules: Vec<(String, hickory_proto::rr::Name)>,
}

impl Redirect {
    pub fn from_args(args: &serde_yaml::Value) -> Result<Self> {
        let mut rules = Vec::new();
        let mut add = |from: &str, to: &str| -> Result<()> {
            let from = hickory_proto::rr::Name::from_ascii(from)
                .map_err(|e| Error::config(format!("bad redirect source `{from}`: {e}")))?;
            let to = hickory_proto::rr::Name::from_ascii(to)
                .map_err(|e| Error::config(format!("bad redirect target `{to}`: {e}")))?;
            rules.push((
                from.to_ascii().trim_end_matches('.').to_ascii_lowercase(),
                to,
            ));
            Ok(())
        };
        match args.get("rules") {
            None => {}
            Some(serde_yaml::Value::Mapping(map)) => {
                for (k, v) in map {
                    let from = k
                        .as_str()
                        .ok_or_else(|| Error::config("redirect source must be a string"))?;
                    let to = v
                        .as_str()
                        .ok_or_else(|| Error::config("redirect target must be a string"))?;
                    add(from, to)?;
                }
            }
            Some(serde_yaml::Value::Sequence(seq)) => {
                for item in seq {
                    let s = item
                        .as_str()
                        .ok_or_else(|| Error::config("redirect rule must be a string"))?;
                    let parts: Vec<_> = s.split_whitespace().collect();
                    if parts.len() != 2 {
                        return Err(Error::config("redirect rule needs source and target"));
                    }
                    add(parts[0], parts[1])?;
                }
            }
            Some(_) => return Err(Error::config("redirect rules must be a map or list")),
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
                ctx.rewrite_name(to.clone());
                ctx.push_trace("redirect", "rewrite", &format!("{qn} -> {to}"));
                break;
            }
        }
        Ok(Action::Continue)
    }
}
