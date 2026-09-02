use async_trait::async_trait;
use serde_yaml::Value;
use std::sync::Arc;

use crate::context::QueryContext;
use crate::dnsutil;
use crate::error::{Error, Result};
use crate::matcher::Matcher;
use crate::plugin::actions::Builtin;
use crate::plugin::cache::Cache;
use crate::plugin::{Action, Executable, Registry};

pub struct Sequence {
    pub tag: String,
    steps: Vec<Step>,
    caches: Vec<Arc<Cache>>,
}

struct Step {
    matchers: Vec<Matcher>,
    exec: Exec,
}

enum Exec {
    Plugin(String),
    Builtin(Builtin),
}

#[derive(Clone)]
pub struct RawStep {
    pub matches: Vec<String>,
    pub exec: String,
}

impl RawStep {
    fn from_value(item: Value) -> Result<Self> {
        match item {
            Value::String(s) => Ok(Self {
                matches: Vec::new(),
                exec: s,
            }),
            Value::Mapping(m) => {
                let exec = m
                    .get(&Value::from("exec"))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| Error::config("sequence step missing exec"))?
                    .to_string();
                let matches = match m.get(&Value::from("matches")) {
                    None => Vec::new(),
                    Some(Value::String(s)) => vec![s.clone()],
                    Some(Value::Sequence(seq)) => seq
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect(),
                    _ => Vec::new(),
                };
                Ok(Self { matches, exec })
            }
            _ => Err(Error::config("invalid sequence step")),
        }
    }
}

pub fn parse_steps(args: &Value) -> Result<Vec<RawStep>> {
    let seq = match args {
        Value::Sequence(s) => s.clone(),
        other => vec![other.clone()],
    };
    seq.into_iter().map(RawStep::from_value).collect()
}

fn parse_exec(s: &str) -> Result<Exec> {
    let s = s.trim();
    if let Some(tag) = s.strip_prefix('$') {
        return Ok(Exec::Plugin(tag.to_string()));
    }
    Ok(Exec::Builtin(Builtin::parse(s)?))
}

pub fn bind_matcher(expr: &str, reg: &Registry) -> Result<Matcher> {
    let expr = expr.trim();
    if let Some(rest) = expr.strip_prefix('!') {
        let inner = bind_matcher(rest.trim(), reg)?;
        return Ok(Matcher::Neg(Box::new(inner)));
    }
    let mut parts = expr.split_whitespace();
    let head = parts.next().unwrap_or("");
    match head {
        "has_resp" => Ok(Matcher::HasResp),
        "has_wanted_ans" => Ok(Matcher::HasWantedAns),
        "qname" => {
            let tag = parts
                .next()
                .ok_or_else(|| Error::config("qname matcher needs a domain_set tag"))?
                .trim_start_matches('$');
            let set = reg
                .domains
                .get(tag)
                .cloned()
                .ok_or_else(|| Error::UnknownTag(tag.to_string()))?;
            Ok(Matcher::Qname(set))
        }
        "qtype" => {
            let types = parts.filter_map(dnsutil::qtype_from_str).collect();
            Ok(Matcher::Qtype(types))
        }
        "client_ip" => {
            let tag = parts
                .next()
                .ok_or_else(|| Error::config("client_ip matcher needs an ip_set tag"))?
                .trim_start_matches('$');
            let set = reg
                .ips
                .get(tag)
                .cloned()
                .ok_or_else(|| Error::UnknownTag(tag.to_string()))?;
            Ok(Matcher::ClientIp(set))
        }
        "resp_ip" => {
            let tag = parts
                .next()
                .ok_or_else(|| Error::config("resp_ip matcher needs an ip_set tag"))?
                .trim_start_matches('$');
            let set = reg
                .ips
                .get(tag)
                .cloned()
                .ok_or_else(|| Error::UnknownTag(tag.to_string()))?;
            Ok(Matcher::RespIp(set))
        }
        "rcode" => {
            let c = parts.next().unwrap_or("NOERROR");
            Ok(Matcher::Rcode(dnsutil::rcode_to_u16(
                dnsutil::rcode_from_str(c),
            )))
        }
        "mark" => {
            let n = parts.next().unwrap_or("0").parse().unwrap_or(0);
            Ok(Matcher::Mark(n))
        }
        "ecs" | "has_ecs" => Ok(Matcher::HasEcs),
        other => Err(Error::config(format!("unknown matcher `{other}`"))),
    }
}

pub fn compile_steps(
    tag: &str,
    raw: Vec<RawStep>,
    reg: &Registry,
    caches: Vec<Arc<Cache>>,
) -> Result<Sequence> {
    let mut steps = Vec::new();
    for r in raw {
        let matchers = r
            .matches
            .iter()
            .map(|s| bind_matcher(s, reg))
            .collect::<Result<Vec<_>>>()?;
        let exec = parse_exec(&r.exec)?;
        steps.push(Step { matchers, exec });
    }
    Ok(Sequence {
        tag: tag.to_string(),
        steps,
        caches,
    })
}

impl Sequence {
    pub async fn run(&self, ctx: &mut QueryContext, reg: &Registry) -> Result<Action> {
        let mut i = 0;
        while i < self.steps.len() {
            let ok = self.steps[i].matchers.iter().all(|m| m.matches(ctx));
            if !ok {
                i += 1;
                continue;
            }
            let action = match &self.steps[i].exec {
                Exec::Plugin(tag) => {
                    let p = reg.get_exec(tag)?;
                    ctx.push_trace(&self.tag, "exec", tag);
                    p.exec(ctx).await?
                }
                Exec::Builtin(b) => {
                    ctx.push_trace(&self.tag, "builtin", b.label());
                    b.apply(ctx)?
                }
            };
            match action {
                Action::Continue => i += 1,
                Action::Accept => {
                    self.store(ctx);
                    return Ok(Action::Accept);
                }
                Action::Return => {
                    self.store(ctx);
                    return Ok(Action::Continue);
                }
                Action::Goto(tag) => {
                    let p = reg.get_exec(&tag)?;
                    let a = p.exec(ctx).await?;
                    self.store(ctx);
                    return Ok(a);
                }
            }
        }
        self.store(ctx);
        Ok(Action::Continue)
    }

    fn store(&self, ctx: &QueryContext) {
        for c in &self.caches {
            c.maybe_store(ctx);
        }
    }
}

pub struct BoundSequence {
    seq: Sequence,
    reg: Arc<Registry>,
}

impl BoundSequence {
    pub fn new(seq: Sequence, reg: Arc<Registry>) -> Arc<Self> {
        Arc::new(Self { seq, reg })
    }
}

#[async_trait]
impl Executable for BoundSequence {
    async fn exec(&self, ctx: &mut QueryContext) -> Result<Action> {
        self.seq.run(ctx, &self.reg).await
    }
}
