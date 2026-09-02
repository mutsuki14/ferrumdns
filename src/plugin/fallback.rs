use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

use crate::context::QueryContext;
use crate::error::{Error, Result};
use crate::plugin::{Action, Executable, Registry};

#[derive(Clone)]
pub struct Fallback {
    pub tag: String,
    pub primary: String,
    pub secondary: String,
    pub threshold: Duration,
    pub always_standby: bool,
}

impl Fallback {
    pub fn from_args(tag: &str, args: &serde_yaml::Value) -> Result<Self> {
        let primary = args
            .get("primary")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::config("fallback needs `primary`"))?
            .trim_start_matches('$')
            .to_string();
        let secondary = args
            .get("secondary")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::config("fallback needs `secondary`"))?
            .trim_start_matches('$')
            .to_string();
        let threshold_ms = args.get("threshold").and_then(|v| v.as_u64()).unwrap_or(500);
        let always_standby = args
            .get("always_standby")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        Ok(Self {
            tag: tag.to_string(),
            primary,
            secondary,
            threshold: Duration::from_millis(threshold_ms),
            always_standby,
        })
    }
}

pub struct BoundFallback {
    inner: Fallback,
    reg: Arc<Registry>,
}

impl BoundFallback {
    pub fn bind(inner: Fallback, reg: Arc<Registry>) -> Arc<Self> {
        Arc::new(Self { inner, reg })
    }
}

#[async_trait]
impl Executable for BoundFallback {
    async fn exec(&self, ctx: &mut QueryContext) -> Result<Action> {
        let f = &self.inner;
        let primary = self.reg.get_exec(&f.primary)?;
        let secondary = self.reg.get_exec(&f.secondary)?;

        if f.always_standby {
            let mut pctx = ctx.fork();
            let mut sctx = ctx.fork();
            let p = primary.clone();
            let s = secondary.clone();
            let thresh = f.threshold;

            let mut primary_task = tokio::spawn(async move {
                let _ = p.exec(&mut pctx).await;
                pctx
            });
            let secondary_task = tokio::spawn(async move {
                let _ = s.exec(&mut sctx).await;
                sctx
            });

            match timeout(thresh, &mut primary_task).await {
                Ok(Ok(pctx)) if pctx.has_wanted_ans() => {
                    secondary_task.abort();
                    ctx.push_trace(&f.tag, "primary", "ok");
                    ctx.absorb(pctx);
                    return Ok(Action::Continue);
                }
                Ok(_) => {}
                Err(_) => {
                    primary_task.abort();
                }
            }
            if let Ok(sctx) = secondary_task.await {
                ctx.push_trace(&f.tag, "secondary", "used");
                ctx.absorb(sctx);
            }
            return Ok(Action::Continue);
        }

        match timeout(f.threshold, primary.exec(ctx)).await {
            Ok(Ok(_)) if ctx.has_wanted_ans() => {
                ctx.push_trace(&f.tag, "primary", "ok");
                Ok(Action::Continue)
            }
            _ => {
                ctx.drop_response();
                ctx.push_trace(&f.tag, "secondary", "fallback");
                secondary.exec(ctx).await?;
                Ok(Action::Continue)
            }
        }
    }
}
