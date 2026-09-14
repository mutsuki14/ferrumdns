use async_trait::async_trait;
use futures::future::{select, Either};
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
        let threshold_ms = args
            .get("threshold")
            .and_then(|v| v.as_u64())
            .unwrap_or(500);
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
            // These futures are owned by this request: dropping the outer
            // request or choosing a winner also drops the losing upstream work.
            let primary_run = Box::pin(timeout(f.threshold, async move {
                let result = primary.exec(&mut pctx).await;
                (result, pctx)
            }));
            let secondary_run = Box::pin(async move {
                let result = secondary.exec(&mut sctx).await;
                (result, sctx)
            });
            let (result, sctx) = match select(primary_run, secondary_run).await {
                Either::Left((primary_result, secondary_run)) => {
                    if let Ok((Ok(_), pctx)) = primary_result {
                        if pctx.has_wanted_ans() {
                            ctx.push_trace(&f.tag, "primary", "ok");
                            ctx.absorb(pctx);
                            return Ok(Action::Continue);
                        }
                    }
                    secondary_run.await
                }
                Either::Right((secondary_result, primary_run)) => {
                    // A ready backup must not preempt a primary that is still
                    // within its configured preference window.
                    if let Ok((Ok(_), pctx)) = primary_run.await {
                        if pctx.has_wanted_ans() {
                            ctx.push_trace(&f.tag, "primary", "ok");
                            ctx.absorb(pctx);
                            return Ok(Action::Continue);
                        }
                    }
                    secondary_result
                }
            };
            ctx.push_trace(&f.tag, "secondary", "used");
            ctx.absorb(sctx);
            result?;
            return Ok(Action::Continue);
        }

        let mut pctx = ctx.fork();
        match timeout(f.threshold, primary.exec(&mut pctx)).await {
            Ok(Ok(_)) if pctx.has_wanted_ans() => {
                ctx.push_trace(&f.tag, "primary", "ok");
                ctx.absorb(pctx);
                Ok(Action::Continue)
            }
            _ => {
                ctx.push_trace(&f.tag, "secondary", "fallback");
                let mut sctx = ctx.fork();
                let result = secondary.exec(&mut sctx).await;
                ctx.absorb(sctx);
                result?;
                Ok(Action::Continue)
            }
        }
    }
}
