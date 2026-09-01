use async_trait::async_trait;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

use crate::context::QueryContext;
use crate::dnsutil;
use crate::error::{Error, Result};
use crate::metrics::Metrics;
use crate::plugin::{Action, Executable};
use crate::upstream::{Upstream, UpstreamSpec};

pub struct Forward {
    tag: String,
    upstreams: Vec<Upstream>,
    concurrent: usize,
    timeout: Duration,
    metrics: Arc<Metrics>,
}

impl Forward {
    pub async fn from_args(
        tag: &str,
        args: &serde_yaml::Value,
        metrics: Arc<Metrics>,
    ) -> Result<Arc<Self>> {
        let list = args
            .get("upstreams")
            .or_else(|| args.get("upstream"))
            .ok_or_else(|| Error::config(format!("forward `{tag}` has no upstreams")))?;
        let items = match list {
            serde_yaml::Value::Sequence(s) => s.clone(),
            other => vec![other.clone()],
        };
        if items.is_empty() {
            return Err(Error::config(format!("forward `{tag}` has empty upstreams")));
        }
        let mut upstreams = Vec::new();
        for item in items {
            let spec = UpstreamSpec::from_value(&item)?;
            upstreams.push(Upstream::connect(spec).await?);
        }
        let concurrent = args
            .get("concurrent")
            .and_then(|v| v.as_u64())
            .unwrap_or(1)
            .max(1) as usize;
        let timeout_raw = args
            .get("timeout")
            .and_then(|v| v.as_u64())
            .unwrap_or(5000);
        if timeout_raw > 0 && timeout_raw < 50 {
            tracing::warn!(
                plugin = %tag,
                timeout_ms = timeout_raw,
                "forward `timeout` is milliseconds (5 means 5ms, not 5s)"
            );
        }
        let timeout = Duration::from_millis(timeout_raw.max(1));
        Ok(Arc::new(Self {
            tag: tag.to_string(),
            upstreams,
            concurrent,
            timeout,
            metrics,
        }))
    }
}

#[async_trait]
impl Executable for Forward {
    async fn exec(&self, ctx: &mut QueryContext) -> Result<Action> {
        let q = ctx.query().clone();
        let n = self.concurrent.min(self.upstreams.len()).max(1);

        if n == 1 {
            match self.upstreams[0].exchange(&q, self.timeout).await {
                Ok(msg) if dnsutil::is_usable_response(&msg) => {
                    self.metrics.upstream_ok.fetch_add(1, Ordering::Relaxed);
                    ctx.push_trace(&self.tag, "ok", self.upstreams[0].label());
                    ctx.set_response(msg);
                }
                Ok(msg) => {
                    self.metrics.upstream_err.fetch_add(1, Ordering::Relaxed);
                    ctx.push_trace(&self.tag, "err", "unusable rcode");
                    ctx.set_response(msg);
                }
                Err(e) => {
                    self.metrics.upstream_err.fetch_add(1, Ordering::Relaxed);
                    ctx.push_trace(&self.tag, "err", &e.to_string());
                    tracing::debug!(plugin = %self.tag, err = %e, "upstream failed");
                }
            }
            return Ok(Action::Continue);
        }

        let (tx, mut rx) = mpsc::channel::<(usize, Result<hickory_proto::op::Message>)>(n);
        for (i, up) in self.upstreams.iter().take(n).enumerate() {
            let up = up.clone();
            let q = q.clone();
            let tx = tx.clone();
            let timeout = self.timeout;
            tokio::spawn(async move {
                let r = up.exchange(&q, timeout).await;
                let _ = tx.send((i, r)).await;
            });
        }
        drop(tx);

        let mut last_err: Option<String> = None;
        let mut last_unusable: Option<hickory_proto::op::Message> = None;
        while let Some((i, r)) = rx.recv().await {
            match r {
                Ok(msg) if dnsutil::is_usable_response(&msg) => {
                    self.metrics.upstream_ok.fetch_add(1, Ordering::Relaxed);
                    ctx.push_trace(&self.tag, "ok", self.upstreams[i].label());
                    ctx.set_response(msg);
                    return Ok(Action::Continue);
                }
                Ok(msg) => {
                    self.metrics.upstream_err.fetch_add(1, Ordering::Relaxed);
                    last_err = Some(format!("{} unusable rcode", self.upstreams[i].label()));
                    last_unusable = Some(msg);
                }
                Err(e) => {
                    self.metrics.upstream_err.fetch_add(1, Ordering::Relaxed);
                    last_err = Some(e.to_string());
                }
            }
        }
        if let Some(msg) = last_unusable {
            ctx.set_response(msg);
        }
        ctx.push_trace(
            &self.tag,
            "err",
            last_err.as_deref().unwrap_or("all upstreams failed"),
        );
        Ok(Action::Continue)
    }
}
