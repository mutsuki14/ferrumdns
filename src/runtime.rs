use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::metrics::Metrics;
use crate::plugin::actions::{Blackhole, Redirect};
use crate::plugin::cache::Cache;
use crate::plugin::fallback::{BoundFallback, Fallback};
use crate::plugin::forward::Forward;
use crate::plugin::hosts::Hosts;
use crate::plugin::sequence::{compile_steps, parse_steps, Sequence};
use crate::plugin::sets;
use crate::plugin::{Action, Executable, Registry};
use crate::server;

pub struct Runtime {
    pub registry: Arc<Registry>,
    pub metrics: Arc<Metrics>,
    pub config: Config,
}

impl Runtime {
    pub async fn build(config: Config) -> Result<Arc<Self>> {
        let metrics = Metrics::new();
        let mut domains = HashMap::new();
        let mut ips = HashMap::new();
        let mut caches = HashMap::new();
        let mut execs: HashMap<String, Arc<dyn Executable>> = HashMap::new();
        let mut pending_seq: Vec<(String, serde_yaml::Value)> = Vec::new();
        let mut pending_fb: Vec<(String, Fallback)> = Vec::new();
        let mut default_entry = None;

        for p in &config.plugins {
            let tag = p.tag.clone().unwrap_or_else(|| p.ty.clone());
            match p.ty.as_str() {
                "domain_set" => {
                    domains.insert(tag, sets::domain_set(&p.args)?);
                }
                "ip_set" => {
                    ips.insert(tag, sets::ip_set(&p.args)?);
                }
                "cache" => {
                    let c = Cache::from_args(&tag, &p.args, metrics.clone());
                    caches.insert(tag.clone(), c.clone());
                    execs.insert(tag, c);
                }
                "hosts" => {
                    execs.insert(tag.clone(), Hosts::from_args(&tag, &p.args)?);
                }
                "forward" | "fast_forward" => {
                    execs.insert(
                        tag.clone(),
                        Forward::from_args(&tag, &p.args, metrics.clone()).await?,
                    );
                }
                "black_hole" | "blackhole" | "reject_any" => {
                    execs.insert(tag, Arc::new(Blackhole::from_args(&p.args)));
                }
                "redirect" => {
                    execs.insert(tag, Arc::new(Redirect::from_args(&p.args)?));
                }
                "sequence" => {
                    if default_entry.is_none() {
                        default_entry = Some(tag.clone());
                    }
                    pending_seq.push((tag, p.args.clone()));
                }
                "fallback" => {
                    pending_fb.push((tag.clone(), Fallback::from_args(&tag, &p.args)?));
                }
                other => return Err(Error::plugin(&tag, other, "unknown plugin type")),
            }
        }

        let cache_list: Vec<Arc<Cache>> = caches.values().cloned().collect();
        let mut registry = Registry {
            execs,
            domains,
            ips,
            caches,
            metrics: metrics.clone(),
            default_entry,
        };

        let compiled: Vec<(String, Sequence)> = {
            let mut v = Vec::new();
            for (tag, args) in &pending_seq {
                let raw = parse_steps(args)?;
                v.push((
                    tag.clone(),
                    compile_steps(tag, raw, &registry, cache_list.clone())?,
                ));
            }
            v
        };

        let slot: Arc<OnceLock<Arc<Registry>>> = Arc::new(OnceLock::new());
        for (tag, seq) in compiled {
            registry.execs.insert(
                tag,
                Arc::new(SlotSequence {
                    seq,
                    slot: slot.clone(),
                }),
            );
        }
        for (tag, fb) in pending_fb {
            registry.execs.insert(
                tag,
                Arc::new(SlotFallback {
                    inner: fb,
                    slot: slot.clone(),
                }),
            );
        }

        let final_reg = Arc::new(registry);
        let _ = slot.set(final_reg.clone());

        Ok(Arc::new(Runtime {
            registry: final_reg,
            metrics,
            config,
        }))
    }

    pub async fn serve(self: Arc<Self>) -> Result<()> {
        let mut handles = Vec::new();
        for srv in &self.config.servers {
            let entry = if srv.exec.is_empty() {
                self.registry
                    .default_entry
                    .clone()
                    .ok_or_else(|| Error::config("server has no exec/entry"))?
            } else {
                srv.exec.clone()
            };
            let timeout = Duration::from_secs(srv.timeout.max(1));
            for l in &srv.listeners {
                let rt = self.clone();
                let entry = entry.clone();
                let l = l.clone();
                handles.push(tokio::spawn(async move {
                    if let Err(e) = server::spawn_listener(rt, entry, timeout, l).await {
                        tracing::error!(err = %e, "listener exited");
                    }
                }));
            }
        }
        if let Some(http) = &self.config.api.http {
            let rt = self.clone();
            let http = http.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = crate::api::serve(rt, &http).await {
                    tracing::error!(err = %e, "api exited");
                }
            }));
        }
        if handles.is_empty() {
            return Err(Error::config(
                "no servers configured — add a `servers` block or a udp_server plugin",
            ));
        }
        tracing::info!(listeners = handles.len(), "ferrumdns running");
        futures::future::join_all(handles).await;
        Ok(())
    }

    pub async fn handle_query(
        &self,
        ctx: &mut crate::context::QueryContext,
        entry: &str,
    ) -> Result<()> {
        server::handle(self, entry, ctx, Duration::from_secs(5)).await
    }
}

struct SlotSequence {
    seq: Sequence,
    slot: Arc<OnceLock<Arc<Registry>>>,
}

#[async_trait::async_trait]
impl Executable for SlotSequence {
    async fn exec(&self, ctx: &mut crate::context::QueryContext) -> Result<Action> {
        let reg = self
            .slot
            .get()
            .ok_or_else(|| Error::config("runtime not ready"))?;
        self.seq.run(ctx, reg).await
    }
}

struct SlotFallback {
    inner: Fallback,
    slot: Arc<OnceLock<Arc<Registry>>>,
}

#[async_trait::async_trait]
impl Executable for SlotFallback {
    async fn exec(&self, ctx: &mut crate::context::QueryContext) -> Result<Action> {
        let reg = self
            .slot
            .get()
            .ok_or_else(|| Error::config("runtime not ready"))?;
        BoundFallback::bind(self.inner.clone(), reg.clone())
            .exec(ctx)
            .await
    }
}
