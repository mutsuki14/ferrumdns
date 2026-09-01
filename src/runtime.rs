use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock, Weak};
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

/// Hot-swappable runtime used by listeners so SIGHUP can rebuild plugins
/// without dropping UDP/TCP sockets.
#[derive(Clone)]
pub struct Live {
    inner: Arc<parking_lot::RwLock<Arc<Runtime>>>,
}

impl Live {
    pub fn new(rt: Arc<Runtime>) -> Self {
        Self {
            inner: Arc::new(parking_lot::RwLock::new(rt)),
        }
    }

    pub fn get(&self) -> Arc<Runtime> {
        self.inner.read().clone()
    }

    pub fn swap(&self, rt: Arc<Runtime>) {
        *self.inner.write() = rt;
    }

    pub async fn serve(self) -> Result<()> {
        let mut handles = Vec::new();
        let snapshot = self.get();
        for srv in &snapshot.config.servers {
            let entry = if srv.exec.is_empty() {
                snapshot
                    .registry
                    .default_entry
                    .clone()
                    .ok_or_else(|| Error::config("server has no exec/entry"))?
            } else {
                srv.exec.clone()
            };
            let timeout = Duration::from_secs(srv.timeout.max(1));
            for l in &srv.listeners {
                let live = self.clone();
                let entry = entry.clone();
                let l = l.clone();
                handles.push(tokio::spawn(async move {
                    if let Err(e) = server::spawn_listener(live, entry, timeout, l).await {
                        tracing::error!(err = %e, "listener exited");
                    }
                }));
            }
        }
        if let Some(http) = &snapshot.config.api.http {
            let live = self.clone();
            let http = http.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = crate::api::serve(live, &http).await {
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

    pub async fn reload_file(&self, path: &PathBuf) -> Result<()> {
        let cfg = Config::load_file(path)?;
        let rt = Runtime::build(cfg).await?;
        self.swap(rt);
        Ok(())
    }
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
                    domains.insert(tag, sets::domain_set(&p.args, &p.base_dir)?);
                }
                "ip_set" => {
                    ips.insert(tag, sets::ip_set(&p.args, &p.base_dir)?);
                }
                "cache" => {
                    let c = Cache::from_args(&tag, &p.args, metrics.clone());
                    caches.insert(tag.clone(), c.clone());
                    execs.insert(tag, c);
                }
                "hosts" => {
                    execs.insert(tag.clone(), Hosts::from_args(&tag, &p.args, &p.base_dir)?);
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

        let rt = Arc::new(Runtime {
            registry: final_reg,
            metrics,
            config,
        });
        bind_cache_refresh(&rt);
        Ok(rt)
    }

    pub async fn handle_query(
        &self,
        ctx: &mut crate::context::QueryContext,
        entry: &str,
    ) -> Result<()> {
        server::handle(self, entry, ctx, Duration::from_secs(5)).await
    }
}

fn bind_cache_refresh(rt: &Arc<Runtime>) {
    let Some(entry) = rt.registry.default_entry.clone() else {
        return;
    };
    let weak: Weak<Runtime> = Arc::downgrade(rt);
    for c in rt.registry.caches.values() {
        c.bind_refresh(weak.clone(), entry.clone());
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
