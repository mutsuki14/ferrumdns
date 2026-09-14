use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::metrics::Metrics;
use crate::plugin::actions::{Blackhole, Builtin, Redirect};
use crate::plugin::cache::Cache;
use crate::plugin::ecs::{Ecs, NoEcs};
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
        // Copy only listener settings, so this future does not keep the first
        // runtime (and its old caches/rules) alive across every reload.
        let (servers, api) = {
            let snapshot = self.get();
            snapshot.validate_service()?;
            (
                snapshot.config.servers.clone(),
                snapshot.config.api.http.clone(),
            )
        };
        let mut handles = tokio::task::JoinSet::new();
        for srv in servers {
            let entry = srv.exec;
            let timeout = Duration::from_secs(srv.timeout.max(1));
            for l in srv.listeners {
                let live = self.clone();
                let entry = entry.clone();
                handles.spawn(async move { server::spawn_listener(live, entry, timeout, l).await });
            }
        }
        if let Some(http) = api {
            let live = self.clone();
            handles.spawn(async move { crate::api::serve(live, &http).await });
        }
        tracing::info!(listeners = handles.len(), "starting listeners");
        let error = match handles.join_next().await {
            Some(Ok(Err(error))) => error,
            Some(Err(error)) => Error::config(format!("listener task failed: {error}")),
            _ => Error::config("listener exited unexpectedly"),
        };
        // One dead listener is a failed service, not a partially healthy one.
        // JoinSet also aborts the children if serve() is cancelled by shutdown.
        handles.shutdown().await;
        Err(error)
    }

    pub async fn reload_file(&self, path: &PathBuf) -> Result<()> {
        let cfg = Config::load_file(path)?;
        let rt = Runtime::build(cfg).await?;
        let previous = self.get();
        if previous.config.servers != rt.config.servers || previous.config.api != rt.config.api {
            return Err(Error::config(
                "listener, entry or API changes require a process restart",
            ));
        }
        if previous.config.log != rt.config.log {
            return Err(Error::config("logging changes require a process restart"));
        }
        self.swap(rt);
        Ok(())
    }
}

impl Runtime {
    pub async fn build(mut config: Config) -> Result<Arc<Self>> {
        config.normalize_entries()?;
        validate_plugin_graph(&config)?;
        validate_settings(&config)?;
        let metrics = Metrics::new();
        let mut domains = HashMap::new();
        let mut ips = HashMap::new();
        let mut caches = HashMap::new();
        let mut execs: HashMap<String, Arc<dyn Executable>> = HashMap::new();
        let mut pending_seq: Vec<(String, serde_yaml::Value)> = Vec::new();
        let mut pending_fb: Vec<(String, Fallback)> = Vec::new();

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
                "ecs" => {
                    execs.insert(tag.clone(), Ecs::from_args(&tag, &p.args)?);
                }
                "no_ecs" | "_no_ecs" => {
                    execs.insert(tag.clone(), NoEcs::new(tag));
                }
                "sequence" => {
                    pending_seq.push((tag, p.args.clone()));
                }
                "fallback" => {
                    pending_fb.push((tag.clone(), Fallback::from_args(&tag, &p.args)?));
                }
                other => return Err(Error::plugin(&tag, other, "unknown plugin type")),
            }
        }

        let default_entry = pick_default_entry(&config, &pending_seq);
        for srv in &mut config.servers {
            if srv.exec.is_empty() {
                srv.exec = default_entry
                    .clone()
                    .ok_or_else(|| Error::config("server has no exec/entry"))?;
            }
        }
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
                v.push((tag.clone(), compile_steps(tag, raw, &registry)?));
            }
            v
        };

        let slot: Arc<OnceLock<Weak<Registry>>> = Arc::new(OnceLock::new());
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
        for srv in &config.servers {
            final_reg.get_exec(&srv.exec)?;
        }
        let _ = slot.set(Arc::downgrade(&final_reg));

        let rt = Arc::new(Runtime {
            registry: final_reg,
            metrics,
            config,
        });
        bind_cache_refresh(&rt);
        Ok(rt)
    }

    /// Library users may build a pipeline alone; CLI check/start require an
    /// actual service endpoint in addition to a valid pipeline.
    pub fn validate_service(&self) -> Result<()> {
        if self.config.api.http.is_none()
            && self
                .config
                .servers
                .iter()
                .all(|server| server.listeners.is_empty())
        {
            return Err(Error::config(
                "no listeners configured — add a server or admin API",
            ));
        }
        Ok(())
    }

    pub async fn handle_query(
        &self,
        ctx: &mut crate::context::QueryContext,
        entry: &str,
    ) -> Result<()> {
        server::handle(
            self,
            entry.trim().trim_start_matches('$'),
            ctx,
            Duration::from_secs(5),
        )
        .await
    }
}

fn pick_default_entry(
    config: &Config,
    pending_seq: &[(String, serde_yaml::Value)],
) -> Option<String> {
    for s in &config.servers {
        let e = s.exec.trim_start_matches('$');
        if !e.is_empty() {
            return Some(e.to_string());
        }
    }
    pending_seq.last().map(|(tag, _)| tag.clone())
}

fn validate_settings(config: &Config) -> Result<()> {
    config
        .log
        .level
        .parse::<tracing::level_filters::LevelFilter>()
        .map_err(|e| Error::config(format!("bad log level: {e}")))?;
    if config
        .log
        .file
        .as_deref()
        .is_some_and(|path| path.trim().is_empty())
    {
        return Err(Error::config("log.file must not be empty"));
    }
    if let Some(bind) = &config.api.http {
        bind.parse::<SocketAddr>()
            .map_err(|e| Error::config(format!("bad api addr {bind}: {e}")))?;
    }
    for srv in &config.servers {
        for listener in &srv.listeners {
            server::validate_listener(listener)?;
        }
    }
    Ok(())
}

/// Resolve the entire call graph before any request can execute it. A timeout
/// cannot protect recursively polled futures from overflowing the thread stack.
fn validate_plugin_graph(config: &Config) -> Result<()> {
    let mut tags = HashSet::new();
    let mut edges = HashMap::<String, Vec<String>>::new();
    for plugin in &config.plugins {
        let tag = plugin.tag.as_deref().unwrap_or(&plugin.ty);
        if tag.is_empty() || tag.starts_with('$') || tag.chars().any(char::is_whitespace) {
            return Err(Error::config(format!("invalid plugin tag `{tag}`")));
        }
        if !tags.insert(tag.to_string()) {
            return Err(Error::config(format!("duplicate plugin tag `{tag}`")));
        }
        if matches!(plugin.ty.as_str(), "domain_set" | "ip_set") {
            continue;
        }
        let mut calls = Vec::new();
        match plugin.ty.as_str() {
            "sequence" => {
                for step in parse_steps(&plugin.args)? {
                    let exec = step.exec.trim();
                    if let Some(target) = exec.strip_prefix('$') {
                        calls.push(target.to_string());
                    } else if let Builtin::Goto(target) = Builtin::parse(exec)? {
                        calls.push(target);
                    }
                }
            }
            "fallback" => {
                let fallback = Fallback::from_args(tag, &plugin.args)?;
                calls.extend([fallback.primary, fallback.secondary]);
            }
            _ => {}
        }
        edges.insert(tag.to_string(), calls);
    }
    for (tag, calls) in &edges {
        for target in calls {
            if !edges.contains_key(target) {
                return Err(Error::config(format!(
                    "plugin `{tag}` references unknown executable `{target}`"
                )));
            }
        }
    }
    let mut depths = HashMap::new();
    for tag in edges.keys() {
        visit_plugin(tag, &edges, &mut Vec::new(), &mut depths)?;
    }
    Ok(())
}

fn visit_plugin(
    tag: &str,
    edges: &HashMap<String, Vec<String>>,
    active: &mut Vec<String>,
    depths: &mut HashMap<String, usize>,
) -> Result<usize> {
    const MAX_PIPELINE_DEPTH: usize = 64;
    if let Some(&depth) = depths.get(tag) {
        return Ok(depth);
    }
    if active.iter().any(|entry| entry == tag) {
        let chain = active
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(tag))
            .collect::<Vec<_>>()
            .join(" -> ");
        return Err(Error::config(format!("plugin reference cycle: {chain}")));
    }
    if active.len() >= MAX_PIPELINE_DEPTH {
        return Err(Error::config(format!(
            "plugin call depth exceeds {MAX_PIPELINE_DEPTH}"
        )));
    }
    active.push(tag.to_string());
    let mut depth = 1;
    for target in &edges[tag] {
        depth = depth.max(1 + visit_plugin(target, edges, active, depths)?);
    }
    active.pop();
    if depth > MAX_PIPELINE_DEPTH {
        return Err(Error::config(format!(
            "plugin call depth exceeds {MAX_PIPELINE_DEPTH}"
        )));
    }
    depths.insert(tag.to_string(), depth);
    Ok(depth)
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
    slot: Arc<OnceLock<Weak<Registry>>>,
}

#[async_trait::async_trait]
impl Executable for SlotSequence {
    async fn exec(&self, ctx: &mut crate::context::QueryContext) -> Result<Action> {
        let reg = self
            .slot
            .get()
            .and_then(Weak::upgrade)
            .ok_or_else(|| Error::config("runtime not ready"))?;
        self.seq.run(ctx, &reg).await
    }
}

struct SlotFallback {
    inner: Fallback,
    slot: Arc<OnceLock<Weak<Registry>>>,
}

#[async_trait::async_trait]
impl Executable for SlotFallback {
    async fn exec(&self, ctx: &mut crate::context::QueryContext) -> Result<Action> {
        let reg = self
            .slot
            .get()
            .and_then(Weak::upgrade)
            .ok_or_else(|| Error::config("runtime not ready"))?;
        BoundFallback::bind(self.inner.clone(), reg.clone())
            .exec(ctx)
            .await
    }
}
