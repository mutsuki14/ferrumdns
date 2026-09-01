pub mod actions;
pub mod cache;
pub mod fallback;
pub mod forward;
pub mod hosts;
pub mod sequence;
pub mod sets;

use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

use crate::context::QueryContext;
use crate::error::{Error, Result};
use crate::matcher::{DomainSet, IpSet};
use crate::metrics::Metrics;
use crate::plugin::cache::Cache;

/// What a plugin tells the sequence runner to do after `exec`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Continue,
    Accept,
    Return,
    Goto(String),
}

#[async_trait]
pub trait Executable: Send + Sync {
    async fn exec(&self, ctx: &mut QueryContext) -> Result<Action>;
}

pub struct Registry {
    pub execs: HashMap<String, Arc<dyn Executable>>,
    pub domains: HashMap<String, Arc<RwLock<DomainSet>>>,
    pub ips: HashMap<String, Arc<RwLock<IpSet>>>,
    pub caches: HashMap<String, Arc<Cache>>,
    pub metrics: Arc<Metrics>,
    pub default_entry: Option<String>,
}

impl Registry {
    pub fn get_exec(&self, tag: &str) -> Result<Arc<dyn Executable>> {
        self.execs
            .get(tag)
            .cloned()
            .ok_or_else(|| Error::UnknownTag(tag.to_string()))
    }
}
