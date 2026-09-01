use parking_lot::RwLock;
use std::sync::Arc;

use crate::error::Result;
use crate::matcher::{DomainSet, IpSet};

pub fn domain_set(args: &serde_yaml::Value) -> Result<Arc<RwLock<DomainSet>>> {
    Ok(Arc::new(RwLock::new(DomainSet::from_args(args)?)))
}

pub fn ip_set(args: &serde_yaml::Value) -> Result<Arc<RwLock<IpSet>>> {
    Ok(Arc::new(RwLock::new(IpSet::from_args(args)?)))
}
