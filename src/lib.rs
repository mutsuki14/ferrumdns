pub mod api;
pub mod config;
pub mod context;
pub mod dnsutil;
pub mod error;
pub mod matcher;
pub mod metrics;
pub mod plugin;
pub mod runtime;
pub mod server;
pub mod upstream;

pub use config::Config;
pub use runtime::Runtime;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
