use serde::Deserialize;
use serde_yaml::Value;
use std::path::Path;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub plugins: Vec<PluginConfig>,
    #[serde(default)]
    pub servers: Vec<ServerConfig>,
    #[serde(default)]
    pub api: ApiConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub file: Option<String>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            file: None,
        }
    }
}

fn default_log_level() -> String {
    "info".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct PluginConfig {
    pub tag: Option<String>,
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(default)]
    pub args: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Sequence / plugin tag that handles queries.
    #[serde(default, alias = "entry")]
    pub exec: String,
    /// Query timeout in seconds. Default 5.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,
}

fn default_timeout() -> u64 {
    5
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListenerConfig {
    /// udp | tcp | tls | dot | https | doh | http
    #[serde(default = "default_proto")]
    pub protocol: String,
    pub addr: String,
    #[serde(default)]
    pub cert: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub url_path: Option<String>,
    #[serde(default)]
    pub idle_timeout: Option<u64>,
}

fn default_proto() -> String {
    "udp".into()
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ApiConfig {
    /// Bind address for the HTTP admin API, e.g. `127.0.0.1:9090`.
    #[serde(default)]
    pub http: Option<String>,
}

impl Config {
    pub fn from_yaml(text: &str) -> Result<Self> {
        let mut cfg: Config =
            serde_yaml::from_str(text).map_err(|e| Error::config(format!("yaml parse: {e}")))?;
        cfg.lift_server_plugins();
        Ok(cfg)
    }

    pub fn load_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::config(format!("read {}: {e}", path.display())))?;
        let mut cfg = Self::from_yaml(&text)?;
        let base = path.parent().unwrap_or(Path::new("."));
        let includes = cfg.include.clone();
        for rel in includes {
            let p = base.join(rel);
            let extra = Self::load_file(&p)?;
            cfg.merge(extra);
        }
        Ok(cfg)
    }

    fn merge(&mut self, other: Config) {
        self.plugins.extend(other.plugins);
        self.servers.extend(other.servers);
        if self.api.http.is_none() {
            self.api.http = other.api.http;
        }
    }

    /// mosdns v5-style `udp_server` / `tcp_server` / `http_server` plugins
    /// are lifted into the `servers` array so the runtime has one path.
    fn lift_server_plugins(&mut self) {
        let mut keep = Vec::with_capacity(self.plugins.len());
        for p in self.plugins.drain(..) {
            match p.ty.as_str() {
                "udp_server" | "tcp_server" | "tls_server" | "http_server" | "doh_server" => {
                    let proto = match p.ty.as_str() {
                        "udp_server" => "udp",
                        "tcp_server" => "tcp",
                        "tls_server" => "tls",
                        _ => "doh",
                    };
                    let entry = p
                        .args
                        .get("entry")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let listen = p
                        .args
                        .get("listen")
                        .or_else(|| p.args.get("addr"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("0.0.0.0:53")
                        .to_string();
                    let timeout = p
                        .args
                        .get("timeout")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(5);
                    self.servers.push(ServerConfig {
                        exec: entry,
                        timeout,
                        listeners: vec![ListenerConfig {
                            protocol: proto.into(),
                            addr: listen,
                            cert: p
                                .args
                                .get("cert")
                                .and_then(|v| v.as_str())
                                .map(str::to_string),
                            key: p
                                .args
                                .get("key")
                                .and_then(|v| v.as_str())
                                .map(str::to_string),
                            url_path: p
                                .args
                                .get("path")
                                .and_then(|v| v.as_str())
                                .map(str::to_string),
                            idle_timeout: p.args.get("idle_timeout").and_then(|v| v.as_u64()),
                        }],
                    });
                }
                _ => keep.push(p),
            }
        }
        self.plugins = keep;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v5_and_lifts_servers() {
        let yaml = r#"
log:
  level: debug
plugins:
  - tag: cache
    type: cache
    args:
      size: 1024
  - tag: main
    type: sequence
    args:
      - exec: $cache
  - type: udp_server
    args:
      entry: main
      listen: 127.0.0.1:5353
"#;
        let cfg = Config::from_yaml(yaml).unwrap();
        assert_eq!(cfg.plugins.len(), 2);
        assert_eq!(cfg.servers.len(), 1);
        assert_eq!(cfg.servers[0].exec, "main");
        assert_eq!(cfg.servers[0].listeners[0].protocol, "udp");
    }
}
