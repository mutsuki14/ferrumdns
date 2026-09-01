use hickory_proto::op::Message;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::dnsutil;
use crate::error::{Error, Result};

#[derive(Clone, Debug)]
pub struct UpstreamSpec {
    pub addr: String,
    pub dial_addr: Option<String>,
    pub bootstrap: Option<String>,
    pub idle_timeout: Duration,
    pub insecure: bool,
    pub tag: Option<String>,
}

impl UpstreamSpec {
    pub fn from_value(v: &serde_yaml::Value) -> Result<Self> {
        if let Some(s) = v.as_str() {
            return Ok(Self {
                addr: s.to_string(),
                dial_addr: None,
                bootstrap: None,
                idle_timeout: Duration::from_secs(10),
                insecure: false,
                tag: None,
            });
        }
        let addr = v
            .get("addr")
            .and_then(|x| x.as_str())
            .ok_or_else(|| Error::config("upstream missing addr"))?
            .to_string();
        Ok(Self {
            tag: v.get("tag").and_then(|x| x.as_str()).map(str::to_string),
            addr,
            dial_addr: v
                .get("dial_addr")
                .and_then(|x| x.as_str())
                .map(str::to_string),
            bootstrap: v
                .get("bootstrap")
                .and_then(|x| x.as_str())
                .map(str::to_string),
            idle_timeout: Duration::from_secs(
                v.get("idle_timeout").and_then(|x| x.as_u64()).unwrap_or(10),
            ),
            insecure: v
                .get("insecure_skip_verify")
                .or_else(|| v.get("insecure"))
                .and_then(|x| x.as_bool())
                .unwrap_or(false),
        })
    }
}

#[derive(Clone)]
pub struct Upstream {
    pub spec: UpstreamSpec,
    kind: Kind,
    http: Option<reqwest::Client>,
    tls: Option<TlsConnector>,
}

#[derive(Clone)]
enum Kind {
    Udp { target: String },
    Tcp { target: String },
    Tls { target: String, sni: String },
    Doh { url: String },
}

impl Upstream {
    pub async fn connect(spec: UpstreamSpec) -> Result<Self> {
        let addr = spec.addr.trim();
        let (scheme, rest) = split_scheme(addr);
        let kind = match scheme {
            "udp" | "" => Kind::Udp {
                target: normalize_hostport(rest, 53),
            },
            "tcp" => Kind::Tcp {
                target: normalize_hostport(rest, 53),
            },
            "tls" | "dot" => {
                let host = host_of(rest);
                Kind::Tls {
                    target: spec
                        .dial_addr
                        .clone()
                        .unwrap_or_else(|| normalize_hostport(rest, 853)),
                    sni: host,
                }
            }
            "https" | "h2" | "doh" => {
                let url = if addr.starts_with("https://") {
                    addr.to_string()
                } else {
                    format!("https://{rest}")
                };
                Kind::Doh { url }
            }
            "http" => Kind::Doh {
                url: if addr.starts_with("http") {
                    addr.to_string()
                } else {
                    format!("http://{rest}")
                },
            },
            other => {
                return Err(Error::config(format!(
                    "unsupported upstream scheme `{other}` in {addr}"
                )))
            }
        };

        let http = if matches!(kind, Kind::Doh { .. }) {
            Some(
                reqwest::Client::builder()
                    .timeout(Duration::from_secs(5))
                    .pool_idle_timeout(spec.idle_timeout)
                    .http2_adaptive_window(true)
                    .build()
                    .map_err(|e| Error::Upstream {
                        addr: spec.addr.clone(),
                        message: e.to_string(),
                    })?,
            )
        } else {
            None
        };

        let tls = if matches!(kind, Kind::Tls { .. }) {
            Some(build_tls_connector()?)
        } else {
            None
        };

        Ok(Self {
            spec,
            kind,
            http,
            tls,
        })
    }

    pub fn label(&self) -> &str {
        self.spec.tag.as_deref().unwrap_or(&self.spec.addr)
    }

    pub async fn exchange(&self, q: &Message, time_limit: Duration) -> Result<Message> {
        timeout(time_limit, self.exchange_inner(q))
            .await
            .map_err(|_| Error::Upstream {
                addr: self.spec.addr.clone(),
                message: "timeout".into(),
            })?
    }

    async fn exchange_inner(&self, q: &Message) -> Result<Message> {
        match &self.kind {
            Kind::Udp { target } => udp_exchange(target, q).await,
            Kind::Tcp { target } => tcp_exchange(target, q).await,
            Kind::Tls { target, sni } => {
                let connector = self.tls.as_ref().expect("tls connector");
                tls_exchange(connector, target, sni, q).await
            }
            Kind::Doh { url } => {
                let client = self.http.as_ref().expect("http client");
                doh_exchange(client, url, q).await
            }
        }
        .map_err(|e| Error::Upstream {
            addr: self.spec.addr.clone(),
            message: e.to_string(),
        })
    }
}

fn split_scheme(addr: &str) -> (&str, &str) {
    if let Some(i) = addr.find("://") {
        (&addr[..i], &addr[i + 3..])
    } else {
        ("", addr)
    }
}

fn host_of(rest: &str) -> String {
    let rest = rest.trim_start_matches('[');
    let host = rest.split(['/', ':', ']']).next().unwrap_or(rest);
    host.to_string()
}

fn normalize_hostport(rest: &str, default_port: u16) -> String {
    let rest = rest.split('/').next().unwrap_or(rest);
    if rest.starts_with('[') {
        if rest.contains("]:") {
            rest.to_string()
        } else {
            format!("{rest}:{default_port}")
        }
    } else if rest.chars().filter(|c| *c == ':').count() == 1 {
        rest.to_string()
    } else {
        format!("{rest}:{default_port}")
    }
}

async fn resolve_target(target: &str) -> Result<SocketAddr> {
    match tokio::net::lookup_host(target).await {
        Ok(mut it) => it
            .next()
            .ok_or_else(|| Error::config(format!("no addr for {target}"))),
        Err(e) => Err(Error::Io(e)),
    }
}

async fn udp_exchange(target: &str, q: &Message) -> Result<Message> {
    let dest = resolve_target(target).await?;
    let bind: SocketAddr = if dest.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let sock = UdpSocket::bind(bind).await?;
    let bytes = dnsutil::encode(q)?;
    sock.send_to(&bytes, dest).await?;
    let mut buf = vec![0u8; 4096];
    let (n, _) = sock.recv_from(&mut buf).await?;
    dnsutil::decode(&buf[..n])
}

async fn tcp_exchange(target: &str, q: &Message) -> Result<Message> {
    let dest = resolve_target(target).await?;
    let mut stream = TcpStream::connect(dest).await?;
    stream.set_nodelay(true)?;
    write_framed(&mut stream, q).await?;
    read_framed(&mut stream).await
}

async fn tls_exchange(
    connector: &TlsConnector,
    target: &str,
    sni: &str,
    q: &Message,
) -> Result<Message> {
    let dest = resolve_target(target).await?;
    let stream = TcpStream::connect(dest).await?;
    stream.set_nodelay(true)?;
    let name = ServerName::try_from(sni.to_string())
        .map_err(|e| Error::protocol(format!("sni {sni}: {e}")))?;
    let mut tls = connector
        .connect(name, stream)
        .await
        .map_err(|e| Error::protocol(e.to_string()))?;
    write_framed(&mut tls, q).await?;
    read_framed(&mut tls).await
}

async fn doh_exchange(client: &reqwest::Client, url: &str, q: &Message) -> Result<Message> {
    let bytes = dnsutil::encode(q)?;
    let resp = client
        .post(url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(bytes)
        .send()
        .await
        .map_err(|e| Error::protocol(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(Error::protocol(format!("doh http {}", resp.status())));
    }
    let body = resp
        .bytes()
        .await
        .map_err(|e| Error::protocol(e.to_string()))?;
    dnsutil::decode(&body)
}

async fn write_framed<S: AsyncWriteExt + Unpin>(s: &mut S, q: &Message) -> Result<()> {
    let bytes = dnsutil::encode(q)?;
    let len = bytes.len() as u16;
    s.write_all(&len.to_be_bytes()).await?;
    s.write_all(&bytes).await?;
    s.flush().await?;
    Ok(())
}

async fn read_framed<S: AsyncReadExt + Unpin>(s: &mut S) -> Result<Message> {
    let mut hdr = [0u8; 2];
    s.read_exact(&mut hdr).await?;
    let len = u16::from_be_bytes(hdr) as usize;
    if len == 0 || len > 65535 {
        return Err(Error::protocol("bad tcp length"));
    }
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf).await?;
    dnsutil::decode(&buf)
}

fn build_tls_connector() -> Result<TlsConnector> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(cfg)))
}
