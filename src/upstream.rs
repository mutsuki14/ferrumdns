use futures::stream::{FuturesUnordered, StreamExt};
use hickory_proto::op::Message;
use hickory_proto::rr::{RData, RecordType};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::dnsutil;
use crate::error::{Error, Result};

const POOL_CAP: usize = 8;
const BOOTSTRAP_QUERY_TIMEOUT: Duration = Duration::from_secs(2);

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

struct StreamPool<S> {
    slots: parking_lot::Mutex<Vec<(S, Instant)>>,
    cap: usize,
    idle: Duration,
}

impl<S> StreamPool<S> {
    fn new(cap: usize, idle: Duration) -> Arc<Self> {
        Arc::new(Self {
            slots: parking_lot::Mutex::new(Vec::with_capacity(cap)),
            cap: cap.max(1),
            idle,
        })
    }

    fn take(&self) -> Option<S> {
        let now = Instant::now();
        let mut g = self.slots.lock();
        while let Some((s, t)) = g.pop() {
            if now.saturating_duration_since(t) < self.idle {
                return Some(s);
            }
        }
        None
    }

    fn put(&self, s: S) {
        let mut g = self.slots.lock();
        if g.len() < self.cap {
            g.push((s, Instant::now()));
        }
    }
}

#[derive(Clone)]
pub struct Upstream {
    pub spec: UpstreamSpec,
    kind: Kind,
    http: Option<reqwest::Client>,
    resolver: Option<Arc<PinResolver>>,
    tls: Option<TlsConnector>,
    tcp_pool: Option<Arc<StreamPool<TcpStream>>>,
    tls_pool: Option<Arc<StreamPool<TlsStream<TcpStream>>>>,
}

#[derive(Clone)]
enum Kind {
    Udp {
        target: String,
        dest: Arc<OnceLock<SocketAddr>>,
    },
    Tcp {
        target: String,
        dest: Arc<OnceLock<SocketAddr>>,
    },
    Tls {
        target: String,
        sni: String,
        dest: Arc<OnceLock<SocketAddr>>,
    },
    Doh {
        url: String,
    },
}

impl Upstream {
    pub async fn connect(spec: UpstreamSpec) -> Result<Self> {
        let addr = spec.addr.trim();
        let (scheme, rest) = split_scheme(addr);
        let kind = match scheme {
            "udp" | "" => Kind::Udp {
                target: normalize_hostport(rest, 53),
                dest: Arc::new(OnceLock::new()),
            },
            "tcp" => Kind::Tcp {
                target: normalize_hostport(rest, 53),
                dest: Arc::new(OnceLock::new()),
            },
            "tls" | "dot" => {
                let host = host_of(rest);
                Kind::Tls {
                    target: spec
                        .dial_addr
                        .clone()
                        .map(|d| normalize_hostport(&d, 853))
                        .unwrap_or_else(|| normalize_hostport(rest, 853)),
                    sni: host,
                    dest: Arc::new(OnceLock::new()),
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

        let (http, resolver) = if matches!(kind, Kind::Doh { .. }) {
            let (client, resolver) = build_http_client(&spec, &kind)?;
            (Some(client), resolver)
        } else {
            (None, None)
        };

        let tls = if matches!(kind, Kind::Tls { .. }) {
            Some(build_tls_connector(spec.insecure)?)
        } else {
            None
        };

        let tcp_pool = if matches!(kind, Kind::Tcp { .. }) {
            Some(StreamPool::new(POOL_CAP, spec.idle_timeout))
        } else {
            None
        };
        let tls_pool = if matches!(kind, Kind::Tls { .. }) {
            Some(StreamPool::new(POOL_CAP, spec.idle_timeout))
        } else {
            None
        };

        Ok(Self {
            spec,
            kind,
            http,
            resolver,
            tls,
            tcp_pool,
            tls_pool,
        })
    }

    pub fn label(&self) -> &str {
        self.spec.tag.as_deref().unwrap_or(&self.spec.addr)
    }

    pub async fn exchange(&self, q: &Message, time_limit: Duration) -> Result<Message> {
        timeout(time_limit, self.exchange_inner(q, time_limit))
            .await
            .map_err(|_| Error::Upstream {
                addr: self.spec.addr.clone(),
                message: "timeout".into(),
            })?
    }

    async fn exchange_inner(&self, q: &Message, time_limit: Duration) -> Result<Message> {
        // Leave at least half of the exchange budget for connecting/querying
        // the resolved server when one bootstrap address family is lost.
        let bootstrap_budget = (time_limit / 2).min(BOOTSTRAP_QUERY_TIMEOUT);
        match &self.kind {
            Kind::Udp { target, dest } => {
                let dest = cached_dest(dest, &self.spec, target, bootstrap_budget).await?;
                udp_exchange_addr(dest, q).await
            }
            Kind::Tcp { target, dest } => {
                let dest = cached_dest(dest, &self.spec, target, bootstrap_budget).await?;
                let pool = self.tcp_pool.as_ref().expect("tcp pool");
                tcp_exchange_pooled(pool, dest, q).await
            }
            Kind::Tls { target, sni, dest } => {
                let dest = cached_dest(dest, &self.spec, target, bootstrap_budget).await?;
                let connector = self.tls.as_ref().expect("tls connector");
                let pool = self.tls_pool.as_ref().expect("tls pool");
                tls_exchange_pooled(pool, connector, dest, sni, q).await
            }
            Kind::Doh { url } => {
                if let Some(resolver) = &self.resolver {
                    let (host, _) = url_host_port(url, 443)?;
                    // Hyper's resolver callback does not receive this request's
                    // deadline. Prime its shared cache within our own budget.
                    resolver.resolve_host(&host, bootstrap_budget).await?;
                }
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

fn build_http_client(
    spec: &UpstreamSpec,
    kind: &Kind,
) -> Result<(reqwest::Client, Option<Arc<PinResolver>>)> {
    let Kind::Doh { url } = kind else {
        unreachable!()
    };
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .pool_idle_timeout(spec.idle_timeout)
        .http2_adaptive_window(true)
        .danger_accept_invalid_certs(spec.insecure);

    let resolver = if spec.dial_addr.is_some() || spec.bootstrap.is_some() {
        let (host, port) = url_host_port(url, if url.starts_with("http://") { 80 } else { 443 })?;
        let resolver = Arc::new(PinResolver::new(spec, &host, port)?);
        builder = builder.dns_resolver(resolver.clone());
        Some(resolver)
    } else {
        None
    };

    let client = builder.build().map_err(|e| Error::Upstream {
        addr: spec.addr.clone(),
        message: e.to_string(),
    })?;
    Ok((client, resolver))
}

#[derive(Clone)]
struct PinResolver {
    pins: Vec<SocketAddr>,
    bootstrap: Option<String>,
    cache: Arc<parking_lot::Mutex<HashMap<String, Vec<SocketAddr>>>>,
}

impl PinResolver {
    fn new(spec: &UpstreamSpec, _host: &str, port: u16) -> Result<Self> {
        let mut pins = Vec::new();
        if let Some(dial) = &spec.dial_addr {
            pins.push(parse_ip_port(dial, port)?);
        }
        Ok(Self {
            pins,
            bootstrap: spec.bootstrap.clone(),
            cache: Arc::new(parking_lot::Mutex::new(HashMap::new())),
        })
    }

    async fn resolve_host(&self, host: &str, budget: Duration) -> Result<Vec<SocketAddr>> {
        if !self.pins.is_empty() {
            return Ok(self.pins.clone());
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, 0)]);
        }
        if let Some(addrs) = self.cache.lock().get(host).cloned() {
            return Ok(addrs);
        }
        let addrs: Vec<SocketAddr> = if let Some(boot) = &self.bootstrap {
            let ips = bootstrap_ips(boot, host, budget).await?;
            tracing::info!(host, bootstrap = %boot, n = ips.len(), "bootstrap resolved");
            ips.into_iter().map(|ip| SocketAddr::new(ip, 0)).collect()
        } else {
            tokio::net::lookup_host((host, 0)).await?.collect()
        };
        self.cache.lock().insert(host.to_string(), addrs.clone());
        Ok(addrs)
    }
}

impl reqwest::dns::Resolve for PinResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        let resolver = self.clone();
        Box::pin(async move {
            let addrs = resolver
                .resolve_host(&host, BOOTSTRAP_QUERY_TIMEOUT)
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            let iter: reqwest::dns::Addrs = Box::new(addrs.into_iter());
            Ok(iter)
        })
    }
}

async fn cached_dest(
    slot: &OnceLock<SocketAddr>,
    spec: &UpstreamSpec,
    target: &str,
    bootstrap_budget: Duration,
) -> Result<SocketAddr> {
    if let Some(d) = slot.get() {
        return Ok(*d);
    }
    let d = resolve_spec(spec, target, bootstrap_budget).await?;
    Ok(*slot.get_or_init(|| d))
}

async fn resolve_spec(
    spec: &UpstreamSpec,
    target: &str,
    bootstrap_budget: Duration,
) -> Result<SocketAddr> {
    if let Some(dial) = &spec.dial_addr {
        let port = port_of(target, 53);
        return parse_ip_port(dial, port);
    }
    let host = host_of(target);
    let port = port_of(target, 53);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    if let Ok(sa) = target.parse::<SocketAddr>() {
        return Ok(sa);
    }
    if let Some(boot) = &spec.bootstrap {
        let ips = bootstrap_ips(boot, &host, bootstrap_budget).await?;
        let ip = *ips.first().ok_or_else(|| {
            Error::config(format!("bootstrap {boot} returned no addresses for {host}"))
        })?;
        tracing::info!(host = %host, bootstrap = %boot, %ip, "bootstrap resolved");
        return Ok(SocketAddr::new(ip, port));
    }
    resolve_target(target).await
}

fn parse_ip_port(s: &str, default_port: u16) -> Result<SocketAddr> {
    let s = s.trim();
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, default_port));
    }
    if let Some(inner) = s.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
        if let Ok(ip) = inner.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, default_port));
        }
    }
    Err(Error::config(format!(
        "dial_addr/bootstrap must be an IP address, got `{s}`"
    )))
}

fn bootstrap_socket(s: &str) -> Result<SocketAddr> {
    let s = s.trim();
    let s = s
        .strip_prefix("udp://")
        .or_else(|| s.strip_prefix("tcp://"))
        .unwrap_or(s);
    parse_ip_port(s, 53)
}

async fn bootstrap_ips(bootstrap: &str, hostname: &str, budget: Duration) -> Result<Vec<IpAddr>> {
    let boot = bootstrap_socket(bootstrap)?;
    let host = hostname.trim_end_matches('.');
    // Query both families concurrently, preserving partial success at the
    // deadline. Retain IPv4 preference even when the AAAA answer arrives first.
    let mut lookups = FuturesUnordered::new();
    for qtype in [RecordType::A, RecordType::AAAA] {
        lookups.push(async move {
            (
                qtype,
                timeout(
                    budget.min(BOOTSTRAP_QUERY_TIMEOUT),
                    bootstrap_query(boot, host, qtype),
                )
                .await,
            )
        });
    }
    let mut ips = Vec::new();
    while let Some((qtype, result)) = lookups.next().await {
        match result {
            Ok(Ok(list)) => ips.extend(list),
            Ok(Err(e)) => tracing::debug!(err = %e, host, ?qtype, "bootstrap lookup"),
            Err(_) => tracing::debug!(host, ?qtype, "bootstrap lookup timeout"),
        }
    }
    if !ips.is_empty() {
        ips.sort_by_key(|ip| !ip.is_ipv4());
        ips.dedup();
        return Ok(ips);
    }
    Err(Error::config(format!(
        "bootstrap {bootstrap} could not resolve {hostname}"
    )))
}

async fn bootstrap_query(boot: SocketAddr, name: &str, qtype: RecordType) -> Result<Vec<IpAddr>> {
    let fqdn = if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    };
    let q =
        crate::context::build_query(&fqdn, qtype).map_err(|e| Error::protocol(e.to_string()))?;
    let resp = udp_exchange_addr(boot, &q).await?;
    Ok(resp
        .answers()
        .iter()
        .filter_map(|r| match r.data() {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(a) => Some(IpAddr::V6(a.0)),
            _ => None,
        })
        .collect())
}

fn split_scheme(addr: &str) -> (&str, &str) {
    if let Some(i) = addr.find("://") {
        (&addr[..i], &addr[i + 3..])
    } else {
        ("", addr)
    }
}

fn host_of(rest: &str) -> String {
    let rest = rest.split('/').next().unwrap_or(rest);
    if let Some(inner) = rest.strip_prefix('[') {
        inner.split(']').next().unwrap_or(inner).to_string()
    } else if rest.parse::<std::net::Ipv6Addr>().is_ok() {
        rest.to_string()
    } else if let Some((h, p)) = rest.rsplit_once(':') {
        if p.parse::<u16>().is_ok() {
            h.to_string()
        } else {
            rest.to_string()
        }
    } else {
        rest.to_string()
    }
}

fn port_of(hostport: &str, default: u16) -> u16 {
    let rest = hostport.split('/').next().unwrap_or(hostport);
    if let Some(inner) = rest.strip_prefix('[') {
        return inner
            .split(']')
            .nth(1)
            .and_then(|s| s.strip_prefix(':'))
            .and_then(|p| p.parse().ok())
            .unwrap_or(default);
    }
    if rest.parse::<std::net::Ipv6Addr>().is_ok() {
        return default;
    }
    rest.rsplit_once(':')
        .and_then(|(_, p)| p.parse().ok())
        .unwrap_or(default)
}

fn normalize_hostport(rest: &str, default_port: u16) -> String {
    let rest = rest.split('/').next().unwrap_or(rest);
    if rest.starts_with('[') {
        if rest.contains("]:") {
            rest.to_string()
        } else {
            format!("{rest}:{default_port}")
        }
    } else if rest.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{rest}]:{default_port}")
    } else if rest.chars().filter(|c| *c == ':').count() == 1 {
        rest.to_string()
    } else {
        format!("{rest}:{default_port}")
    }
}

fn url_host_port(url: &str, default_port: u16) -> Result<(String, u16)> {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or(rest);
    Ok((
        host_of(authority).to_ascii_lowercase(),
        port_of(authority, default_port),
    ))
}

async fn resolve_target(target: &str) -> Result<SocketAddr> {
    match tokio::net::lookup_host(target).await {
        Ok(mut it) => it
            .next()
            .ok_or_else(|| Error::config(format!("no addr for {target}"))),
        Err(e) => Err(Error::Io(e)),
    }
}

async fn udp_exchange_addr(dest: SocketAddr, q: &Message) -> Result<Message> {
    let bind: SocketAddr = if dest.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let sock = UdpSocket::bind(bind).await?;
    // Connected UDP filters unexpected source IPs and ports in the kernel.
    sock.connect(dest).await?;
    let bytes = dnsutil::encode(q)?;
    sock.send(&bytes).await?;
    let mut buf = vec![0u8; 65535];
    for _ in 0..4 {
        let n = sock.recv(&mut buf).await?;
        let Ok(resp) = dnsutil::decode(&buf[..n]) else {
            continue;
        };
        if let Ok(ok) = dnsutil::take_response(q, resp) {
            if ok.truncated() {
                // Keep the original exchange deadline: this future is also
                // used by bootstrap lookups and cancelled by their deadline.
                let mut stream = TcpStream::connect(dest).await?;
                stream.set_nodelay(true)?;
                let full = framed_exchange(&mut stream, q).await?;
                if full.truncated() {
                    return Err(Error::protocol("truncated tcp response"));
                }
                return Ok(full);
            }
            return Ok(ok);
        }
    }
    Err(Error::protocol("no matching udp response"))
}

async fn framed_exchange<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    q: &Message,
) -> Result<Message> {
    write_framed(stream, q).await?;
    let resp = read_framed(stream).await?;
    dnsutil::take_response(q, resp)
}

async fn tcp_exchange_pooled(
    pool: &StreamPool<TcpStream>,
    dest: SocketAddr,
    q: &Message,
) -> Result<Message> {
    if let Some(mut stream) = pool.take() {
        match framed_exchange(&mut stream, q).await {
            Ok(msg) => {
                pool.put(stream);
                return Ok(msg);
            }
            Err(e) => tracing::debug!(err = %e, %dest, "reused tcp conn failed"),
        }
    }
    let mut stream = TcpStream::connect(dest).await?;
    stream.set_nodelay(true)?;
    let msg = framed_exchange(&mut stream, q).await?;
    pool.put(stream);
    Ok(msg)
}

async fn tls_exchange_pooled(
    pool: &StreamPool<TlsStream<TcpStream>>,
    connector: &TlsConnector,
    dest: SocketAddr,
    sni: &str,
    q: &Message,
) -> Result<Message> {
    if let Some(mut stream) = pool.take() {
        match framed_exchange(&mut stream, q).await {
            Ok(msg) => {
                pool.put(stream);
                return Ok(msg);
            }
            Err(e) => tracing::debug!(err = %e, %dest, "reused tls conn failed"),
        }
    }
    let stream = TcpStream::connect(dest).await?;
    stream.set_nodelay(true)?;
    let name = ServerName::try_from(sni.to_string())
        .map_err(|e| Error::protocol(format!("sni {sni}: {e}")))?;
    let mut tls = connector
        .connect(name, stream)
        .await
        .map_err(|e| Error::protocol(e.to_string()))?;
    let msg = framed_exchange(&mut tls, q).await?;
    pool.put(tls);
    Ok(msg)
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
    dnsutil::take_response(q, dnsutil::decode(&body)?)
}

async fn write_framed<S: AsyncWriteExt + Unpin>(s: &mut S, q: &Message) -> Result<()> {
    let bytes = dnsutil::encode(q)?;
    if bytes.len() > u16::MAX as usize {
        return Err(Error::protocol("tcp payload too large"));
    }
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

fn build_tls_connector(insecure: bool) -> Result<TlsConnector> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cfg = if insecure {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    Ok(TlsConnector::from(Arc::new(cfg)))
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bootstrap_keeps_delayed_ipv4_after_fast_ipv6() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let mock = tokio::spawn(async move {
            let mut pending_a = None;
            for _ in 0..2 {
                let mut bytes = [0; 2048];
                let (n, peer) = socket.recv_from(&mut bytes).await.unwrap();
                let q = dnsutil::decode(&bytes[..n]).unwrap();
                if q.queries()[0].query_type() == RecordType::A {
                    pending_a = Some((q, peer));
                } else {
                    let mut r =
                        dnsutil::reply_skeleton(&q, hickory_proto::op::ResponseCode::NoError);
                    r.add_answer(dnsutil::record_aaaa(
                        q.queries()[0].name().clone(),
                        60,
                        std::net::Ipv6Addr::LOCALHOST,
                    ));
                    socket
                        .send_to(&dnsutil::encode(&r).unwrap(), peer)
                        .await
                        .unwrap();
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
            let (q, peer) = pending_a.unwrap();
            let mut r = dnsutil::reply_skeleton(&q, hickory_proto::op::ResponseCode::NoError);
            r.add_answer(dnsutil::record_a(
                q.queries()[0].name().clone(),
                60,
                std::net::Ipv4Addr::LOCALHOST,
            ));
            socket
                .send_to(&dnsutil::encode(&r).unwrap(), peer)
                .await
                .unwrap();
        });
        let addresses = bootstrap_ips(
            &addr.to_string(),
            "resolver.test",
            Duration::from_millis(200),
        )
        .await
        .unwrap();
        assert_eq!(
            addresses,
            vec![
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
            ]
        );
        mock.await.unwrap();
    }

    #[tokio::test]
    async fn http_ip_literal_never_queries_bootstrap_dns() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let spec = UpstreamSpec {
            addr: "https://127.0.0.1/dns-query".into(),
            dial_addr: None,
            bootstrap: Some(socket.local_addr().unwrap().to_string()),
            idle_timeout: Duration::from_secs(10),
            insecure: false,
            tag: None,
        };
        let resolver = PinResolver::new(&spec, "127.0.0.1", 443).unwrap();
        let addresses = resolver
            .resolve_host("127.0.0.1", Duration::from_millis(10))
            .await
            .unwrap();
        assert_eq!(
            addresses,
            vec!["127.0.0.1:0".parse::<SocketAddr>().unwrap()]
        );
        let mut bytes = [0; 512];
        assert_eq!(
            socket.try_recv_from(&mut bytes).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn host_of_ipv6_and_hostport() {
        assert_eq!(
            host_of("[2606:4700:4700::1111]:853"),
            "2606:4700:4700::1111"
        );
        assert_eq!(host_of("2606:4700:4700::1111"), "2606:4700:4700::1111");
        assert_eq!(host_of("1.1.1.1:853"), "1.1.1.1");
        assert_eq!(host_of("dns.google"), "dns.google");
        assert_eq!(host_of("dns.google:853"), "dns.google");
        assert_eq!(
            normalize_hostport("2606:4700:4700::1111", 853),
            "[2606:4700:4700::1111]:853"
        );
        assert_eq!(
            normalize_hostport("[2606:4700:4700::1111]", 853),
            "[2606:4700:4700::1111]:853"
        );
        assert_eq!(normalize_hostport("1.1.1.1", 853), "1.1.1.1:853");
        assert_eq!(normalize_hostport("1.1.1.1:853", 853), "1.1.1.1:853");
    }

    #[test]
    fn bootstrap_parses_ip() {
        assert_eq!(
            bootstrap_socket("1.1.1.1").unwrap(),
            "1.1.1.1:53".parse().unwrap()
        );
        assert_eq!(
            bootstrap_socket("8.8.8.8:5353").unwrap(),
            "8.8.8.8:5353".parse().unwrap()
        );
        assert_eq!(
            bootstrap_socket("udp://9.9.9.9").unwrap(),
            "9.9.9.9:53".parse().unwrap()
        );
        assert_eq!(
            bootstrap_socket("[2606:4700:4700::1111]").unwrap(),
            "[2606:4700:4700::1111]:53".parse().unwrap()
        );
        assert!(bootstrap_socket("dns.google").is_err());
    }

    #[test]
    fn url_host_port_https() {
        let (h, p) = url_host_port("https://cloudflare-dns.com/dns-query", 443).unwrap();
        assert_eq!(h, "cloudflare-dns.com");
        assert_eq!(p, 443);
        let (h, p) = url_host_port("https://dns.google:8443/dns-query", 443).unwrap();
        assert_eq!(h, "dns.google");
        assert_eq!(p, 8443);
    }

    #[test]
    fn port_of_ipv6() {
        assert_eq!(port_of("[2606:4700:4700::1111]:853", 53), 853);
        assert_eq!(port_of("1.1.1.1:853", 53), 853);
        assert_eq!(port_of("dns.google", 853), 853);
    }
}
