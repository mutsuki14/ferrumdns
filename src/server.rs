use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::Router;
use base64::Engine;
use hickory_proto::op::ResponseCode;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio_rustls::TlsAcceptor;

use crate::config::ListenerConfig;
use crate::context::{ClientProto, QueryContext};
use crate::dnsutil::{self, Incoming};
use crate::error::{Error, Result};
use crate::plugin::{Action, Registry};
use crate::runtime::Runtime;

pub async fn spawn_listener(rt: Arc<Runtime>, entry: String, timeout: Duration, l: ListenerConfig) -> Result<()> {
    let proto = l.protocol.to_ascii_lowercase();
    let idle = Duration::from_secs(l.idle_timeout.unwrap_or(10).max(1));
    match proto.as_str() {
        "udp" | "" => spawn_udp(rt, entry, timeout, l.addr).await,
        "tcp" => spawn_tcp(rt, entry, timeout, idle, l.addr, ClientProto::Tcp, None).await,
        "tls" | "dot" => {
            let acceptor = tls_acceptor(
                l.cert.as_deref().ok_or_else(|| Error::config("tls listener needs cert"))?,
                l.key.as_deref().ok_or_else(|| Error::config("tls listener needs key"))?,
            )?;
            spawn_tcp(rt, entry, timeout, idle, l.addr, ClientProto::Tls, Some(acceptor)).await
        }
        "doh" | "https" | "http" => spawn_doh(rt, entry, timeout, l).await,
        other => Err(Error::config(format!("unknown listener protocol `{other}`"))),
    }
}

async fn spawn_udp(rt: Arc<Runtime>, entry: String, timeout: Duration, addr: String) -> Result<()> {
    let sock = bind_udp(&addr)?;
    tracing::info!(%addr, entry = %entry, "udp listen");
    let sock = Arc::new(sock);
    loop {
        let mut buf = vec![0u8; 65535];
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(err = %e, "udp recv");
                continue;
            }
        };
        let rt = rt.clone();
        let entry = entry.clone();
        let sock = sock.clone();
        tokio::spawn(async move {
            let q = match dnsutil::decode(&buf[..n]) {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!(err = %e, "bad udp query");
                    return;
                }
            };
            match dnsutil::classify_incoming(&q) {
                Incoming::Drop => return,
                Incoming::NotImp => {
                    let mut ctx = QueryContext::new(q, Some(peer.ip()), ClientProto::Udp);
                    ctx.reject(ResponseCode::NotImp);
                    if let Some(resp) = ctx.response() {
                        let max = dnsutil::udp_payload_max(ctx.query());
                        if let Ok(bytes) = dnsutil::encode_udp(resp, max) {
                            let _ = sock.send_to(&bytes, peer).await;
                        }
                    }
                    return;
                }
                Incoming::Ok => {}
            }
            let mut ctx = QueryContext::new(q, Some(peer.ip()), ClientProto::Udp);
            if let Err(e) = handle(&rt, &entry, &mut ctx, timeout).await {
                tracing::debug!(err = %e, "udp handle");
                return;
            }
            if let Some(resp) = ctx.response() {
                let max = dnsutil::udp_payload_max(ctx.query());
                if let Ok(bytes) = dnsutil::encode_udp(resp, max) {
                    let _ = sock.send_to(&bytes, peer).await;
                }
            }
        });
    }
}

fn bind_udp(addr: &str) -> Result<UdpSocket> {
    let addr: SocketAddr = addr
        .parse()
        .map_err(|e| Error::config(format!("bad listen addr {addr}: {e}")))?;
    let domain = if addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    UdpSocket::from_std(sock.into()).map_err(Error::from)
}

async fn spawn_tcp(
    rt: Arc<Runtime>,
    entry: String,
    timeout: Duration,
    idle: Duration,
    addr: String,
    proto: ClientProto,
    tls: Option<TlsAcceptor>,
) -> Result<()> {
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!(%addr, proto = proto.as_str(), entry = %entry, "stream listen");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(err = %e, "tcp accept");
                continue;
            }
        };
        let rt = rt.clone();
        let entry = entry.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let result = async {
                if let Some(acc) = tls {
                    let mut tls = acc.accept(stream).await.map_err(|e| Error::protocol(e.to_string()))?;
                    serve_framed(&rt, &entry, timeout, idle, proto, Some(peer.ip()), &mut tls).await
                } else {
                    let mut stream = stream;
                    let _ = stream.set_nodelay(true);
                    serve_framed(&rt, &entry, timeout, idle, proto, Some(peer.ip()), &mut stream).await
                }
            };
            if let Err(e) = result.await {
                tracing::debug!(err = %e, "tcp session");
            }
        });
    }
}

async fn serve_framed<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    rt: &Runtime,
    entry: &str,
    timeout: Duration,
    idle: Duration,
    proto: ClientProto,
    peer: Option<std::net::IpAddr>,
    stream: &mut S,
) -> Result<()> {
    loop {
        let mut hdr = [0u8; 2];
        match tokio::time::timeout(idle, stream.read_exact(&mut hdr)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Ok(()),
        }
        let len = u16::from_be_bytes(hdr) as usize;
        if len == 0 {
            return Err(Error::protocol("bad length"));
        }
        let mut buf = vec![0u8; len];
        tokio::time::timeout(idle, stream.read_exact(&mut buf))
            .await
            .map_err(|_| Error::protocol("idle timeout"))??;
        let q = dnsutil::decode(&buf)?;
        match dnsutil::classify_incoming(&q) {
            Incoming::Drop => continue,
            Incoming::NotImp => {
                let mut ctx = QueryContext::new(q, peer, proto);
                ctx.reject(ResponseCode::NotImp);
                write_tcp_response(stream, idle, &ctx).await?;
                continue;
            }
            Incoming::Ok => {}
        }
        let mut ctx = QueryContext::new(q, peer, proto);
        handle(rt, entry, &mut ctx, timeout).await?;
        write_tcp_response(stream, idle, &ctx).await?;
    }
}

async fn write_tcp_response<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    idle: Duration,
    ctx: &QueryContext,
) -> Result<()> {
    let Some(resp) = ctx.response() else {
        return Ok(());
    };
    let bytes = dnsutil::encode(resp)?;
    let n = bytes.len() as u16;
    tokio::time::timeout(idle, async {
        stream.write_all(&n.to_be_bytes()).await?;
        stream.write_all(&bytes).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| Error::protocol("idle timeout"))??;
    Ok(())
}

#[derive(Clone)]
struct DohState {
    rt: Arc<Runtime>,
    entry: String,
    timeout: Duration,
}

async fn spawn_doh(rt: Arc<Runtime>, entry: String, timeout: Duration, l: ListenerConfig) -> Result<()> {
    if l.cert.is_some() || l.key.is_some() {
        tracing::warn!("doh/http listener ignores cert/key — terminate TLS in front, or use protocol: tls for DoT");
    }
    let state = DohState {
        rt,
        entry,
        timeout,
    };
    let path = l.url_path.clone().unwrap_or_else(|| "/dns-query".into());
    let mut app = Router::new().route("/dns-query", post(doh_post).get(doh_get));
    if path != "/dns-query" {
        app = app.route(&path, post(doh_post).get(doh_get));
    }
    let app = app.with_state(state);

    let addr: SocketAddr = l
        .addr
        .parse()
        .map_err(|e| Error::config(format!("bad doh addr: {e}")))?;
    tracing::info!(%addr, path = %path, "doh listen (http)");
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .await
        .map_err(|e| Error::config(e.to_string()))
}

async fn doh_post(State(st): State<DohState>, headers: HeaderMap, body: Bytes) -> impl IntoResponse {
    doh_handle(&st, headers, body).await
}

async fn doh_get(State(st): State<DohState>, uri: Uri) -> impl IntoResponse {
    let Some(raw) = uri.query().and_then(dns_query_param) else {
        return (StatusCode::BAD_REQUEST, "missing dns= parameter").into_response();
    };
    doh_handle(&st, HeaderMap::new(), Bytes::from(raw)).await
}

fn dns_query_param(query: &str) -> Option<Vec<u8>> {
    for part in query.split('&') {
        let (k, v) = part.split_once('=')?;
        if k != "dns" {
            continue;
        }
        let v = percent_decode(v);
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        if let Ok(b) = engine.decode(&v) {
            return Some(b);
        }
        let padded = base64::engine::general_purpose::URL_SAFE;
        if let Ok(b) = padded.decode(&v) {
            return Some(b);
        }
    }
    None
}

fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16) {
                out.push(b as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

async fn doh_handle(st: &DohState, _headers: HeaderMap, body: Bytes) -> axum::response::Response {
    let q = match dnsutil::decode(&body) {
        Ok(m) => m,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
        }
    };
    let mut ctx = QueryContext::new(q, None, ClientProto::Https);
    if let Err(e) = handle(&st.rt, &st.entry, &mut ctx, st.timeout).await {
        return (StatusCode::BAD_GATEWAY, e.to_string()).into_response();
    }
    match ctx.response().and_then(|r| dnsutil::encode(r).ok()) {
        Some(bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/dns-message")],
            bytes,
        )
            .into_response(),
        None => StatusCode::BAD_GATEWAY.into_response(),
    }
}

fn tls_acceptor(cert: &str, key: &str) -> Result<TlsAcceptor> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certs = load_certs(Path::new(cert))?;
    let key = load_key(Path::new(key))?;
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| Error::config(e.to_string()))?;
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut r = std::io::BufReader::new(std::fs::File::open(path)?);
    rustls_pemfile::certs(&mut r)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::config(e.to_string()))
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let mut r = std::io::BufReader::new(std::fs::File::open(path)?);
    loop {
        match rustls_pemfile::read_one(&mut r) {
            Ok(Some(rustls_pemfile::Item::Pkcs8Key(k))) => return Ok(PrivateKeyDer::Pkcs8(k)),
            Ok(Some(rustls_pemfile::Item::Pkcs1Key(k))) => return Ok(PrivateKeyDer::Pkcs1(k)),
            Ok(Some(rustls_pemfile::Item::Sec1Key(k))) => return Ok(PrivateKeyDer::Sec1(k)),
            Ok(Some(_)) => continue,
            Ok(None) => return Err(Error::config(format!("no private key in {}", path.display()))),
            Err(e) => return Err(Error::config(e.to_string())),
        }
    }
}

pub async fn handle(rt: &Runtime, entry: &str, ctx: &mut QueryContext, timeout: Duration) -> Result<()> {
    match dnsutil::classify_incoming(ctx.query()) {
        Incoming::Drop => return Ok(()),
        Incoming::NotImp => {
            ctx.reject(ResponseCode::NotImp);
        }
        Incoming::Ok => {
            let exec = rt.registry.get_exec(entry)?;
            match tokio::time::timeout(timeout, exec.exec(ctx)).await {
                Ok(Ok(Action::Continue | Action::Accept | Action::Return | Action::Goto(_))) => {}
                Ok(Err(e)) => {
                    tracing::debug!(err = %e, "pipeline");
                    if !ctx.has_resp() {
                        ctx.reject(ResponseCode::ServFail);
                    }
                }
                Err(_) => {
                    ctx.reject(ResponseCode::ServFail);
                }
            }
        }
    }
    if ctx.has_resp() {
        rt.metrics
            .responses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    } else {
        rt.metrics
            .dropped
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    let us = ctx.start.elapsed().as_micros() as u64;
    rt.metrics.observe_query(us);
    Ok(())
}

pub fn registry_of(rt: &Runtime) -> &Registry {
    &rt.registry
}
