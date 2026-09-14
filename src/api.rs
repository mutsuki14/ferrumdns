use axum::body::Bytes;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Json;
use axum::Router;
use serde::Deserialize;
use std::net::SocketAddr;
use std::time::Instant;

use crate::context::{build_query, ClientProto, QueryContext, TraceEvent};
use crate::dnsutil;
use crate::error::Result;
use crate::metrics::Snapshot;
use crate::runtime::Live;

#[derive(Clone)]
struct AppState {
    live: Live,
    id_prefix: u64,
    initial_started: Instant,
}

pub async fn serve(live: Live, bind: &str) -> Result<()> {
    let addr: SocketAddr = bind
        .parse()
        .map_err(|e| crate::error::Error::config(format!("bad api addr {bind}: {e}")))?;
    let state = AppState {
        initial_started: live.get().metrics.started,
        live,
        id_prefix: rand::random(),
    };
    let app = Router::new()
        .route("/", get(index))
        .route("/assets/style.css", get(stylesheet))
        .route("/assets/app.js", get(javascript))
        .route("/favicon.svg", get(favicon))
        .route("/health", get(health))
        .route("/metrics", get(metrics_prom))
        .route("/api/system", get(system))
        .route("/api/stats", get(stats))
        .route("/api/plugins", get(plugins))
        .route("/api/query", post(query))
        .route("/api/cache/flush", post(flush))
        .layer(middleware::from_fn(response_headers))
        .with_state(state);
    tracing::info!(%addr, "admin api");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .await
        .map_err(|e| crate::error::Error::config(e.to_string()))
}

async fn response_headers(request: Request, next: Next) -> Response {
    let mut response = if request.uri().path().starts_with("/api/")
        && !request.method().is_safe()
        && !trusted_browser_source(request.headers())
    {
        (
            StatusCode::FORBIDDEN,
            "cross-origin API writes are not allowed",
        )
            .into_response()
    } else {
        next.run(request).await
    };
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        ),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

/// Browsers attach source metadata even to empty form submissions. Keep older
/// CLI clients working when neither header is present, while rejecting browser
/// writes from other origins before they can reach a mutating handler.
fn trusted_browser_source(headers: &HeaderMap) -> bool {
    let mut sites = headers.get_all("sec-fetch-site").iter();
    if let Some(site) = sites.next() {
        if sites.next().is_some() || !matches!(site.to_str(), Ok("same-origin" | "none")) {
            return false;
        }
    }

    let mut origins = headers.get_all(header::ORIGIN).iter();
    let Some(origin) = origins.next() else {
        return true;
    };
    if origins.next().is_some() {
        return false;
    }
    let Some(origin) = origin
        .to_str()
        .ok()
        .and_then(|value| reqwest::Url::parse(value).ok())
    else {
        return false;
    };
    if !matches!(origin.scheme(), "http" | "https")
        || origin.host_str().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return false;
    }

    let mut hosts = headers.get_all(header::HOST).iter();
    let Some(host) = hosts.next().and_then(|value| value.to_str().ok()) else {
        return false;
    };
    if hosts.next().is_some()
        || host.contains('@')
        || host.parse::<axum::http::uri::Authority>().is_err()
    {
        return false;
    }
    // The API can sit behind a TLS proxy. Compare host and effective port using
    // the origin's scheme, and never treat a forwarded Host as authoritative.
    reqwest::Url::parse(&format!("{}://{host}", origin.scheme()))
        .map(|target| target.origin() == origin.origin())
        .unwrap_or(false)
}

async fn index() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("../web/index.html"),
    )
}

async fn stylesheet() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../web/style.css"),
    )
}

async fn javascript() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../web/app.js"),
    )
}

async fn favicon() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "image/svg+xml")],
        include_str!("../web/favicon.svg"),
    )
}

async fn health() -> &'static str {
    "ok"
}

async fn metrics_prom(State(st): State<AppState>) -> String {
    st.live.get().metrics.prometheus()
}

async fn stats(State(st): State<AppState>) -> Json<Snapshot> {
    Json(st.live.get().metrics.snapshot())
}

async fn system(State(st): State<AppState>) -> Json<serde_json::Value> {
    let rt = st.live.get();
    // Use monotonic timestamps rather than deriving an epoch from elapsed time:
    // wall-clock adjustments and request timing must not change a runtime ID.
    let (direction, elapsed) = match rt
        .metrics
        .started
        .checked_duration_since(st.initial_started)
    {
        Some(elapsed) => ("+", elapsed),
        None => ("-", st.initial_started.duration_since(rt.metrics.started)),
    };
    let runtime_id = format!("{:016x}{direction}{}", st.id_prefix, elapsed.as_nanos());
    let mut upstreams = Vec::new();
    for plugin in &rt.config.plugins {
        if !matches!(plugin.ty.as_str(), "forward" | "fast_forward") {
            continue;
        }
        let Some(list) = plugin
            .args
            .get("upstreams")
            .or_else(|| plugin.args.get("upstream"))
        else {
            continue;
        };
        let values = match list.as_sequence() {
            Some(values) => values.as_slice(),
            None => std::slice::from_ref(list),
        };
        for value in values {
            if let Ok(spec) = crate::upstream::UpstreamSpec::from_value(value) {
                upstreams.push(serde_json::json!({
                    "plugin": plugin.tag.as_deref().unwrap_or(&plugin.ty),
                    "tag": spec.tag,
                    "addr": public_upstream_address(&spec.addr),
                }));
            }
        }
    }
    Json(serde_json::json!({
        "version": crate::VERSION,
        "runtime_id": runtime_id,
        "entry": rt.registry.default_entry,
        "listeners": rt.config.servers.iter().flat_map(|server| {
            server.listeners.iter().map(move |listener| {
                let protocol = listener.protocol.to_ascii_lowercase();
                let tls = matches!(protocol.as_str(), "tls" | "dot")
                    || (matches!(protocol.as_str(), "http" | "https" | "doh")
                        && listener.cert.is_some() && listener.key.is_some());
                serde_json::json!({
                    "protocol": if protocol.is_empty() { "udp" } else { &protocol },
                    "addr": listener.addr,
                    "entry": server.exec,
                    "timeout_secs": server.timeout.max(1),
                    "tls": tls,
                })
            })
        }).collect::<Vec<_>>(),
        "plugins": rt.config.plugins.iter().map(|plugin| serde_json::json!({
            "tag": plugin.tag.as_deref().unwrap_or(&plugin.ty),
            "type": plugin.ty,
        })).collect::<Vec<_>>(),
        "upstreams": upstreams,
    }))
}

/// Upstream credentials can occur in userinfo, paths, queries and fragments.
/// The console only needs the endpoint's protocol, hostname and explicit port.
fn public_upstream_address(address: &str) -> String {
    let address = address.trim();
    let normalized = if address.contains("://") {
        address.to_string()
    } else {
        format!("udp://{address}")
    };
    let Ok(url) = reqwest::Url::parse(&normalized) else {
        return "(hidden)".into();
    };
    let Some(host) = url.host_str() else {
        return "(hidden)".into();
    };
    let port = url
        .port()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    format!("{}://{host}{port}", url.scheme())
}

async fn plugins(State(st): State<AppState>) -> Json<serde_json::Value> {
    let rt = st.live.get();
    let r = &rt.registry;
    Json(serde_json::json!({
        "executables": r.execs.keys().collect::<Vec<_>>(),
        "domain_sets": r.domains.keys().collect::<Vec<_>>(),
        "ip_sets": r.ips.keys().collect::<Vec<_>>(),
        "caches": r.caches.iter().map(|(k, c)| serde_json::json!({
            "tag": k,
            "size": c.len(),
        })).collect::<Vec<_>>(),
        "entry": r.default_entry,
    }))
}

#[derive(Deserialize)]
struct QueryReq {
    name: String,
    #[serde(default = "default_qtype")]
    qtype: String,
    #[serde(default)]
    entry: Option<String>,
    /// Optional EDNS Client Subnet, e.g. `"203.0.113.0/24"`.
    #[serde(default)]
    ecs: Option<String>,
    /// Optional client address (used by `ecs: auto`).
    #[serde(default)]
    client_ip: Option<String>,
}

fn default_qtype() -> String {
    "A".into()
}

#[derive(serde::Serialize)]
struct QueryResp {
    rcode: String,
    answers: Vec<String>,
    records: Vec<QueryRecord>,
    elapsed_us: u64,
    cache_hit: bool,
    ecs: Option<String>,
    trace: Vec<TraceEvent>,
}

#[derive(serde::Serialize)]
struct QueryRecord {
    name: String,
    ttl: u32,
    #[serde(rename = "type")]
    record_type: String,
    data: String,
}

async fn query(
    State(st): State<AppState>,
    Json(req): Json<QueryReq>,
) -> std::result::Result<Json<QueryResp>, (StatusCode, String)> {
    let rt = st.live.get();
    let qtype =
        dnsutil::qtype_from_str(&req.qtype).ok_or((StatusCode::BAD_REQUEST, "bad qtype".into()))?;
    let mut name = req.name.clone();
    if !name.ends_with('.') {
        name.push('.');
    }
    let msg = build_query(&name, qtype).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let mut msg = msg;
    if let Some(spec) = req.ecs.as_deref() {
        let cs =
            dnsutil::parse_ecs_spec(spec).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        dnsutil::set_ecs(&mut msg, cs);
    }
    let client_ip = req
        .client_ip
        .as_deref()
        .map(|s| {
            s.parse()
                .map_err(|_| (StatusCode::BAD_REQUEST, "bad client_ip".into()))
        })
        .transpose()?;
    let mut ctx = QueryContext::new(msg, client_ip, ClientProto::Https);
    ctx.trace_enabled = true;
    let entry = req
        .entry
        .map(|entry| entry.trim().trim_start_matches('$').to_string())
        .or_else(|| rt.registry.default_entry.clone())
        .ok_or((StatusCode::BAD_REQUEST, "no entry".into()))?;
    rt.registry
        .get_exec(&entry)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    rt.handle_query(&mut ctx, &entry)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    let rcode = ctx
        .response()
        .map(|r| format!("{}", r.response_code()))
        .unwrap_or_else(|| "SERVFAIL".into());
    let answers = ctx
        .response()
        .map(|r| {
            r.answers()
                .iter()
                .map(|rec| format!("{} {} {:?}", rec.name(), rec.ttl(), rec.data()))
                .collect()
        })
        .unwrap_or_default();
    let cache_hit = ctx.trace.iter().any(|t| {
        (t.event == "hit" || t.event == "lazy_hit") && rt.registry.caches.contains_key(&t.plugin)
    });
    let records = ctx
        .response()
        .map(|response| {
            response
                .answers()
                .iter()
                .map(|record| QueryRecord {
                    name: record.name().to_string(),
                    ttl: record.ttl(),
                    record_type: record.record_type().to_string(),
                    data: record.data().to_string(),
                })
                .collect()
        })
        .unwrap_or_default();
    let ecs = dnsutil::ecs_of(ctx.query()).map(|cs| dnsutil::ecs_label(Some(&cs)));
    Ok(Json(QueryResp {
        rcode,
        answers,
        records,
        elapsed_us: ctx.start.elapsed().as_micros() as u64,
        cache_hit,
        ecs,
        trace: ctx.trace,
    }))
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FlushReq {
    #[serde(default)]
    tag: Option<String>,
}

async fn flush(
    State(st): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<Json<serde_json::Value>, (StatusCode, String)> {
    let req = if body.is_empty() {
        FlushReq::default()
    } else {
        let content_type = headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim);
        if content_type != Some("application/json") {
            return Err((
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "expected application/json".into(),
            ));
        }
        serde_json::from_slice::<FlushReq>(&body).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "invalid cache flush request".into(),
            )
        })?
    };
    let rt = st.live.get();
    let mut flushed = if let Some(tag) = req.tag {
        let cache = rt
            .registry
            .caches
            .get(&tag)
            .ok_or((StatusCode::NOT_FOUND, "unknown cache tag".into()))?;
        cache.flush();
        vec![tag]
    } else {
        rt.registry
            .caches
            .iter()
            .map(|(tag, cache)| {
                cache.flush();
                tag.clone()
            })
            .collect::<Vec<_>>()
    };
    flushed.sort_unstable();
    Ok(Json(serde_json::json!({ "ok": true, "flushed": flushed })))
}
