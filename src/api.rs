use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Json;
use axum::Router;
use serde::Deserialize;
use std::net::SocketAddr;

use crate::context::{build_query, ClientProto, QueryContext, TraceEvent};
use crate::dnsutil;
use crate::error::Result;
use crate::metrics::Snapshot;
use crate::runtime::Live;

#[derive(Clone)]
struct AppState {
    live: Live,
}

pub async fn serve(live: Live, bind: &str) -> Result<()> {
    let addr: SocketAddr = bind
        .parse()
        .map_err(|e| crate::error::Error::config(format!("bad api addr {bind}: {e}")))?;
    let app = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics_prom))
        .route("/api/stats", get(stats))
        .route("/api/plugins", get(plugins))
        .route("/api/query", post(query))
        .route("/api/cache/flush", post(flush))
        .with_state(AppState { live });
    tracing::info!(%addr, "admin api");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .await
        .map_err(|e| crate::error::Error::config(e.to_string()))
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
    elapsed_us: u64,
    cache_hit: bool,
    ecs: Option<String>,
    trace: Vec<TraceEvent>,
}

async fn query(State(st): State<AppState>, Json(req): Json<QueryReq>) -> std::result::Result<Json<QueryResp>, (StatusCode, String)> {
    let rt = st.live.get();
    let qtype = dnsutil::qtype_from_str(&req.qtype).ok_or((StatusCode::BAD_REQUEST, "bad qtype".into()))?;
    let mut name = req.name.clone();
    if !name.ends_with('.') {
        name.push('.');
    }
    let msg = build_query(&name, qtype).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let mut msg = msg;
    if let Some(spec) = req.ecs.as_deref() {
        let cs = dnsutil::parse_ecs_spec(spec).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        dnsutil::set_ecs(&mut msg, cs);
    }
    let client_ip = req
        .client_ip
        .as_deref()
        .and_then(|s| s.parse().ok());
    let mut ctx = QueryContext::new(msg, client_ip, ClientProto::Https);
    ctx.trace_enabled = true;
    let entry = req
        .entry
        .or_else(|| rt.registry.default_entry.clone())
        .ok_or((StatusCode::BAD_REQUEST, "no entry".into()))?;
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
    let ecs = dnsutil::ecs_of(ctx.query()).map(|cs| dnsutil::ecs_label(Some(&cs)));
    Ok(Json(QueryResp {
        rcode,
        answers,
        elapsed_us: ctx.start.elapsed().as_micros() as u64,
        cache_hit,
        ecs,
        trace: ctx.trace,
    }))
}

async fn flush(State(st): State<AppState>) -> Json<serde_json::Value> {
    let rt = st.live.get();
    for c in rt.registry.caches.values() {
        c.flush();
    }
    Json(serde_json::json!({ "ok": true }))
}
