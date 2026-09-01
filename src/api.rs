use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Json;
use axum::Router;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::context::{build_query, ClientProto, QueryContext, TraceEvent};
use crate::dnsutil;
use crate::error::Result;
use crate::metrics::Snapshot;
use crate::runtime::Runtime;

#[derive(Clone)]
struct AppState {
    rt: Arc<Runtime>,
}

pub async fn serve(rt: Arc<Runtime>, bind: &str) -> Result<()> {
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
        .with_state(AppState { rt });
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
    st.rt.metrics.prometheus()
}

async fn stats(State(st): State<AppState>) -> Json<Snapshot> {
    Json(st.rt.metrics.snapshot())
}

async fn plugins(State(st): State<AppState>) -> Json<serde_json::Value> {
    let r = &st.rt.registry;
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
    trace: Vec<TraceEvent>,
}

async fn query(State(st): State<AppState>, Json(req): Json<QueryReq>) -> std::result::Result<Json<QueryResp>, (StatusCode, String)> {
    let qtype = dnsutil::qtype_from_str(&req.qtype).ok_or((StatusCode::BAD_REQUEST, "bad qtype".into()))?;
    let mut name = req.name.clone();
    if !name.ends_with('.') {
        name.push('.');
    }
    let msg = build_query(&name, qtype).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let mut ctx = QueryContext::new(msg, None, ClientProto::Https);
    ctx.trace_enabled = true;
    let entry = req
        .entry
        .or_else(|| st.rt.registry.default_entry.clone())
        .ok_or((StatusCode::BAD_REQUEST, "no entry".into()))?;
    st.rt
        .handle_query(&mut ctx, &entry)
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
        (t.event == "hit" || t.event == "lazy_hit") && st.rt.registry.caches.contains_key(&t.plugin)
    });
    Ok(Json(QueryResp {
        rcode,
        answers,
        elapsed_us: ctx.start.elapsed().as_micros() as u64,
        cache_hit,
        trace: ctx.trace,
    }))
}

async fn flush(State(st): State<AppState>) -> Json<serde_json::Value> {
    for c in st.rt.registry.caches.values() {
        c.flush();
    }
    Json(serde_json::json!({ "ok": true }))
}

#[allow(dead_code)]
fn _use_ordering() {
    let _ = Ordering::Relaxed;
}
