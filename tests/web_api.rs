use ferrumdns::{Config, Live, Runtime};
use reqwest::{Client, Response, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

const PIPELINE: &str = r#"
plugins:
  - {tag: cache_one, type: cache, args: {size: 64}}
  - {tag: cache_two, type: cache, args: {size: 64}}
  - tag: hosts
    type: hosts
    args:
      ttl: 300
      entries: ["192.0.2.42 admin.test", "2001:db8::42 admin.test"]
  - tag: main
    type: sequence
    args:
      - exec: $cache_one
      - {matches: has_resp, exec: accept}
      - exec: $hosts
  - tag: secondary
    type: sequence
    args:
      - exec: $cache_two
      - {matches: has_resp, exec: accept}
      - exec: $hosts
servers:
  - exec: main
    timeout: 3
    listeners: [{protocol: udp, addr: '127.0.0.1:5353'}]
"#;

struct Admin {
    base: String,
    client: Client,
    live: Live,
    server: tokio::task::JoinHandle<ferrumdns::error::Result<()>>,
}

impl Drop for Admin {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Admin {
    async fn start(config: Config) -> Self {
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        let live = Live::new(Runtime::build(config).await.unwrap());
        let served_live = live.clone();
        drop(reservation);
        let server =
            tokio::spawn(
                async move { ferrumdns::api::serve(served_live, &address.to_string()).await },
            );
        let admin = Self {
            base: format!("http://{address}"),
            client: Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap(),
            live,
            server,
        };
        for _ in 0..100 {
            if admin
                .client
                .get(format!("{}/health", admin.base))
                .send()
                .await
                .is_ok()
            {
                return admin;
            }
            assert!(
                !admin.server.is_finished(),
                "admin API exited during startup"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("admin API did not become ready");
    }

    async fn get(&self, path: &str) -> Response {
        self.client
            .get(format!("{}{path}", self.base))
            .send()
            .await
            .unwrap()
    }

    async fn post(&self, path: &str, body: Option<Value>) -> Response {
        let request = self.client.post(format!("{}{path}", self.base));
        let request = if let Some(body) = body {
            request
                .header("Content-Type", "application/json")
                .body(body.to_string())
        } else {
            request
        };
        request.send().await.unwrap()
    }

    async fn query(&self, entry: &str, qtype: &str) -> Value {
        json_body(
            self.post(
                "/api/query",
                Some(json!({
                    "name": "admin.test", "qtype": qtype, "entry": entry,
                })),
            )
            .await,
        )
        .await
    }

    fn cache_size(&self, tag: &str) -> usize {
        self.live.get().registry.caches[tag].len()
    }
}

async fn json_body(response: Response) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_str(&response.text().await.unwrap()).unwrap()
}

#[tokio::test]
async fn embedded_console_has_correct_mime_security_headers_and_real_404s() {
    let admin = Admin::start(Config::from_yaml(PIPELINE).unwrap()).await;
    for (path, content_type) in [
        ("/", "text/html; charset=utf-8"),
        ("/assets/style.css", "text/css; charset=utf-8"),
        ("/assets/app.js", "text/javascript; charset=utf-8"),
        ("/favicon.svg", "image/svg+xml"),
    ] {
        let response = admin.get(path).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(response.headers()["content-type"], content_type);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        let csp = response.headers()["content-security-policy"]
            .to_str()
            .unwrap();
        assert!(csp.contains("script-src 'self'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(!csp.contains("unsafe-inline"));
        assert!(!response.text().await.unwrap().is_empty());
    }
    for path in ["/api/missing", "/assets/missing.js", "/missing"] {
        let response = admin.get(path).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert!(!response.text().await.unwrap().contains("<!DOCTYPE"));
    }
    assert_eq!(
        admin.post("/", None).await.status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(admin.get("/health").await.text().await.unwrap(), "ok");
    assert!(admin
        .get("/metrics")
        .await
        .text()
        .await
        .unwrap()
        .contains("ferrumdns_queries_total"));
}

#[tokio::test]
async fn system_reports_runtime_generation_and_only_public_configuration() {
    let mut config = Config::from_yaml(PIPELINE).unwrap();
    config.log.file = Some("private-log-file.log".into());
    let extra = Config::from_yaml(r#"
plugins:
  - tag: forward
    type: fast_forward
    args:
      upstreams:
        - "127.0.0.1:5300"
        - "udp://[::1]:5354"
        - tag: secure_resolver
          addr: "https://private-user:private-password@resolver.example.test:8443/private-path-token?api_key=private-query-token#private-fragment-token"
servers:
  - exec: main
    listeners: [{protocol: doh, addr: '127.0.0.1:8053', url_path: '/private-listener-path'}]
"#).unwrap();
    config.plugins.extend(extra.plugins);
    config.servers.extend(extra.servers);
    config.servers[1].listeners[0].cert = Some(format!(
        "{}/tests/protocol/localhost-test.pem",
        env!("CARGO_MANIFEST_DIR")
    ));
    config.servers[1].listeners[0].key = Some(format!(
        "{}/tests/protocol/localhost-test.key",
        env!("CARGO_MANIFEST_DIR")
    ));
    let admin = Admin::start(config.clone()).await;
    let system = json_body(admin.get("/api/system").await).await;
    assert_eq!(system["version"], ferrumdns::VERSION);
    assert_eq!(system["entry"], "main");
    assert_eq!(
        system["listeners"][0],
        json!({
            "protocol":"udp", "addr":"127.0.0.1:5353", "entry":"main", "timeout_secs":3, "tls":false,
        })
    );
    assert_eq!(system["listeners"][1]["tls"], true);
    assert!(system["plugins"]
        .as_array()
        .unwrap()
        .contains(&json!({"tag":"forward", "type":"fast_forward"})));
    assert_eq!(
        system["upstreams"],
        json!([
            {"plugin":"forward", "tag":null, "addr":"udp://127.0.0.1:5300"},
            {"plugin":"forward", "tag":null, "addr":"udp://[::1]:5354"},
            {"plugin":"forward", "tag":"secure_resolver", "addr":"https://resolver.example.test:8443"},
        ])
    );
    let serialized = system.to_string();
    for secret in [
        "private-user",
        "private-password",
        "private-path-token",
        "private-query-token",
        "private-fragment-token",
        "private-listener-path",
        "private-log-file",
        "localhost-test",
        "192.0.2.42",
        "2001:db8::42",
        "CARGO_MANIFEST_DIR",
    ] {
        assert!(
            !serialized.contains(secret),
            "system response leaked {secret}"
        );
    }
    let original_id = system["runtime_id"].as_str().unwrap();
    assert!(!original_id.is_empty());
    assert_eq!(
        json_body(admin.get("/api/system").await).await["runtime_id"],
        original_id
    );
    let old_runtime = Arc::downgrade(&admin.live.get());
    admin.live.swap(Runtime::build(config).await.unwrap());
    let reloaded = json_body(admin.get("/api/system").await).await;
    assert_ne!(reloaded["runtime_id"], original_id);
    assert_eq!(
        json_body(admin.get("/api/system").await).await["runtime_id"],
        reloaded["runtime_id"]
    );
    assert!(
        old_runtime.upgrade().is_none(),
        "admin API retained an obsolete runtime"
    );
}

#[tokio::test]
async fn query_records_are_readable_and_legacy_fields_still_work() {
    let admin = Admin::start(Config::from_yaml(PIPELINE).unwrap()).await;
    for (qtype, data) in [("A", "192.0.2.42"), ("AAAA", "2001:db8::42")] {
        let response = admin.query("$main", qtype).await;
        assert_eq!(response["rcode"], "No Error");
        assert_eq!(response["cache_hit"], false);
        assert_eq!(
            response["records"],
            json!([
                {"name":"admin.test.", "ttl":300, "type":qtype, "data":data},
            ])
        );
        assert!(response["answers"][0].as_str().unwrap().contains(data));
        assert!(response["elapsed_us"].is_u64());
        assert!(response["trace"].is_array());
        assert!(response.get("ecs").is_some());
        let cached = admin.query("main", qtype).await;
        assert_eq!(cached["cache_hit"], true);
        assert_eq!(cached["records"][0]["data"], data);
    }
    let stats = json_body(admin.get("/api/stats").await).await;
    assert_eq!(stats["queries"], 4);
    assert_eq!(stats["cache_hits"], 2);
}

#[tokio::test]
async fn cache_flush_targets_one_cache_and_preserves_legacy_flush_all() {
    let admin = Admin::start(Config::from_yaml(PIPELINE).unwrap()).await;
    admin.query("main", "A").await;
    admin.query("secondary", "A").await;
    assert_eq!(admin.cache_size("cache_one"), 1);
    assert_eq!(admin.cache_size("cache_two"), 1);
    let plugins = json_body(admin.get("/api/plugins").await).await;
    assert!(plugins["caches"]
        .as_array()
        .unwrap()
        .contains(&json!({"tag":"cache_one", "size":1})));

    for body in [
        json!({"tag":"missing"}),
        json!({"tags":["cache_one"]}),
        json!({"tag":42}),
    ] {
        assert!(admin
            .post("/api/cache/flush", Some(body))
            .await
            .status()
            .is_client_error());
        assert_eq!(admin.cache_size("cache_one"), 1);
        assert_eq!(admin.cache_size("cache_two"), 1);
    }
    let malformed = admin
        .client
        .post(format!("{}/api/cache/flush", admin.base))
        .header("Content-Type", "application/json")
        .body("{")
        .send()
        .await
        .unwrap();
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    let wrong_mime = admin
        .client
        .post(format!("{}/api/cache/flush", admin.base))
        .header("Content-Type", "text/plain")
        .body(r#"{"tag":"cache_one"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_mime.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(admin.cache_size("cache_one"), 1);
    assert_eq!(admin.cache_size("cache_two"), 1);

    let flushed = json_body(
        admin
            .post("/api/cache/flush", Some(json!({"tag":"cache_one"})))
            .await,
    )
    .await;
    assert_eq!(flushed, json!({"ok":true, "flushed":["cache_one"]}));
    assert_eq!(admin.cache_size("cache_one"), 0);
    assert_eq!(admin.cache_size("cache_two"), 1);
    assert_eq!(admin.query("secondary", "A").await["cache_hit"], true);
    assert_eq!(admin.query("main", "A").await["cache_hit"], false);

    for body in [None, Some(json!({}))] {
        let flushed = json_body(admin.post("/api/cache/flush", body).await).await;
        assert_eq!(
            flushed,
            json!({"ok":true, "flushed":["cache_one", "cache_two"]})
        );
        assert_eq!(admin.cache_size("cache_one"), 0);
        assert_eq!(admin.cache_size("cache_two"), 0);
        admin.query("main", "A").await;
        admin.query("secondary", "A").await;
    }
}

#[tokio::test]
async fn browser_cross_origin_writes_cannot_flush_caches() {
    let admin = Admin::start(Config::from_yaml(PIPELINE).unwrap()).await;
    admin.query("main", "A").await;
    admin.query("secondary", "A").await;
    let mut wrong_port = reqwest::Url::parse(&admin.base).unwrap();
    let port = wrong_port.port().unwrap();
    wrong_port
        .set_port(Some(if port == 65535 { 65534 } else { port + 1 }))
        .unwrap();
    for (origin, site) in [
        (Some("https://evil.example"), Some("cross-site")),
        (Some("https://evil.example"), None),
        (Some("https://evil.example"), Some("same-origin")),
        (Some(admin.base.as_str()), Some("cross-site")),
        (Some(admin.base.as_str()), Some("same-site")),
        (None, Some("cross-site")),
        (None, Some("same-site")),
        (Some("null"), None),
        (Some(wrong_port.as_str()), None),
        (Some("file:///"), None),
        (Some("http://user:password@127.0.0.1"), None),
    ] {
        let mut request = admin.client.post(format!("{}/api/cache/flush", admin.base));
        if let Some(origin) = origin {
            request = request.header("Origin", origin);
        }
        if let Some(site) = site {
            request = request.header("Sec-Fetch-Site", site);
        }
        // An empty POST is enough to exercise the legacy flush-all behavior.
        let response = request.send().await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "origin={origin:?}, site={site:?}"
        );
        assert_eq!(admin.cache_size("cache_one"), 1);
        assert_eq!(admin.cache_size("cache_two"), 1);
    }
    let spoofed_proxy = admin
        .client
        .post(format!("{}/api/cache/flush", admin.base))
        .header("Origin", "https://evil.example")
        .header("X-Forwarded-Host", "evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(spoofed_proxy.status(), StatusCode::FORBIDDEN);
    assert_eq!(admin.cache_size("cache_one"), 1);
    assert_eq!(admin.cache_size("cache_two"), 1);

    let blocked_query = admin
        .client
        .post(format!("{}/api/query", admin.base))
        .header("Origin", "https://evil.example")
        .header("Content-Type", "application/json")
        .body(r#"{"name":"admin.test"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(blocked_query.status(), StatusCode::FORBIDDEN);
    let get = admin
        .client
        .get(format!("{}/api/stats", admin.base))
        .header("Origin", "https://evil.example")
        .header("Sec-Fetch-Site", "cross-site")
        .send()
        .await
        .unwrap();
    assert_eq!(
        get.status(),
        StatusCode::OK,
        "read-only requests retain their behavior"
    );
}

#[tokio::test]
async fn same_origin_browser_and_legacy_cli_writes_remain_supported() {
    let admin = Admin::start(Config::from_yaml(PIPELINE).unwrap()).await;
    for site in [Some("same-origin"), Some("none"), None] {
        admin.query("main", "A").await;
        let mut request = admin
            .client
            .post(format!("{}/api/cache/flush", admin.base))
            .header("Origin", admin.base.as_str());
        if let Some(site) = site {
            request = request.header("Sec-Fetch-Site", site);
        }
        assert_eq!(request.send().await.unwrap().status(), StatusCode::OK);
        assert_eq!(admin.cache_size("cache_one"), 0);
    }
    // Proxy-facing origins can use HTTPS, IPv6, and explicit default ports.
    for (host, origin) in [
        ("console.example", "https://console.example:443"),
        ("console.example:80", "http://console.example"),
        ("[::1]:9090", "http://[::1]:9090"),
    ] {
        admin.query("main", "A").await;
        let response = admin
            .client
            .post(format!("{}/api/cache/flush", admin.base))
            .header("Host", host)
            .header("Origin", origin)
            .header("Sec-Fetch-Site", "same-origin")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{host} / {origin}");
        assert_eq!(admin.cache_size("cache_one"), 0);
    }
    admin.query("main", "A").await;
    let cli = json_body(admin.post("/api/cache/flush", None).await).await;
    assert_eq!(cli["ok"], true);
    assert_eq!(admin.cache_size("cache_one"), 0);
}
