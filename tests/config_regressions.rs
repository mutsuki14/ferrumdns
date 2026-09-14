use ferrumdns::context::{build_query, ClientProto, QueryContext};
use ferrumdns::{Config, Live, Runtime};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

const PIPELINE: &str =
    "plugins:\n  - tag: main\n    type: sequence\n    args: [{exec: reject NXDOMAIN}]\n";

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let path = std::env::temp_dir().join(format!(
                "ferrumdns-config-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            // Independent PID namespaces may share a temporary directory.
            // Atomically claim ownership instead of accepting an existing path.
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create test directory {}: {error}", path.display()),
            }
        }
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn build_error(yaml: &str) -> String {
    match Runtime::build(Config::from_yaml(yaml).unwrap()).await {
        Ok(_) => panic!("bad configuration unexpectedly built: {yaml}"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn include_cycles_return_errors_without_aborting() {
    let dir = TempDir::new();
    let first = dir.write("a.yaml", "include: [b.yaml]\n");
    dir.write("b.yaml", "include: [./a.yaml]\n");
    let error = Config::load_file(&first).unwrap_err().to_string();
    assert!(error.contains("include cycle"), "{error}");
    assert!(error.contains("a.yaml") && error.contains("b.yaml"));
}

#[test]
fn excessive_include_depth_is_bounded() {
    let dir = TempDir::new();
    for i in 0..65 {
        dir.write(
            &format!("{i}.yaml"),
            &format!("include: [{}.yaml]\n", i + 1),
        );
    }
    dir.write("65.yaml", "plugins: []\n");
    let error = Config::load_file(&dir.0.join("0.yaml"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("include depth"), "{error}");
}

#[cfg(unix)]
#[test]
fn include_cycle_through_symlink_is_detected() {
    let dir = TempDir::new();
    let config = dir.write("config.yaml", "include: [alias.yaml]\n");
    std::os::unix::fs::symlink(&config, dir.0.join("alias.yaml")).unwrap();
    assert!(Config::load_file(&config)
        .unwrap_err()
        .to_string()
        .contains("include cycle"));
}

#[test]
fn sibling_includes_remain_valid_and_keep_relative_paths() {
    let dir = TempDir::new();
    std::fs::create_dir_all(dir.0.join("nested")).unwrap();
    dir.write("nested/shared.yaml", "plugins: []\n");
    dir.write("nested/a.yaml", "include: [shared.yaml]\nplugins:\n  - tag: hosts\n    type: hosts\n    args: {files: [hosts.txt]}\n");
    dir.write("nested/b.yaml", "include: [shared.yaml]\n");
    let config = dir.write(
        "config.yaml",
        "include: [nested/a.yaml, nested/b.yaml]\nlog: {file: run.log}\n",
    );
    let loaded = Config::load_file(&config).unwrap();
    assert_eq!(loaded.plugins[0].base_dir, dir.0.join("nested"));
    assert_eq!(
        loaded.log.file.as_deref(),
        Some(dir.0.join("run.log").to_str().unwrap())
    );
}

#[tokio::test]
async fn duplicate_and_unknown_plugin_references_are_rejected() {
    let duplicate = format!("{PIPELINE}  - tag: main\n    type: cache\n");
    assert!(build_error(&duplicate)
        .await
        .contains("duplicate plugin tag"));
    for exec in ["$missing", "goto missing", "jump $missing"] {
        let yaml = PIPELINE.replace("reject NXDOMAIN", exec);
        assert!(
            build_error(&yaml).await.contains("unknown executable"),
            "{exec}"
        );
    }
    let fallback = "plugins:\n  - tag: fb\n    type: fallback\n    args: {primary: missing, secondary: missing}\n";
    assert!(build_error(fallback).await.contains("unknown executable"));
    let wrong_kind = "plugins:\n  - tag: domains\n    type: domain_set\n  - tag: main\n    type: sequence\n    args: [{exec: $domains}]\n";
    assert!(build_error(wrong_kind).await.contains("unknown executable"));
}

#[tokio::test]
async fn recursive_sequences_and_fallbacks_are_rejected_before_queries() {
    for exec in ["$main", "goto main"] {
        assert!(build_error(&PIPELINE.replace("reject NXDOMAIN", exec))
            .await
            .contains("reference cycle"));
    }
    let indirect = "plugins:\n  - tag: a\n    type: sequence\n    args: [{exec: $fb}]\n  - tag: fb\n    type: fallback\n    args: {primary: a, secondary: b}\n  - tag: b\n    type: sequence\n    args: [{exec: accept}]\n";
    assert!(build_error(indirect).await.contains("reference cycle"));
    let mut deep = String::from("plugins:\n");
    for i in 0..65 {
        deep += &format!(
            "  - tag: step{i}\n    type: sequence\n    args: [{{exec: $step{}}}]\n",
            i + 1
        );
    }
    deep += "  - tag: step65\n    type: sequence\n    args: [{exec: accept}]\n";
    assert!(build_error(&deep).await.contains("call depth"));
}

#[tokio::test]
async fn acyclic_forward_references_still_work() {
    let yaml = "plugins:\n  - tag: main\n    type: sequence\n    args: [{exec: $later}]\n  - tag: later\n    type: sequence\n    args: [{exec: reject NXDOMAIN}]\n";
    let runtime = Runtime::build(Config::from_yaml(yaml).unwrap())
        .await
        .unwrap();
    let mut query = QueryContext::new(
        build_query("example.test.", RecordType::A).unwrap(),
        None,
        ClientProto::Udp,
    );
    runtime.handle_query(&mut query, "$main").await.unwrap();
    assert_eq!(
        query.response().unwrap().response_code(),
        ResponseCode::NXDomain
    );
}

#[tokio::test]
async fn invalid_listener_api_and_entry_settings_fail_build() {
    for listener in [
        "{protocol: bad, addr: '127.0.0.1:5353'}",
        "{protocol: udp, addr: not-an-address}",
        "{protocol: tls, addr: '127.0.0.1:8853'}",
        "{protocol: doh, addr: '127.0.0.1:8053', url_path: '/bad/{wildcard}'}",
    ] {
        let yaml = format!("{PIPELINE}servers:\n  - exec: main\n    listeners: [{listener}]\n");
        let _ = build_error(&yaml).await;
    }
    assert!(build_error("api: {http: not-an-address}\n")
        .await
        .contains("bad api addr"));
    let yaml = format!(
        "{PIPELINE}servers:\n  - exec: missing\n    listeners: [{{addr: '127.0.0.1:5353'}}]\n"
    );
    assert!(build_error(&yaml).await.contains("unknown plugin tag"));
}

#[tokio::test]
async fn dropping_a_runtime_releases_its_registry_caches_and_rules() {
    let yaml = "plugins:\n  - tag: cache\n    type: cache\n    args: {size: 16}\n  - tag: main\n    type: sequence\n    args: [{exec: $cache}, {exec: reject NXDOMAIN}]\n";
    let runtime = Runtime::build(Config::from_yaml(yaml).unwrap())
        .await
        .unwrap();
    let registry = Arc::downgrade(&runtime.registry);
    let cache = Arc::downgrade(&runtime.registry.caches["cache"]);
    drop(runtime);
    assert!(
        registry.upgrade().is_none(),
        "registry must not form an Arc cycle"
    );
    assert!(
        cache.upgrade().is_none(),
        "cache must be released with its runtime"
    );
}

#[tokio::test]
async fn failed_reload_retains_working_config_and_valid_reload_frees_old_registry() {
    let dir = TempDir::new();
    let yaml = format!(
        "{PIPELINE}servers:\n  - exec: main\n    listeners: [{{addr: '127.0.0.1:5353'}}]\n"
    );
    let path = dir.write("config.yaml", &yaml);
    let original = Runtime::build(Config::load_file(&path).unwrap())
        .await
        .unwrap();
    let registry = Arc::downgrade(&original.registry);
    let live = Live::new(original.clone());
    dir.write("config.yaml", "include: [config.yaml]\n");
    assert!(live.reload_file(&path).await.is_err());
    assert!(Arc::ptr_eq(&live.get(), &original));
    dir.write("config.yaml", &yaml.replace("main", "renamed"));
    assert!(live
        .reload_file(&path)
        .await
        .unwrap_err()
        .to_string()
        .contains("restart"));
    assert!(Arc::ptr_eq(&live.get(), &original));
    dir.write("config.yaml", &yaml.replace("NXDOMAIN", "REFUSED"));
    live.reload_file(&path).await.unwrap();
    drop(original);
    assert!(registry.upgrade().is_none());
    let mut query = QueryContext::new(
        build_query("example.test.", RecordType::A).unwrap(),
        None,
        ClientProto::Udp,
    );
    live.get().handle_query(&mut query, "main").await.unwrap();
    assert_eq!(
        query.response().unwrap().response_code(),
        ResponseCode::Refused
    );
}

#[tokio::test]
async fn failed_listener_propagates_and_other_listeners_are_cancelled() {
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let taken_addr = occupied.local_addr().unwrap();
    let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_addr = reservation.local_addr().unwrap();
    drop(reservation);
    let yaml = format!("{PIPELINE}servers:\n  - exec: main\n    listeners:\n      - {{protocol: udp, addr: '{udp_addr}', workers: 1}}\n      - {{protocol: tcp, addr: '{taken_addr}'}}\n");
    let live = Live::new(
        Runtime::build(Config::from_yaml(&yaml).unwrap())
            .await
            .unwrap(),
    );
    let result = tokio::time::timeout(Duration::from_secs(2), live.serve())
        .await
        .expect("startup must not hang");
    assert!(result.is_err(), "bind failure must propagate");
    // Child UDP workers are cancelled asynchronously when their JoinSet drops.
    let mut released = false;
    for _ in 0..50 {
        if std::net::UdpSocket::bind(udp_addr).is_ok() {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(released, "startup failure leaked a sibling UDP listener");
}

#[test]
fn cli_check_rejects_unrunnable_configs_and_start_returns_failure() {
    let dir = TempDir::new();
    let pipeline = dir.write("pipeline.yaml", PIPELINE);
    let check = Command::new(env!("CARGO_BIN_EXE_ferrumdns"))
        .args(["check", "-c"])
        .arg(&pipeline)
        .output()
        .unwrap();
    assert!(
        !check.status.success(),
        "CLI check must reject a service with no endpoints"
    );
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let yaml = format!(
        "{PIPELINE}servers:\n  - exec: main\n    listeners: [{{protocol: tcp, addr: '{}'}}]\n",
        occupied.local_addr().unwrap()
    );
    let path = dir.write("occupied.yaml", &yaml);
    let start = Command::new(env!("CARGO_BIN_EXE_ferrumdns"))
        .args(["start", "-c"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        !start.status.success(),
        "start bind failure must produce a nonzero exit code"
    );
}

#[test]
fn configured_log_file_receives_logs_and_is_not_truncated() {
    let dir = TempDir::new();
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let yaml = format!("{PIPELINE}log: {{file: run.log}}\nservers:\n  - exec: main\n    listeners: [{{protocol: tcp, addr: '{}'}}]\n", occupied.local_addr().unwrap());
    let config = dir.write("config.yaml", &yaml);
    let log = dir.write("run.log", "previous logs\n");
    let output = Command::new(env!("CARGO_BIN_EXE_ferrumdns"))
        .args(["start", "-c"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let contents = std::fs::read_to_string(log).unwrap();
    assert!(contents.starts_with("previous logs\n"));
    assert!(contents.contains("starting ferrumdns"));
    assert!(
        !contents.contains('\u{1b}'),
        "file logs should not contain ANSI escape codes"
    );
    assert!(
        output.stdout.is_empty(),
        "configured file logs must not silently go to stdout"
    );
}

async fn wait_for_api(client: &reqwest::Client, base: &str) {
    for _ in 0..100 {
        if client.get(format!("{base}/health")).send().await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("API did not become ready");
}

#[tokio::test]
async fn serving_does_not_pin_the_initial_runtime_after_reload() {
    let dir = TempDir::new();
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let yaml = format!("{PIPELINE}api: {{http: '{address}'}}\n");
    let path = dir.write("config.yaml", &yaml);
    let runtime = Runtime::build(Config::load_file(&path).unwrap())
        .await
        .unwrap();
    let previous = Arc::downgrade(&runtime);
    let live = Live::new(runtime);
    let server = tokio::spawn(live.clone().serve());
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    wait_for_api(&client, &format!("http://{address}")).await;
    dir.write("config.yaml", &yaml.replace("NXDOMAIN", "REFUSED"));
    live.reload_file(&path).await.unwrap();
    let leaked = previous.upgrade().is_some();
    server.abort();
    let _ = server.await;
    assert!(!leaked, "Live::serve retained its initial runtime snapshot");
}

#[tokio::test]
async fn api_rejects_invalid_client_ip_and_normalizes_explicit_entry() {
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let live = Live::new(
        Runtime::build(Config::from_yaml(PIPELINE).unwrap())
            .await
            .unwrap(),
    );
    let server =
        tokio::spawn(async move { ferrumdns::api::serve(live, &address.to_string()).await });
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    let base = format!("http://{address}");
    wait_for_api(&client, &base).await;
    for body in [
        r#"{"name":"example.test","client_ip":"not-an-ip"}"#,
        r#"{"name":"example.test","entry":"missing"}"#,
    ] {
        let response = client
            .post(format!("{base}/api/query"))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    }
    let response = client
        .post(format!("{base}/api/query"))
        .header("Content-Type", "application/json")
        .body(r#"{"name":"example.test","entry":"$main"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn dollar_listener_entry_resolves_dns_queries() {
    let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let yaml = format!("{PIPELINE}servers:\n  - exec: $main\n    listeners: [{{protocol: udp, addr: '{address}', workers: 1}}]\n");
    let runtime = Runtime::build(Config::from_yaml(&yaml).unwrap())
        .await
        .unwrap();
    assert_eq!(runtime.config.servers[0].exec, "main");
    let server = tokio::spawn(Live::new(runtime).serve());
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let wire =
        ferrumdns::dnsutil::encode(&build_query("example.test.", RecordType::A).unwrap()).unwrap();
    let mut buffer = [0; 2048];
    let mut received = None;
    for _ in 0..20 {
        client.send_to(&wire, address).await.unwrap();
        if let Ok(Ok((length, _))) =
            tokio::time::timeout(Duration::from_millis(50), client.recv_from(&mut buffer)).await
        {
            received = Some(ferrumdns::dnsutil::decode(&buffer[..length]).unwrap());
            break;
        }
    }
    server.abort();
    let _ = server.await;
    assert_eq!(
        received
            .expect("UDP listener dropped a valid $main query")
            .response_code(),
        ResponseCode::NXDomain
    );
}
