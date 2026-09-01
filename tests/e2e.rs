use ferrumdns::config::Config;
use ferrumdns::context::{build_query, ClientProto, QueryContext};
use ferrumdns::runtime::{Live, Runtime};
use hickory_proto::rr::RecordType;
use std::net::IpAddr;

const YAML: &str = r#"
plugins:
  - tag: ads
    type: domain_set
    args:
      exps:
        - ads.evil.test
        - keyword:tracker
  - tag: hosts
    type: hosts
    args:
      entries:
        - "10.9.8.7 box.test"
        - "box.test 10.9.8.8"
  - tag: cache
    type: cache
    args:
      size: 128
  - tag: main
    type: sequence
    args:
      - matches:
          - qname $ads
        exec: reject NXDOMAIN
      - exec: $hosts
      - matches: has_resp
        exec: accept
      - exec: $cache
      - matches: has_resp
        exec: accept
"#;

#[tokio::test]
async fn hosts_and_adblock() {
    let cfg = Config::from_yaml(YAML).unwrap();
    let rt = Runtime::build(cfg).await.unwrap();

    let q = build_query("box.test.", RecordType::A).unwrap();
    let mut ctx = QueryContext::new(q, None, ClientProto::Udp);
    rt.handle_query(&mut ctx, "main").await.unwrap();
    assert!(ctx.has_resp());
    let ips = ctx.answer_ips();
    assert!(ips.contains(&"10.9.8.7".parse::<IpAddr>().unwrap())
        || ips.contains(&"10.9.8.8".parse::<IpAddr>().unwrap()));

    let q = build_query("ads.evil.test.", RecordType::A).unwrap();
    let mut ctx = QueryContext::new(q, None, ClientProto::Udp);
    ctx.trace_enabled = true;
    rt.handle_query(&mut ctx, "main").await.unwrap();
    assert!(ctx.has_resp());
    assert_eq!(
        hickory_proto::op::ResponseCode::NXDomain,
        ctx.response().unwrap().response_code()
    );

    let q = build_query("box.test.", RecordType::AAAA).unwrap();
    let mut ctx = QueryContext::new(q, None, ClientProto::Udp);
    rt.handle_query(&mut ctx, "main").await.unwrap();
    assert!(ctx.has_resp(), "AAAA for a hosts name must not miss");
    assert!(ctx.answer_ips().is_empty());
    assert_eq!(
        hickory_proto::op::ResponseCode::NoError,
        ctx.response().unwrap().response_code()
    );
}

#[tokio::test]
async fn cache_hit_after_hosts() {
    let yaml = r#"
plugins:
  - tag: hosts
    type: hosts
    args:
      entries: ["1.2.3.4 cached.test"]
  - tag: cache
    type: cache
    args: { size: 64 }
  - tag: main
    type: sequence
    args:
      - exec: $cache
      - matches: has_resp
        exec: accept
      - exec: $hosts
"#;
    let cfg = Config::from_yaml(yaml).unwrap();
    let rt = Runtime::build(cfg).await.unwrap();

    let q = build_query("cached.test.", RecordType::A).unwrap();
    let mut ctx = QueryContext::new(q.clone(), None, ClientProto::Udp);
    rt.handle_query(&mut ctx, "main").await.unwrap();
    assert!(ctx.has_resp());

    let mut ctx2 = QueryContext::new(q, None, ClientProto::Udp);
    ctx2.trace_enabled = true;
    rt.handle_query(&mut ctx2, "main").await.unwrap();
    assert!(ctx2.has_resp());
    assert!(
        ctx2.trace.iter().any(|t| t.event == "hit" && t.plugin == "cache"),
        "expected cache hit, trace={:?}",
        ctx2.trace
    );
}

#[tokio::test]
async fn lazy_cache_skips_lookup_on_refresh() {
    let yaml = r#"
plugins:
  - tag: hosts
    type: hosts
    args:
      ttl: 1
      entries: ["9.9.9.9 lazy.test"]
  - tag: cache
    type: cache
    args:
      size: 64
      lazy_cache_ttl: 86400
      lazy_cache_reply_ttl: 5
  - tag: main
    type: sequence
    args:
      - exec: $cache
      - matches: has_resp
        exec: accept
      - exec: $hosts
"#;
    let cfg = Config::from_yaml(yaml).unwrap();
    let rt = Runtime::build(cfg).await.unwrap();

    let q = build_query("lazy.test.", RecordType::A).unwrap();
    let mut ctx = QueryContext::new(q.clone(), None, ClientProto::Udp);
    rt.handle_query(&mut ctx, "main").await.unwrap();
    assert!(ctx.has_resp());

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    let mut lazy = QueryContext::new(q.clone(), None, ClientProto::Udp);
    lazy.trace_enabled = true;
    rt.handle_query(&mut lazy, "main").await.unwrap();
    assert!(lazy.has_resp());
    assert!(
        lazy.trace
            .iter()
            .any(|t| t.event == "lazy_hit" && t.plugin == "cache"),
        "expected lazy_hit, trace={:?}",
        lazy.trace
    );
    let ttl = lazy.response().unwrap().answers()[0].ttl();
    assert_eq!(ttl, 5, "lazy reply TTL");

    // background refresh should rewrite the entry with a fresh 1s TTL
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let mut again = QueryContext::new(q, None, ClientProto::Udp);
    again.trace_enabled = true;
    rt.handle_query(&mut again, "main").await.unwrap();
    assert!(again.has_resp());
    assert!(
        again
            .trace
            .iter()
            .any(|t| t.event == "hit" && t.plugin == "cache"),
        "refresh should have stored a fresh entry, trace={:?}",
        again.trace
    );
}

#[tokio::test]
async fn live_reload_swaps_hosts() {
    let yaml1 = r#"
plugins:
  - tag: hosts
    type: hosts
    args:
      entries: ["1.1.1.1 a.test"]
  - tag: main
    type: sequence
    args:
      - exec: $hosts
"#;
    let yaml2 = r#"
plugins:
  - tag: hosts
    type: hosts
    args:
      entries: ["2.2.2.2 a.test"]
  - tag: main
    type: sequence
    args:
      - exec: $hosts
"#;
    let live = Live::new(Runtime::build(Config::from_yaml(yaml1).unwrap()).await.unwrap());
    let q = build_query("a.test.", RecordType::A).unwrap();
    let mut ctx = QueryContext::new(q.clone(), None, ClientProto::Udp);
    live.get().handle_query(&mut ctx, "main").await.unwrap();
    assert_eq!(ctx.answer_ips()[0], "1.1.1.1".parse::<IpAddr>().unwrap());

    live.swap(Runtime::build(Config::from_yaml(yaml2).unwrap()).await.unwrap());
    let mut ctx = QueryContext::new(q, None, ClientProto::Udp);
    live.get().handle_query(&mut ctx, "main").await.unwrap();
    assert_eq!(ctx.answer_ips()[0], "2.2.2.2".parse::<IpAddr>().unwrap());
}

#[tokio::test]
async fn example_configs_build() {
    use std::path::Path;
    for file in [
        "examples/simple.yaml",
        "examples/dev.yaml",
        "examples/docker.yaml",
        "examples/split-horizon.yaml",
    ] {
        let cfg = Config::load_file(Path::new(file))
            .unwrap_or_else(|e| panic!("load {file}: {e}"));
        Runtime::build(cfg)
            .await
            .unwrap_or_else(|e| panic!("build {file}: {e}"));
    }
}
