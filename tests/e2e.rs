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
    assert_eq!(ctx2.answer_ips()[0], "1.2.3.4".parse::<IpAddr>().unwrap());
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

    // background refresh should rewrite the entry with a fresh hosts TTL (1s)
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
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
    let ttl = again.response().unwrap().answers()[0].ttl();
    assert!(
        ttl <= 1,
        "refresh must store hosts TTL, not the lazy 5s wire, got {ttl}"
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
async fn ecs_attaches_is_cached_separately_and_stripped_from_reply() {
    let yaml = r#"
plugins:
  - tag: ecs
    type: ecs
    args:
      ipv4: 203.0.113.9
      mask4: 24
  - tag: hosts
    type: hosts
    args:
      entries: ["9.9.9.9 ecs.test"]
  - tag: cache
    type: cache
    args: { size: 64 }
  - tag: main
    type: sequence
    args:
      - exec: $ecs
      - exec: $cache
      - matches: has_resp
        exec: accept
      - exec: $hosts
"#;
    let cfg = Config::from_yaml(yaml).unwrap();
    let rt = Runtime::build(cfg).await.unwrap();

    let q = build_query("ecs.test.", RecordType::A).unwrap();
    let mut ctx = QueryContext::new(q.clone(), None, ClientProto::Udp);
    ctx.trace_enabled = true;
    rt.handle_query(&mut ctx, "main").await.unwrap();
    assert!(ctx.has_resp());
    assert!(
        ctx.trace.iter().any(|t| t.event == "attach" && t.plugin == "ecs"),
        "trace={:?}",
        ctx.trace
    );
    assert!(
        ferrumdns::dnsutil::ecs_of(ctx.response().unwrap()).is_none(),
        "injected ECS must not leak to the client"
    );
    // query still carries ECS internally after pipeline
    assert!(ferrumdns::dnsutil::ecs_of(ctx.query()).is_some());

    let mut hit = QueryContext::new(q, None, ClientProto::Udp);
    hit.trace_enabled = true;
    rt.handle_query(&mut hit, "main").await.unwrap();
    assert!(
        hit.trace.iter().any(|t| t.event == "hit" && t.plugin == "cache"),
        "ecs-keyed cache should hit, trace={:?}",
        hit.trace
    );
    assert_eq!(hit.answer_ips()[0], "9.9.9.9".parse::<IpAddr>().unwrap());

    // a different subnet must miss (cache key includes ECS)
    let mut other = build_query("ecs.test.", RecordType::A).unwrap();
    ferrumdns::dnsutil::set_ecs(
        &mut other,
        hickory_proto::rr::rdata::opt::ClientSubnet::new(
            "198.51.100.0".parse().unwrap(),
            24,
            0,
        ),
    );
    let mut miss = QueryContext::new(other, None, ClientProto::Udp);
    miss.trace_enabled = true;
    rt.handle_query(&mut miss, "main").await.unwrap();
    assert!(
        miss.trace.iter().any(|t| t.event == "miss" && t.plugin == "cache"),
        "different ECS must not share a cache entry, trace={:?}",
        miss.trace
    );
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

#[tokio::test]
async fn default_entry_is_server_exec_not_first_sequence() {
    let cfg = Config::load_file(std::path::Path::new("examples/split-horizon.yaml")).unwrap();
    let rt = Runtime::build(cfg).await.unwrap();
    assert_eq!(
        rt.registry.default_entry.as_deref(),
        Some("main"),
        "lazy refresh / API must re-enter the listener pipeline"
    );
}

#[tokio::test]
async fn helper_sequence_does_not_fill_unrelated_cache() {
    let yaml = r#"
plugins:
  - tag: hosts
    type: hosts
    args:
      entries: ["1.1.1.1 side.test"]
  - tag: cache
    type: cache
    args: { size: 64 }
  - tag: helper
    type: sequence
    args:
      - exec: $hosts
  - tag: lookup
    type: sequence
    args:
      - exec: $cache
      - matches: has_resp
        exec: accept
"#;
    let rt = Runtime::build(Config::from_yaml(yaml).unwrap()).await.unwrap();
    let q = build_query("side.test.", RecordType::A).unwrap();
    let mut ctx = QueryContext::new(q.clone(), None, ClientProto::Udp);
    rt.handle_query(&mut ctx, "helper").await.unwrap();
    assert_eq!(ctx.answer_ips()[0], "1.1.1.1".parse::<IpAddr>().unwrap());

    let mut lookup = QueryContext::new(q, None, ClientProto::Udp);
    lookup.trace_enabled = true;
    rt.handle_query(&mut lookup, "lookup").await.unwrap();
    assert!(
        lookup
            .trace
            .iter()
            .any(|t| t.event == "miss" && t.plugin == "cache"),
        "helper sequence must not write the global LRU, trace={:?}",
        lookup.trace
    );
    assert!(!lookup.has_resp());
}
