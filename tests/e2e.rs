use ferrumdns::config::Config;
use ferrumdns::context::{build_query, ClientProto, QueryContext};
use ferrumdns::runtime::Runtime;
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
        ctx2.trace.iter().any(|t| t.event == "hit"),
        "expected cache hit, trace={:?}",
        ctx2.trace
    );
}
