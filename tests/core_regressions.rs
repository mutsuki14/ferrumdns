use ferrumdns::context::{build_query, ClientProto, QueryContext};
use ferrumdns::plugin::actions::Builtin;
use ferrumdns::plugin::Executable;
use ferrumdns::{Config, Runtime};
use hickory_proto::rr::{RData, RecordType};

#[tokio::test]
async fn invalid_ttl_ranges_are_rejected_before_serving() {
    for expression in [
        "ttl 300-60",
        "ttl a-60",
        "ttl 60-a",
        "ttl 60-",
        "ttl -1",
        "ttl",
    ] {
        let cfg = Config::from_yaml(&format!(
            "plugins:\n  - tag: main\n    type: sequence\n    args:\n      - exec: {expression}\n"
        ))
        .unwrap();
        assert!(Runtime::build(cfg).await.is_err(), "accepted {expression}");
    }
}

#[tokio::test]
async fn valid_ttl_range_clamps_answers_without_panicking() {
    let cfg = Config::from_yaml(
        r#"
plugins:
  - tag: hosts
    type: hosts
    args:
      ttl: 1200
      entries: ["192.0.2.1 ttl.test"]
  - tag: main
    type: sequence
    args:
      - exec: $hosts
      - exec: ttl 60-300
"#,
    )
    .unwrap();
    let rt = Runtime::build(cfg).await.unwrap();
    let mut ctx = QueryContext::new(
        build_query("ttl.test", RecordType::A).unwrap(),
        None,
        ClientProto::Udp,
    );
    rt.handle_query(&mut ctx, "main").await.unwrap();
    assert_eq!(ctx.response().unwrap().answers()[0].ttl(), 300);
    assert!(Builtin::Ttl { min: 300, max: 60 }.apply(&mut ctx).is_err());
}

#[tokio::test]
async fn redirect_preserves_original_question_and_adds_alias_chain() {
    let cfg = Config::from_yaml(
        r#"
plugins:
  - tag: redir
    type: redirect
    args:
      rules: {alias.test: target.test}
  - tag: hosts
    type: hosts
    args:
      entries: ["192.0.2.7 target.test"]
  - tag: main
    type: sequence
    args:
      - exec: $redir
      - exec: $hosts
"#,
    )
    .unwrap();
    let rt = Runtime::build(cfg).await.unwrap();
    let q = build_query("alias.test", RecordType::A).unwrap();
    let expected = q.queries().to_vec();
    let mut ctx = QueryContext::new(q, None, ClientProto::Udp);
    rt.handle_query(&mut ctx, "main").await.unwrap();
    let response = ctx.response().unwrap();
    assert_eq!(response.queries(), expected.as_slice());
    assert!(response.answers().iter().any(|record| {
        record.name() == expected[0].name()
            && matches!(record.data(), RData::CNAME(c) if c.0.to_ascii().trim_end_matches('.') == "target.test")
    }), "redirect response needs a CNAME from alias.test to target.test");
    assert_eq!(ctx.answer_ips()[0].to_string(), "192.0.2.7");
}

#[test]
fn invalid_redirect_rules_do_not_silently_disappear() {
    for yaml in [
        "rules: [123]",
        "rules: [\"only-one-name\"]",
        "rules: [\"a.test b.test c.test\"]",
        "rules: {a.test: 123}",
    ] {
        let args = serde_yaml::from_str(yaml).unwrap();
        assert!(
            ferrumdns::plugin::actions::Redirect::from_args(&args).is_err(),
            "accepted {yaml}"
        );
    }
}

#[tokio::test]
async fn ecs_zero_and_maximum_prefixes_are_preserved() {
    for (ip_key, address, mask_key, prefix, qtype) in [
        ("ipv4", "8.8.8.8", "mask4", 0, RecordType::A),
        ("ipv4", "8.8.8.8", "mask4", 32, RecordType::A),
        ("ipv6", "2001:4860:4860::8888", "mask6", 0, RecordType::AAAA),
        (
            "ipv6",
            "2001:4860:4860::8888",
            "mask6",
            128,
            RecordType::AAAA,
        ),
    ] {
        let args =
            serde_yaml::from_str(&format!("{ip_key}: '{address}'\n{mask_key}: {prefix}")).unwrap();
        let plugin = ferrumdns::plugin::ecs::Ecs::from_args("ecs", &args).unwrap();
        let mut ctx = QueryContext::new(
            build_query("ecs.test", qtype).unwrap(),
            None,
            ClientProto::Udp,
        );
        plugin.exec(&mut ctx).await.unwrap();
        let ecs = ferrumdns::dnsutil::ecs_of(ctx.query()).unwrap();
        assert_eq!(ecs.source_prefix(), prefix);
        if prefix == 0 {
            assert!(ecs.addr().is_unspecified());
        }
    }
}

#[test]
fn invalid_ecs_masks_are_rejected_instead_of_changed() {
    for masks in [
        "mask4: 33",
        "mask4: -1",
        "mask4: wrong",
        "mask6: 129",
        "mask6: -1",
        "mask6: 1.5",
    ] {
        let args = serde_yaml::from_str(&format!("ipv4: 8.8.8.8\n{masks}")).unwrap();
        assert!(
            ferrumdns::plugin::ecs::Ecs::from_args("ecs", &args).is_err(),
            "accepted {masks}"
        );
    }
}

#[tokio::test]
async fn hosts_inline_comments_do_not_install_extra_names() {
    let args = serde_yaml::from_str("entries: [\"192.0.2.8 real.test alias.test # unrelated.test\", \"reverse.test 192.0.2.9 # another.test\"]").unwrap();
    let plugin =
        ferrumdns::plugin::hosts::Hosts::from_args("hosts", &args, std::path::Path::new("."))
            .unwrap();
    for (name, expected) in [
        ("real.test", Some("192.0.2.8")),
        ("alias.test", Some("192.0.2.8")),
        ("reverse.test", Some("192.0.2.9")),
        ("unrelated.test", None),
        ("another.test", None),
    ] {
        let mut ctx = QueryContext::new(
            build_query(name, RecordType::A).unwrap(),
            None,
            ClientProto::Udp,
        );
        plugin.exec(&mut ctx).await.unwrap();
        assert_eq!(
            ctx.answer_ips().first().map(ToString::to_string).as_deref(),
            expected,
            "hostname {name}"
        );
    }
}
