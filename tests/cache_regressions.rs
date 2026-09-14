// Regression coverage for cache isolation, redirects and request cancellation.
#[cfg(test)]
mod tests {
    use ferrumdns::config::Config;
    use ferrumdns::context::{build_query, ClientProto, QueryContext};
    use ferrumdns::dnsutil;
    use ferrumdns::metrics::Metrics;
    use ferrumdns::plugin::{cache::Cache, Executable};
    use ferrumdns::runtime::Runtime;
    use hickory_proto::op::{Edns, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};
    use std::sync::Arc;
    use std::time::Duration;

    async fn runtime(yaml: &str) -> Arc<Runtime> {
        Runtime::build(Config::from_yaml(yaml).unwrap())
            .await
            .unwrap()
    }

    fn ctx(name: &str) -> QueryContext {
        QueryContext::new(
            build_query(name, RecordType::A).unwrap(),
            None,
            ClientProto::Udp,
        )
    }

    #[tokio::test]
    async fn runtime_drop_must_release_plugin_registry() {
        let rt = runtime(
            r#"
plugins:
  - { tag: cache, type: cache, args: { size: 64 } }
  - { tag: main, type: sequence, args: ["$cache"] }
"#,
        )
        .await;
        let registry = Arc::downgrade(&rt.registry);
        let cache = Arc::downgrade(rt.registry.caches.get("cache").unwrap());
        drop(rt);
        assert!(
            registry.upgrade().is_none(),
            "registry remains alive after Runtime is dropped: Arc reference cycle"
        );
        assert!(
            cache.upgrade().is_none(),
            "cached DNS answers remain alive after reload/drop"
        );
    }

    #[tokio::test]
    async fn cache_must_distinguish_dnssec_do_and_cd() {
        let cache = Cache::from_args(
            "cache",
            &serde_yaml::from_str("{}").unwrap(),
            Metrics::new(),
        );
        let mut insecure = ctx("signed.test.");
        insecure.query_mut().set_checking_disabled(true);
        let mut edns = Edns::new();
        edns.set_dnssec_ok(false);
        insecure.query_mut().set_edns(edns);
        let mut resp = dnsutil::reply_skeleton(insecure.query(), ResponseCode::NoError);
        resp.add_answer(dnsutil::record_a(
            Name::from_ascii("signed.test.").unwrap(),
            60,
            "1.2.3.4".parse().unwrap(),
        ));
        insecure.set_response(resp);
        cache.maybe_store(&insecure);

        let mut validating = ctx("signed.test.");
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        validating.query_mut().set_edns(edns);
        cache.exec(&mut validating).await.unwrap();
        assert!(
            !validating.has_resp(),
            "DO=1/CD=0 query hit DO=0/CD=1 cache entry"
        );
    }

    #[tokio::test]
    async fn skipped_cache_must_not_leak_private_answer_to_public_client() {
        let rt = runtime(
            r#"
plugins:
  - { tag: lan, type: ip_set, args: { exps: ["10.0.0.0/8"] } }
  - { tag: private, type: hosts, args: { entries: ["10.0.0.99 split.test"] } }
  - { tag: public, type: hosts, args: { entries: ["9.9.9.9 split.test"] } }
  - { tag: cache, type: cache, args: { size: 64 } }
  - tag: main
    type: sequence
    args:
      - { matches: "client_ip $lan", exec: "$private" }
      - { matches: has_resp, exec: accept }
      - exec: $cache
      - { matches: has_resp, exec: accept }
      - exec: $public
"#,
        )
        .await;
        let mut internal = ctx("split.test.");
        internal.client_addr = Some("10.0.0.1".parse().unwrap());
        rt.handle_query(&mut internal, "main").await.unwrap();
        assert_eq!(internal.answer_ips()[0].to_string(), "10.0.0.99");
        let mut external = ctx("split.test.");
        external.client_addr = Some("203.0.113.1".parse().unwrap());
        rt.handle_query(&mut external, "main").await.unwrap();
        assert_eq!(
            external.answer_ips()[0].to_string(),
            "9.9.9.9",
            "LAN query accepted before $cache must not populate public cache"
        );
    }

    #[tokio::test]
    async fn fallback_must_not_leak_failed_primary_marks_to_secondary() {
        let rt = runtime(r#"
plugins:
  - { tag: hosts, type: hosts, args: { entries: ["9.9.9.9 fallback.test"] } }
  - { tag: primary, type: sequence, args: ["mark 7", "return"] }
  - tag: secondary
    type: sequence
    args:
      - { matches: "mark 7", exec: "reject NXDOMAIN" }
      - exec: $hosts
  - { tag: fb, type: fallback, args: { primary: primary, secondary: secondary, threshold: 100, always_standby: false } }
  - { tag: main, type: sequence, args: ["$fb"] }
"#).await;
        let mut q = ctx("fallback.test.");
        rt.handle_query(&mut q, "main").await.unwrap();
        assert_eq!(
            q.response().unwrap().response_code(),
            ResponseCode::NoError,
            "failed primary branch altered secondary matching"
        );
    }

    #[tokio::test]
    async fn lazy_refresh_must_restart_with_original_query() {
        let rt = runtime(
            r#"
plugins:
  - { tag: redirect, type: redirect, args: { rules: ["a.test b.test", "b.test c.test"] } }
  - { tag: hosts, type: hosts, args: { ttl: 1, entries: ["1.1.1.1 b.test", "2.2.2.2 c.test"] } }
  - { tag: cache, type: cache, args: { size: 64, lazy_cache_ttl: 60, lazy_cache_reply_ttl: 5 } }
  - tag: main
    type: sequence
    args:
      - exec: $redirect
      - exec: $cache
      - { matches: has_resp, exec: accept }
      - exec: $hosts
"#,
        )
        .await;
        let mut first = ctx("a.test.");
        rt.handle_query(&mut first, "main").await.unwrap();
        assert_eq!(first.answer_ips()[0].to_string(), "1.1.1.1");
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let mut stale = ctx("a.test.");
        rt.handle_query(&mut stale, "main").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut after = ctx("a.test.");
        after.trace_enabled = true;
        rt.handle_query(&mut after, "main").await.unwrap();
        assert!(
            after
                .trace
                .iter()
                .any(|t| t.plugin == "cache" && t.event == "hit"),
            "background refresh rewrote b.test -> c.test and left b.test stale: {:?}",
            after.trace
        );
    }

    #[tokio::test]
    async fn cancelling_fallback_must_cancel_spawned_branches() {
        use ferrumdns::plugin::fallback::{BoundFallback, Fallback};
        use ferrumdns::plugin::{Action, Registry};
        use std::collections::HashMap;
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Delayed(Arc<AtomicUsize>);
        #[async_trait::async_trait]
        impl Executable for Delayed {
            async fn exec(&self, _: &mut QueryContext) -> ferrumdns::error::Result<Action> {
                tokio::time::sleep(Duration::from_millis(60)).await;
                self.0.fetch_add(1, Ordering::Relaxed);
                Ok(Action::Continue)
            }
        }
        let completed = Arc::new(AtomicUsize::new(0));
        let mut execs: HashMap<String, Arc<dyn Executable>> = HashMap::new();
        execs.insert("p".into(), Arc::new(Delayed(completed.clone())));
        execs.insert("s".into(), Arc::new(Delayed(completed.clone())));
        let reg = Arc::new(Registry {
            execs,
            domains: HashMap::new(),
            ips: HashMap::new(),
            caches: HashMap::new(),
            metrics: Metrics::new(),
            default_entry: None,
        });
        let fallback = BoundFallback::bind(
            Fallback {
                tag: "fb".into(),
                primary: "p".into(),
                secondary: "s".into(),
                threshold: Duration::from_millis(200),
                always_standby: true,
            },
            reg,
        );
        let mut q = ctx("cancel.test.");
        assert!(
            tokio::time::timeout(Duration::from_millis(10), fallback.exec(&mut q))
                .await
                .is_err()
        );
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(
            completed.load(Ordering::Relaxed),
            0,
            "both detached upstream branches continued after parent request timeout"
        );
    }

    #[tokio::test]
    async fn cache_with_false_matcher_is_not_written() {
        let rt = runtime(
            r#"
plugins:
  - { tag: hosts, type: hosts, args: { entries: ["1.2.3.4 conditional.test"] } }
  - { tag: cache, type: cache, args: {} }
  - tag: main
    type: sequence
    args:
      - { matches: "mark 99", exec: "$cache" }
      - exec: $hosts
"#,
        )
        .await;
        let mut q = ctx("conditional.test.");
        rt.handle_query(&mut q, "main").await.unwrap();
        assert!(q.has_resp());
        assert_eq!(rt.registry.caches["cache"].len(), 0);
    }

    #[tokio::test]
    async fn redirect_cache_before_or_after_rewrite_preserves_aliases_and_keys() {
        for cache_before_redirect in [false, true] {
            let mut steps = if cache_before_redirect {
                vec!["$cache", "accept-if-hit", "$redirect"]
            } else {
                vec!["$redirect", "$cache", "accept-if-hit"]
            };
            steps.push("$hosts");
            let steps = steps
                .iter()
                .map(|step| {
                    if *step == "accept-if-hit" {
                        "      - { matches: has_resp, exec: accept }".to_string()
                    } else {
                        format!("      - exec: {step}")
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            let yaml = format!(
                r#"
plugins:
  - {{ tag: redirect, type: redirect, args: {{ rules: ["a.test target.test", "b.test target.test"] }} }}
  - {{ tag: hosts, type: hosts, args: {{ entries: ["1.2.3.4 target.test"] }} }}
  - {{ tag: cache, type: cache, args: {{}} }}
  - tag: main
    type: sequence
    args:
{steps}
"#
            );
            let rt = runtime(&yaml).await;
            for (name, expected_aliases) in [
                ("a.test.", 1),
                ("a.test.", 1),
                ("b.test.", 1),
                ("target.test.", 0),
            ] {
                let mut q = ctx(name);
                q.trace_enabled = true;
                rt.handle_query(&mut q, "main").await.unwrap();
                let response = q.response().unwrap();
                assert_eq!(response.queries(), q.original().queries());
                let aliases = response
                    .answers()
                    .iter()
                    .filter(|r| r.record_type() == RecordType::CNAME)
                    .collect::<Vec<_>>();
                assert_eq!(aliases.len(), expected_aliases);
                if let Some(alias) = aliases.first() {
                    assert_eq!(alias.name(), &Name::from_ascii(name).unwrap());
                }
                assert_eq!(q.answer_ips()[0].to_string(), "1.2.3.4");
            }
            // Before redirect: aliases have separate keys; after it: all three
            // names share exactly one target entry without polluting its RRsets.
            assert_eq!(
                rt.registry.caches["cache"].len(),
                if cache_before_redirect { 3 } else { 1 }
            );
        }
    }

    #[test]
    fn lazy_refresh_restores_initial_marks_and_query() {
        let mut q = ctx("original.test.");
        q.add_mark(7);
        q.begin_pipeline("main");
        q.add_mark(9);
        q.rewrite_name(Name::from_ascii("modified.test.").unwrap());
        q.strip_ecs_on_reply = true;
        let lazy = q.clone_for_lazy();
        assert_eq!(lazy.qname_str(), "original.test.");
        assert!(lazy.has_mark(7));
        assert!(!lazy.has_mark(9));
        assert!(!lazy.strip_ecs_on_reply);
        assert!(lazy.skip_cache);
    }

    #[tokio::test]
    async fn cache_isolates_individual_flags_and_rebuilds_question_edns_payload() {
        let cache = Cache::from_args(
            "cache",
            &serde_yaml::from_str("{}").unwrap(),
            Metrics::new(),
        );
        let mut original = ctx("MiXeD.test.");
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        original.query_mut().set_edns(edns);
        let mut response = dnsutil::reply_skeleton(original.query(), ResponseCode::NoError);
        response.add_answer(dnsutil::record_a(
            Name::from_ascii("MiXeD.test.").unwrap(),
            60,
            "1.2.3.4".parse().unwrap(),
        ));
        original.set_response(response);
        cache.maybe_store(&original);
        for flag in ["do", "cd", "rd", "no-edns"] {
            let mut query = ctx("mixed.test.");
            query.query_mut().set_edns(Edns::new());
            match flag {
                "do" => {
                    query
                        .query_mut()
                        .extensions_mut()
                        .as_mut()
                        .unwrap()
                        .set_dnssec_ok(true);
                }
                "cd" => {
                    query.query_mut().set_checking_disabled(true);
                }
                "rd" => {
                    query.query_mut().set_recursion_desired(false);
                }
                _ => {
                    *query.query_mut().extensions_mut() = None;
                }
            }
            cache.exec(&mut query).await.unwrap();
            assert!(!query.has_resp(), "flag {flag} must have a separate key");
        }
        let mut hit = ctx("mixed.test.");
        let mut edns = Edns::new();
        edns.set_max_payload(512);
        hit.query_mut().set_edns(edns);
        cache.exec(&mut hit).await.unwrap();
        assert!(hit.served_from_cache);
        let response = hit.response().unwrap();
        assert_eq!(response.id(), hit.query().id());
        assert_eq!(response.queries(), hit.query().queries());
        assert_eq!(response.extensions().as_ref().unwrap().max_payload(), 512);
    }

    #[tokio::test]
    async fn cache_does_not_store_or_replay_client_specific_edns_cookies() {
        use hickory_proto::rr::rdata::opt::EdnsOption;
        let cache = Cache::from_args(
            "cache",
            &serde_yaml::from_str("{}").unwrap(),
            Metrics::new(),
        );
        let mut warm = ctx("cookie.test.");
        let mut edns = Edns::new();
        edns.options_mut()
            .insert(EdnsOption::Unknown(10, vec![1; 8]));
        warm.query_mut().set_edns(edns);
        let mut response = dnsutil::reply_skeleton(warm.query(), ResponseCode::NoError);
        response.add_answer(dnsutil::record_a(
            Name::from_ascii("cookie.test.").unwrap(),
            60,
            "1.2.3.4".parse().unwrap(),
        ));
        warm.set_response(response);
        cache.maybe_store(&warm);
        assert_eq!(cache.len(), 0, "query cookie must bypass cache");
        *warm.query_mut().extensions_mut() = None;
        cache.maybe_store(&warm);
        assert_eq!(
            cache.len(),
            0,
            "unsolicited upstream cookie must also bypass cache"
        );
    }

    #[tokio::test]
    async fn winning_forward_closes_losing_tcp_exchange() {
        use ferrumdns::plugin::forward::Forward;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio::sync::oneshot;
        let slow = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fast = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (received_tx, received_rx) = oneshot::channel();
        let (closed_tx, closed_rx) = oneshot::channel();
        let yaml = format!(
            "concurrent: 2\ntimeout: 5000\nupstreams: [tcp://{}, tcp://{}]",
            fast.local_addr().unwrap(),
            slow.local_addr().unwrap()
        );
        let slow_server = tokio::spawn(async move {
            let (mut socket, _) = slow.accept().await.unwrap();
            let len = socket.read_u16().await.unwrap();
            let mut wire = vec![0; len as usize];
            socket.read_exact(&mut wire).await.unwrap();
            received_tx.send(()).unwrap();
            let result = tokio::time::timeout(Duration::from_millis(500), socket.read_u8()).await;
            let closed = matches!(result, Ok(Err(ref error)) if error.kind() == std::io::ErrorKind::UnexpectedEof);
            let _ = closed_tx.send(closed);
        });
        let fast_server = tokio::spawn(async move {
            let (mut socket, _) = fast.accept().await.unwrap();
            let len = socket.read_u16().await.unwrap();
            let mut wire = vec![0; len as usize];
            socket.read_exact(&mut wire).await.unwrap();
            let query = dnsutil::decode(&wire).unwrap();
            received_rx.await.unwrap();
            let mut response = dnsutil::reply_skeleton(&query, ResponseCode::NoError);
            response.add_answer(dnsutil::record_a(
                Name::from_ascii("race.test.").unwrap(),
                60,
                "1.2.3.4".parse().unwrap(),
            ));
            let wire = dnsutil::encode(&response).unwrap();
            socket.write_u16(wire.len() as u16).await.unwrap();
            socket.write_all(&wire).await.unwrap();
        });
        let forward = Forward::from_args(
            "forward",
            &serde_yaml::from_str(&yaml).unwrap(),
            Metrics::new(),
        )
        .await
        .unwrap();
        let mut query = ctx("race.test.");
        tokio::time::timeout(Duration::from_secs(2), forward.exec(&mut query))
            .await
            .unwrap()
            .unwrap();
        assert!(query.has_wanted_ans());
        assert!(
            closed_rx.await.unwrap(),
            "losing TCP stream must close when the fast upstream wins"
        );
        slow_server.await.unwrap();
        fast_server.await.unwrap();
    }

    #[tokio::test]
    async fn deeply_negated_matchers_keep_parity_without_recursion() {
        use ferrumdns::plugin::sequence::bind_matcher;
        let rt = runtime("plugins: [{ tag: main, type: sequence, args: [accept] }]").await;
        let mut query = ctx("negation.test.");
        query.add_mark(7);
        for count in [0, 1, 2, 3, 20_000, 20_001] {
            let expression = format!("{} mark 7", "! ".repeat(count));
            let matcher = bind_matcher(&expression, &rt.registry).unwrap();
            assert_eq!(matcher.matches(&query), count % 2 == 0);
        }
    }
}
