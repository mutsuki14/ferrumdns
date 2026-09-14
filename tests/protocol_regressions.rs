//! Deterministic protocol regressions. All network traffic stays on loopback.
use base64::Engine;
use ferrumdns::config::ListenerConfig;
use ferrumdns::context::build_query;
use ferrumdns::dnsutil;
use ferrumdns::upstream::{Upstream, UpstreamSpec};
use ferrumdns::{Config, Live, Runtime};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

const LIMIT: Duration = Duration::from_secs(3);

fn answer(q: &Message, ip: Ipv4Addr) -> Message {
    let mut r = dnsutil::reply_skeleton(q, ResponseCode::NoError);
    r.add_answer(dnsutil::record_a(q.queries()[0].name().clone(), 60, ip));
    r
}

fn first_ip(r: &Message) -> String {
    r.answers()[0].data().to_string()
}

async fn read_frame<S: AsyncReadExt + Unpin>(s: &mut S) -> Message {
    let size = s.read_u16().await.unwrap();
    let mut bytes = vec![0; size as usize];
    s.read_exact(&mut bytes).await.unwrap();
    dnsutil::decode(&bytes).unwrap()
}

async fn write_frame<S: AsyncWriteExt + Unpin>(s: &mut S, q: &Message) {
    let bytes = dnsutil::encode(q).unwrap();
    s.write_u16(bytes.len() as u16).await.unwrap();
    s.write_all(&bytes).await.unwrap();
    s.flush().await.unwrap();
}

async fn framed_query<S: AsyncReadExt + AsyncWriteExt + Unpin>(s: &mut S, q: &Message) -> Message {
    timeout(LIMIT, async {
        write_frame(s, q).await;
        read_frame(s).await
    })
    .await
    .expect("DNS stream query timed out")
}

async fn upstream(addr: String, bootstrap: Option<String>) -> Upstream {
    Upstream::connect(UpstreamSpec {
        addr,
        dial_addr: None,
        bootstrap,
        idle_timeout: Duration::from_secs(10),
        insecure: false,
        tag: None,
    })
    .await
    .unwrap()
}

fn hosts_config(ip: &str) -> Config {
    Config::from_yaml(&format!(
        r#"
plugins:
  - tag: hosts
    type: hosts
    args:
      entries: ["{ip} audit.test"]
  - tag: main
    type: sequence
    args:
      - exec: $hosts
"#
    ))
    .unwrap()
}

struct Listener {
    addr: SocketAddr,
    task: JoinHandle<ferrumdns::error::Result<()>>,
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn listener(live: Live, protocol: &str, tls: bool) -> Listener {
    let reserve = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = reserve.local_addr().unwrap();
    drop(reserve);
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/protocol");
    let cfg = ListenerConfig {
        protocol: protocol.into(),
        addr: addr.to_string(),
        cert: tls.then(|| {
            fixtures
                .join("localhost-test.pem")
                .to_str()
                .unwrap()
                .to_string()
        }),
        key: tls.then(|| {
            fixtures
                .join("localhost-test.key")
                .to_str()
                .unwrap()
                .to_string()
        }),
        url_path: None,
        idle_timeout: Some(1),
        workers: Some(1),
    };
    let task = tokio::spawn(ferrumdns::server::spawn_listener(
        live,
        "main".into(),
        LIMIT,
        cfg,
    ));
    let result = Listener { addr, task };
    timeout(LIMIT, async {
        loop {
            assert!(!result.task.is_finished(), "listener exited during startup");
            if TcpStream::connect(addr).await.is_ok() {
                break;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    result
}

#[tokio::test]
async fn udp_response_must_come_from_configured_source() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let mock = tokio::spawn(async move {
        let mut bytes = [0; 2048];
        let (n, peer) = socket.recv_from(&mut bytes).await.unwrap();
        let q = dnsutil::decode(&bytes[..n]).unwrap();
        let alien = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        alien
            .send_to(
                &dnsutil::encode(&answer(&q, Ipv4Addr::new(203, 0, 113, 66))).unwrap(),
                peer,
            )
            .await
            .unwrap();
        sleep(Duration::from_millis(30)).await;
        socket
            .send_to(
                &dnsutil::encode(&answer(&q, Ipv4Addr::new(192, 0, 2, 1))).unwrap(),
                peer,
            )
            .await
            .unwrap();
    });
    let up = upstream(format!("udp://{addr}"), None).await;
    let q = build_query("audit.test.", RecordType::A).unwrap();
    let result = up.exchange(&q, LIMIT).await.unwrap();
    assert_eq!(first_ip(&result), "192.0.2.1");
    mock.await.unwrap();
}

#[tokio::test]
async fn udp_ignores_wrong_question_before_accepting_valid_reply() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let mock = tokio::spawn(async move {
        let mut bytes = [0; 2048];
        let (n, peer) = socket.recv_from(&mut bytes).await.unwrap();
        let q = dnsutil::decode(&bytes[..n]).unwrap();
        let mut wrong = q.clone();
        wrong.queries_mut()[0].set_name(Name::from_ascii("unrelated.test.").unwrap());
        socket
            .send_to(
                &dnsutil::encode(&answer(&wrong, Ipv4Addr::new(203, 0, 113, 66))).unwrap(),
                peer,
            )
            .await
            .unwrap();
        socket
            .send_to(
                &dnsutil::encode(&answer(&q, Ipv4Addr::new(192, 0, 2, 2))).unwrap(),
                peer,
            )
            .await
            .unwrap();
    });
    let up = upstream(format!("udp://{addr}"), None).await;
    let q = build_query("audit.test.", RecordType::A).unwrap();
    let result = up.exchange(&q, LIMIT).await.unwrap();
    assert_eq!(result.queries(), q.queries());
    assert_eq!(first_ip(&result), "192.0.2.2");
    mock.await.unwrap();
}

#[tokio::test]
async fn udp_truncation_retries_tcp_for_a_tcp_client() {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(addr).await.unwrap();
    let mock = tokio::spawn(async move {
        let mut bytes = [0; 2048];
        let (n, peer) = udp.recv_from(&mut bytes).await.unwrap();
        let q = dnsutil::decode(&bytes[..n]).unwrap();
        let mut truncated = dnsutil::reply_skeleton(&q, ResponseCode::NoError);
        truncated.set_truncated(true);
        udp.send_to(&dnsutil::encode(&truncated).unwrap(), peer)
            .await
            .unwrap();
        let (mut stream, _) = timeout(LIMIT, tcp.accept()).await.unwrap().unwrap();
        let retry = read_frame(&mut stream).await;
        assert_eq!(retry.queries(), q.queries());
        write_frame(&mut stream, &answer(&retry, Ipv4Addr::new(192, 0, 2, 3))).await;
    });
    let cfg = Config::from_yaml(&format!(
        r#"
plugins:
  - tag: upstream
    type: forward
    args:
      upstreams: ["udp://{addr}"]
  - tag: main
    type: sequence
    args:
      - exec: $upstream
"#
    ))
    .unwrap();
    let server = listener(Live::new(Runtime::build(cfg).await.unwrap()), "tcp", false).await;
    let mut stream = TcpStream::connect(server.addr).await.unwrap();
    let q = build_query("audit.test.", RecordType::A).unwrap();
    let result = framed_query(&mut stream, &q).await;
    assert!(!result.truncated());
    assert_eq!(first_ip(&result), "192.0.2.3");
    mock.await.unwrap();
}

#[tokio::test]
async fn live_reload_updates_existing_tcp_session() {
    let live = Live::new(Runtime::build(hosts_config("10.0.0.1")).await.unwrap());
    let server = listener(live.clone(), "tcp", false).await;
    let mut stream = TcpStream::connect(server.addr).await.unwrap();
    let q = build_query("audit.test.", RecordType::A).unwrap();
    assert_eq!(first_ip(&framed_query(&mut stream, &q).await), "10.0.0.1");
    live.swap(Runtime::build(hosts_config("10.0.0.2")).await.unwrap());
    assert_eq!(first_ip(&framed_query(&mut stream, &q).await), "10.0.0.2");
}

#[tokio::test]
async fn doh_get_and_post_use_the_direct_client_ip() {
    let cfg = Config::from_yaml(
        r#"
plugins:
  - tag: local
    type: ip_set
    args: { exps: ["127.0.0.0/8"] }
  - tag: local_hosts
    type: hosts
    args: { entries: ["10.0.0.1 audit.test"] }
  - tag: other_hosts
    type: hosts
    args: { entries: ["10.0.0.2 audit.test"] }
  - tag: main
    type: sequence
    args:
      - matches: client_ip $local
        exec: $local_hosts
      - matches: has_resp
        exec: accept
      - exec: $other_hosts
"#,
    )
    .unwrap();
    let live = Live::new(Runtime::build(cfg).await.unwrap());
    let server = listener(live, "http", false).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(LIMIT)
        .build()
        .unwrap();
    let q = build_query("audit.test.", RecordType::A).unwrap();
    let bytes = dnsutil::encode(&q).unwrap();
    let response = client
        .post(format!("http://{}/dns-query", server.addr))
        .header("content-type", "application/dns-message")
        // An arbitrary forwarding header must not override the socket peer.
        .header("x-forwarded-for", "203.0.113.7")
        .body(bytes.clone())
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    assert_eq!(
        first_ip(&dnsutil::decode(&response.bytes().await.unwrap()).unwrap()),
        "10.0.0.1"
    );
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let response = client
        .get(format!("http://{}/dns-query?dns={encoded}", server.addr))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    assert_eq!(
        first_ip(&dnsutil::decode(&response.bytes().await.unwrap()).unwrap()),
        "10.0.0.1"
    );
}

#[tokio::test]
async fn an_idle_tls_client_cannot_block_a_new_doh_handshake() {
    let live = Live::new(Runtime::build(hosts_config("10.0.0.1")).await.unwrap());
    let server = listener(live, "https", true).await;
    let mut idle = TcpStream::connect(server.addr).await.unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_millis(700))
        .build()
        .unwrap();
    let q = build_query("audit.test.", RecordType::A).unwrap();
    let response = client
        .post(format!("https://{}/dns-query", server.addr))
        .header("content-type", "application/dns-message")
        .body(dnsutil::encode(&q).unwrap())
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    assert_eq!(
        first_ip(&dnsutil::decode(&response.bytes().await.unwrap()).unwrap()),
        "10.0.0.1"
    );
    let mut byte = [0];
    let closed = timeout(Duration::from_secs(2), idle.read(&mut byte))
        .await
        .expect("incomplete TLS handshake must expire");
    assert!(matches!(closed, Ok(0) | Err(_)));
}

#[tokio::test]
async fn bootstrap_partial_success_survives_a_lost_other_family() {
    for successful_type in [RecordType::A, RecordType::AAAA] {
        let final_addr = if successful_type == RecordType::A {
            "127.0.0.1:0"
        } else {
            "[::1]:0"
        };
        let resolver = UdpSocket::bind(final_addr).await.unwrap();
        let resolver_addr = resolver.local_addr().unwrap();
        let bootstrap = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bootstrap_addr = bootstrap.local_addr().unwrap();
        let boot_mock = tokio::spawn(async move {
            let mut bytes = [0; 2048];
            loop {
                let (n, peer) = bootstrap.recv_from(&mut bytes).await.unwrap();
                let q = dnsutil::decode(&bytes[..n]).unwrap();
                if q.queries()[0].query_type() == successful_type {
                    let mut r = dnsutil::reply_skeleton(&q, ResponseCode::NoError);
                    if successful_type == RecordType::A {
                        r.add_answer(dnsutil::record_a(
                            q.queries()[0].name().clone(),
                            60,
                            Ipv4Addr::LOCALHOST,
                        ));
                    } else {
                        r.add_answer(dnsutil::record_aaaa(
                            q.queries()[0].name().clone(),
                            60,
                            std::net::Ipv6Addr::LOCALHOST,
                        ));
                    }
                    bootstrap
                        .send_to(&dnsutil::encode(&r).unwrap(), peer)
                        .await
                        .unwrap();
                }
            }
        });
        let final_mock = tokio::spawn(async move {
            let mut bytes = [0; 2048];
            let (n, peer) = resolver.recv_from(&mut bytes).await.unwrap();
            let q = dnsutil::decode(&bytes[..n]).unwrap();
            resolver
                .send_to(
                    &dnsutil::encode(&answer(&q, Ipv4Addr::new(192, 0, 2, 4))).unwrap(),
                    peer,
                )
                .await
                .unwrap();
        });
        let up = upstream(
            format!("udp://resolver.test:{}", resolver_addr.port()),
            Some(bootstrap_addr.to_string()),
        )
        .await;
        let q = build_query("audit.test.", RecordType::A).unwrap();
        let result = up.exchange(&q, Duration::from_millis(500)).await.unwrap();
        assert_eq!(first_ip(&result), "192.0.2.4");
        final_mock.await.unwrap();
        boot_mock.abort();
    }
}

#[tokio::test]
async fn live_reload_updates_existing_dot_session() {
    let live = Live::new(Runtime::build(hosts_config("10.0.0.1")).await.unwrap());
    let server = listener(live.clone(), "tls", true).await;
    let mut roots = rustls::RootCertStore::empty();
    let fixture = include_bytes!("protocol/localhost-test.pem");
    for certificate in rustls_pemfile::certs(&mut fixture.as_slice()) {
        roots.add(certificate.unwrap()).unwrap();
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(server.addr).await.unwrap();
    let mut stream = connector
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            stream,
        )
        .await
        .unwrap();
    let q = build_query("audit.test.", RecordType::A).unwrap();
    assert_eq!(first_ip(&framed_query(&mut stream, &q).await), "10.0.0.1");
    live.swap(Runtime::build(hosts_config("10.0.0.2")).await.unwrap());
    assert_eq!(first_ip(&framed_query(&mut stream, &q).await), "10.0.0.2");
}

#[tokio::test]
async fn doh_bootstrap_uses_the_current_short_exchange_budget() {
    let live = Live::new(Runtime::build(hosts_config("10.0.0.1")).await.unwrap());
    let server = listener(live, "http", false).await;
    let bootstrap = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bootstrap_addr = bootstrap.local_addr().unwrap();
    let mock = tokio::spawn(async move {
        loop {
            let mut bytes = [0; 2048];
            let (n, peer) = bootstrap.recv_from(&mut bytes).await.unwrap();
            let q = dnsutil::decode(&bytes[..n]).unwrap();
            if q.queries()[0].query_type() == RecordType::A {
                bootstrap
                    .send_to(
                        &dnsutil::encode(&answer(&q, Ipv4Addr::LOCALHOST)).unwrap(),
                        peer,
                    )
                    .await
                    .unwrap();
            }
        }
    });
    let up = upstream(
        // localhost also avoids any environment-configured outbound proxy.
        format!("http://localhost:{}/dns-query", server.addr.port()),
        Some(bootstrap_addr.to_string()),
    )
    .await;
    let q = build_query("audit.test.", RecordType::A).unwrap();
    let result = up.exchange(&q, Duration::from_millis(500)).await.unwrap();
    assert_eq!(first_ip(&result), "10.0.0.1");
    mock.abort();
}
