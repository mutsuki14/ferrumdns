# FerrumDNS

**A high-performance plugin-pipeline DNS forwarder written in Rust.**

Inspired by [mosdns-x](https://github.com/pmkol/mosdns-x) — same mental model (plugins, sequences, matchers), implemented from scratch for predictable latency, no GC pauses, and a tiny memory footprint.

[![ci](https://github.com/mutsuki14/ferrumdns/actions/workflows/ci.yml/badge.svg)](https://github.com/mutsuki14/ferrumdns/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-steelblue.svg)](LICENSE)

---

FerrumDNS 是一个用 **Rust** 编写的高性能 DNS 转发器。配置模型对齐 mosdns-x / mosdns v5：把缓存、分流、广告拦截、加密上游、回退组合成一条可编排的流水线。

## Why FerrumDNS

| | mosdns-x (Go) | FerrumDNS (Rust) |
|---|---|---|
| Runtime | GC | zero-GC, tokio |
| Pipeline | plugin sequence | plugin sequence (compatible YAML) |
| Listen | UDP / TCP / DoT / DoH / DoQ / DoH3 | UDP / TCP / DoT / DoH |
| Upstream | UDP / TCP / DoT / DoH / DoQ / DoH3 | UDP / TCP / DoT / DoH |
| Cache | sharded LRU + lazy TTL | sharded LRU + lazy TTL |
| Admin | HTTP + Prometheus | HTTP JSON + Prometheus |

## Install

```bash
# from source
cargo install --path . --locked

# or build a release binary
cargo build --release
sudo install -m 0755 target/release/ferrumdns /usr/local/bin/
```

Drop `examples/simple.yaml` at `/etc/ferrumdns/config.yaml`, then:

```bash
ferrumdns check -c /etc/ferrumdns/config.yaml
sudo ferrumdns start -c /etc/ferrumdns/config.yaml
```

Docker:

```bash
docker build -t ferrumdns .
docker run --rm -p 53:53/udp -p 53:53/tcp -p 9090:9090 \
  -v $PWD/config.yaml:/etc/ferrumdns/config.yaml \
  ferrumdns
```

Without root, bind a high port (`0.0.0.0:5353`) instead of `:53`.

## Quick start

```yaml
log:
  level: info

api:
  http: 127.0.0.1:9090

plugins:
  - tag: ads
    type: domain_set
    args:
      exps:
        - keyword:doubleclick
        - ads.example.com

  - tag: cache
    type: cache
    args:
      size: 8192
      lazy_cache_ttl: 86400

  - tag: hosts
    type: hosts
    args:
      entries:
        - "10.0.0.1 router.lan"

  - tag: upstream
    type: forward
    args:
      concurrent: 2
      upstreams:
        - addr: https://cloudflare-dns.com/dns-query
        - addr: tls://1.1.1.1
        - addr: udp://8.8.8.8:53

  - tag: main
    type: sequence
    args:
      - matches: [qname $ads]
        exec: reject NXDOMAIN
      - exec: $hosts
      - matches: has_resp
        exec: accept
      - exec: $cache
      - matches: has_resp
        exec: accept
      - exec: $upstream

  - type: udp_server
    args:
      entry: main
      listen: 0.0.0.0:53

  - type: tcp_server
    args:
      entry: main
      listen: 0.0.0.0:53
```

Point a client at it:

```bash
dig @127.0.0.1 router.lan
curl -s http://127.0.0.1:9090/api/stats
```

## Architecture

```
client ──► UDP/TCP/DoT/DoH listener
              │
              ▼
         sequence (main)
           ├─ matchers  (qname / qtype / client_ip / resp_ip / has_resp / …)
           ├─ hosts / blackhole / redirect / ttl
           ├─ sharded LRU cache  (lazy refresh)
           ├─ forward  (race N encrypted upstreams)
           └─ fallback (primary + secondary, optional always_standby)
```

Each query carries a `QueryContext` through the pipeline. Plugins either fill a response, rewrite the question, or jump (`accept` / `return` / `goto` / `reject`).

## Plugins

| Type | Role |
|---|---|
| `sequence` | Ordered steps with `matches` + `exec` |
| `forward` / `fast_forward` | Concurrent upstream exchange |
| `cache` | Sharded LRU, optional lazy TTL |
| `hosts` | Static A/AAAA |
| `domain_set` | Suffix / `full:` / `keyword:` / `regexp:` / `domain:` |
| `ip_set` | CIDR set |
| `fallback` | Primary/secondary with threshold |
| `black_hole` | Force an RCODE |
| `redirect` | Rewrite qname |
| `udp_server` / `tcp_server` / `tls_server` / `doh_server` | Listeners (also via `servers:`) |

Built-in `exec` commands: `accept`, `return`, `reject <rcode>`, `drop_resp`, `ttl min-max`, `prefer_ipv4`, `prefer_ipv6`, `mark N`, `goto $tag`.

Matchers: `qname $set`, `qtype A AAAA`, `client_ip $set`, `resp_ip $set`, `has_resp`, `has_wanted_ans`, `rcode`, `mark`. Prefix `!` to negate.

### Upstream URL schemes

```
udp://8.8.8.8:53
tcp://1.1.1.1:53
tls://1.1.1.1          # DoT, port 853
https://dns.google/dns-query
```

`concurrent: N` races the first N upstreams and takes the first successful answer.

## Admin API

Bind with `api.http`. Endpoints:

| Method | Path | |
|---|---|---|
| GET | `/health` | liveness |
| GET | `/metrics` | Prometheus text |
| GET | `/api/stats` | JSON counters |
| GET | `/api/plugins` | loaded tags |
| POST | `/api/query` | `{ "name", "qtype", "entry?" }` — debug a query with a pipeline trace |
| POST | `/api/cache/flush` | drop the LRU |

## Config compatibility

FerrumDNS accepts **mosdns v5-style** plugin lists (`matches` / `exec` / `$tag`) and **mosdns-x-style** `servers:` + `listeners`. Not every mosdns-x plugin is implemented (no nftset, no DoQ/DoH3 yet). The goal is a drop-in subset for the forwarding / split-horizon / ad-block setups people actually run.

## Performance notes

- Multi-thread tokio runtime, `SO_REUSEPORT` on UDP
- 16-way sharded cache to keep LRU locks off the hot path
- DoH connection pooling via reqwest/hyper HTTP/2
- DoT / TCP use length-prefixed RFC 7766 sessions
- Release profile: LTO thin, `opt-level=3`, stripped

## Development

```bash
cargo test
cargo run -- start -c examples/simple.yaml
```

## License

MIT. Architecture inspired by mosdns / mosdns-x (GPL-3.0); this codebase is original.

## Status

v0.1 — usable as a LAN / homelab / OpenWrt-class forwarder. Planned: DoQ, DoH3, geosite/geoip dat, SIGHUP reload, ECS.
