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
| Listen | UDP / TCP / DoT / DoH / DoQ / DoH3 | UDP / TCP / DoT / DoH (DoH listener is HTTP; terminate TLS in front) |
| Upstream | UDP / TCP / DoT / DoH / DoQ / DoH3 | UDP / TCP / DoT / DoH |
| Cache | sharded LRU + lazy TTL | sharded LRU + lazy TTL |
| Admin | HTTP + Prometheus | HTTP JSON + Prometheus |

## Install

Requires a Rust toolchain (1.80+, via [rustup](https://rustup.rs)). Clone the repo, then pick **one** install path.

```bash
git clone https://github.com/mutsuki14/ferrumdns.git
cd ferrumdns
```

### A. System binary (bind `:53`)

```bash
cargo build --release
sudo install -m 0755 target/release/ferrumdns /usr/local/bin/ferrumdns
sudo mkdir -p /etc/ferrumdns
sudo cp examples/simple.yaml /etc/ferrumdns/config.yaml
ferrumdns check -c /etc/ferrumdns/config.yaml
sudo ferrumdns start -c /etc/ferrumdns/config.yaml
```

`:53` needs root or `CAP_NET_BIND_SERVICE` (the [systemd unit](systemd/ferrumdns.service) already sets the capability). Query it with:

```bash
dig @127.0.0.1 router.lan
curl -s http://127.0.0.1:9090/api/stats
```

### B. User install, high port (no root)

`cargo install` puts the binary in `~/.cargo/bin`. Put that directory on your `PATH`. **Do not** run it via `sudo` — sudo's PATH does not include `~/.cargo/bin`.

```bash
cargo install --path . --locked
ferrumdns check -c examples/dev.yaml
ferrumdns start -c examples/dev.yaml
```

```bash
dig @127.0.0.1 -p 5353 router.lan
curl -s http://127.0.0.1:9090/api/stats
```

### Docker

The image already contains `examples/docker.yaml` (API on `0.0.0.0:9090` so published port 9090 is reachable). Do **not** mount a host path that does not exist — Docker will create a directory there and the process will fail to read the config.

```bash
docker build -t ferrumdns .
docker run --rm --name ferrumdns \
  -p 53:53/udp -p 53:53/tcp -p 9090:9090 \
  ferrumdns
```

To override the baked-in config, pass a file that already exists:

```bash
docker run --rm --name ferrumdns \
  -p 53:53/udp -p 53:53/tcp -p 9090:9090 \
  -v "$PWD/examples/docker.yaml:/etc/ferrumdns/config.yaml:ro" \
  ferrumdns
```

### systemd

```bash
sudo mkdir -p /etc/ferrumdns
sudo cp examples/simple.yaml /etc/ferrumdns/config.yaml
sudo install -m 0755 target/release/ferrumdns /usr/local/bin/ferrumdns
sudo cp systemd/ferrumdns.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ferrumdns
```

## Quick start

Checked-in configs:

| File | Bind | API | Use |
|---|---|---|---|
| [`examples/simple.yaml`](examples/simple.yaml) | `0.0.0.0:53` | `127.0.0.1:9090` | local / systemd |
| [`examples/dev.yaml`](examples/dev.yaml) | `127.0.0.1:5353` | `127.0.0.1:9090` | `cargo run`, no root |
| [`examples/docker.yaml`](examples/docker.yaml) | `0.0.0.0:53` | `0.0.0.0:9090` | container |
| [`examples/split-horizon.yaml`](examples/split-horizon.yaml) | `0.0.0.0:53` | `127.0.0.1:9090` | ads + CN split + fallback |

`files:` paths inside a YAML file are resolved relative to that file, so `ferrumdns check -c examples/split-horizon.yaml` works from the repo root.

Minimal pipeline (same shape as `examples/simple.yaml`):

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
      listen: 127.0.0.1:5353

  - type: tcp_server
    args:
      entry: main
      listen: 127.0.0.1:5353
```

Save that as `config.yaml` and run `ferrumdns check -c config.yaml && ferrumdns start -c config.yaml`.

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

Relative `files:` entries (`hosts`, `domain_set`, `ip_set`) and `include:` are resolved against the config file's directory.

## Performance notes

- Multi-thread tokio runtime, `SO_REUSEPORT` on UDP
- 16-way sharded cache to keep LRU locks off the hot path
- DoH connection pooling via reqwest/hyper HTTP/2
- DoT / TCP use length-prefixed RFC 7766 sessions
- Release profile: LTO thin, `opt-level=3`, stripped

## Development

```bash
cargo test --all
cargo run -- start -c examples/dev.yaml
dig @127.0.0.1 -p 5353 router.lan
curl -s http://127.0.0.1:9090/api/stats
curl -s -X POST http://127.0.0.1:9090/api/query \
  -H 'content-type: application/json' \
  -d '{"name":"router.lan","qtype":"A"}'
```

`examples/dev.yaml` binds `127.0.0.1:5353` so this does not need root. `examples/simple.yaml` binds `:53` and will fail with `permission denied` as a normal user.

## License

MIT. Architecture inspired by mosdns / mosdns-x (GPL-3.0); this codebase is original.

## Status

v0.1 — usable as a LAN / homelab / OpenWrt-class forwarder. Planned: DoQ, DoH3, geosite/geoip dat, SIGHUP reload, ECS.
