# FerrumDNS

[**English**](README.md) | [简体中文](README.zh-CN.md)

[![ci](https://github.com/mutsuki14/ferrumdns/actions/workflows/ci.yml/badge.svg)](https://github.com/mutsuki14/ferrumdns/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/mutsuki14/ferrumdns?style=flat-square)](https://github.com/mutsuki14/ferrumdns/releases/latest)
[![license](https://img.shields.io/badge/license-MIT-steelblue.svg?style=flat-square)](LICENSE)
[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)

A high-performance plugin-pipeline DNS forwarder written in Rust.

Inspired by [mosdns-x](https://github.com/pmkol/mosdns-x) — same mental model (plugins, sequences, matchers), implemented from scratch for predictable latency, no GC pauses, and a small memory footprint.

## Table of Contents

- [Security](#security)
- [Background](#background)
- [Install](#install)
  - [System binary](#system-binary)
  - [Without root](#without-root)
  - [Docker](#docker)
  - [systemd](#systemd)
- [Usage](#usage)
  - [Quick start](#quick-start)
  - [Architecture](#architecture)
  - [Plugins](#plugins)
  - [EDNS Client Subnet](#edns-client-subnet)
  - [Upstreams](#upstreams)
  - [Listeners](#listeners)
  - [Compatibility](#compatibility)
  - [Performance](#performance)
- [API](#api)
- [Maintainers](#maintainers)
- [Contributing](#contributing)
- [License](#license)

## Security

- Bind `api.http` to loopback unless it sits behind something that authenticates callers. The admin API can flush the cache and replay queries.
- `ecs.auto: true` only belongs on a **public** resolver. Private, CGNAT, and loopback client addresses are skipped, but you still should not advertise a LAN IP as a subnet to the internet.
- Leave `insecure_skip_verify` off. It disables TLS validation for DoT/DoH upstreams.
- Incoming responses (`QR=1`) and non-QUERY opcodes are dropped or answered `NOTIMP` so the listener is not an amplifier.

## Background

FerrumDNS is a LAN / homelab / OpenWrt-class forwarder. The pipeline is mosdns-compatible YAML: plugins tagged and wired through a `sequence` of `matches` + `exec`.

v0.1.0 is the first tagged release. Shipped: lazy-cache background refresh, bootstrap DNS, DoH TLS listeners, UDP `SO_REUSEPORT` workers, TCP/DoT connection reuse, SIGHUP plugin reload, EDNS Client Subnet. Planned: DoQ, DoH3, geosite/geoip dat.

| | mosdns-x (Go) | FerrumDNS (Rust) |
|---|---|---|
| Runtime | GC | zero-GC, tokio |
| Pipeline | plugin sequence | plugin sequence (compatible YAML) |
| Listen | UDP / TCP / DoT / DoH / DoQ / DoH3 | UDP / TCP / DoT / DoH (HTTPS with `cert`/`key`, or HTTP behind a terminator) |
| Upstream | UDP / TCP / DoT / DoH / DoQ / DoH3 | UDP / TCP / DoT / DoH (`bootstrap` / `dial_addr`) |
| Cache | sharded LRU + lazy TTL | sharded LRU + lazy TTL + background refresh |
| ECS | `ecs` / `_no_ecs` | RFC 7871; cache key includes the subnet |
| Admin | HTTP + Prometheus | HTTP JSON + Prometheus |
| Reload | SIGHUP | SIGHUP swaps plugins, keeps sockets |

## Install

Download a binary from [GitHub Releases](https://github.com/mutsuki14/ferrumdns/releases/latest), or build from source (Rust 1.80+, via [rustup](https://rustup.rs)). Clone the repo, then pick **one** path.

```sh
git clone https://github.com/mutsuki14/ferrumdns.git
cd ferrumdns
```

### System binary

Binds `:53`. Needs root or `CAP_NET_BIND_SERVICE` (the [systemd unit](systemd/ferrumdns.service) already sets the capability).

```sh
cargo build --release
sudo install -m 0755 target/release/ferrumdns /usr/local/bin/ferrumdns
sudo mkdir -p /etc/ferrumdns
sudo cp examples/simple.yaml /etc/ferrumdns/config.yaml
ferrumdns check -c /etc/ferrumdns/config.yaml
sudo ferrumdns start -c /etc/ferrumdns/config.yaml
```

```sh
dig @127.0.0.1 router.lan
curl -s http://127.0.0.1:9090/api/stats
```

### Without root

`cargo install` puts the binary in `~/.cargo/bin`. Put that directory on your `PATH`. **Do not** run it via `sudo` — sudo's PATH does not include `~/.cargo/bin`.

```sh
cargo install --path . --locked
ferrumdns check -c examples/dev.yaml
ferrumdns start -c examples/dev.yaml
```

```sh
dig @127.0.0.1 -p 5353 router.lan
curl -s http://127.0.0.1:9090/api/stats
```

### Docker

The image already contains `examples/docker.yaml` (API on `0.0.0.0:9090` so published port 9090 is reachable). Do **not** mount a host path that does not exist — Docker will create a directory there and the process will fail to read the config.

```sh
docker build -t ferrumdns .
docker run --rm --name ferrumdns \
  -p 53:53/udp -p 53:53/tcp -p 9090:9090 \
  ferrumdns
```

To override the baked-in config, pass a file that already exists:

```sh
docker run --rm --name ferrumdns \
  -p 53:53/udp -p 53:53/tcp -p 9090:9090 \
  -v "$PWD/examples/docker.yaml:/etc/ferrumdns/config.yaml:ro" \
  ferrumdns
```

### systemd

```sh
sudo mkdir -p /etc/ferrumdns
sudo cp examples/simple.yaml /etc/ferrumdns/config.yaml
sudo install -m 0755 target/release/ferrumdns /usr/local/bin/ferrumdns
sudo cp systemd/ferrumdns.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ferrumdns
# later: edit /etc/ferrumdns/config.yaml then
sudo systemctl reload ferrumdns   # SIGHUP — plugins swap, sockets stay
```

## Usage

### Quick start

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

  - tag: ecs
    type: ecs
    args:
      ipv4: 8.8.8.8
      mask4: 24

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
          bootstrap: 1.1.1.1
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
      - exec: $ecs
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

`examples/dev.yaml` binds `127.0.0.1:5353` so this does not need root. `examples/simple.yaml` binds `:53` and will fail with `permission denied` as a normal user.

### Architecture

```
client ──► UDP/TCP/DoT/DoH listener
              │
              ▼
         sequence (main)
           ├─ matchers  (qname / qtype / client_ip / resp_ip / has_resp / …)
           ├─ hosts / blackhole / redirect / ttl / ecs
           ├─ sharded LRU cache  (lazy TTL + background refresh; key includes ECS)
           ├─ forward  (race N encrypted upstreams)
           └─ fallback (primary + secondary, optional always_standby)
```

Each query carries a `QueryContext` through the pipeline. Plugins either fill a response, rewrite the question, or jump (`accept` / `return` / `goto` / `reject`).

### Plugins

| Type | Role |
|---|---|
| `sequence` | Ordered steps with `matches` + `exec` |
| `forward` / `fast_forward` | Concurrent upstream exchange |
| `cache` | Sharded LRU, optional lazy TTL + background refresh |
| `hosts` | Static A/AAAA |
| `domain_set` | Suffix / `full:` / `keyword:` / `regexp:` / `domain:` |
| `ip_set` | CIDR set |
| `fallback` | Primary/secondary with threshold |
| `black_hole` | Force an RCODE |
| `redirect` | Rewrite qname |
| `ecs` | Attach EDNS Client Subnet (RFC 7871) |
| `no_ecs` / `_no_ecs` | Strip ECS from query and reply |
| `udp_server` / `tcp_server` / `tls_server` / `doh_server` | Listeners (also via `servers:`) |

Built-in `exec` commands: `accept`, `return`, `reject <rcode>`, `drop_resp`, `ttl min-max`, `prefer_ipv4`, `prefer_ipv6`, `mark N`, `goto $tag`, `no_ecs`.

Matchers: `qname $set`, `qtype A AAAA`, `client_ip $set`, `resp_ip $set`, `has_resp`, `has_wanted_ans`, `rcode`, `mark`, `ecs`. Prefix `!` to negate.

### EDNS Client Subnet

Put `ecs` **before** `cache` so geo-steered answers don't collide in the LRU. If the client did not send ECS, the plugin strips it from the reply (RFC 7871 privacy). `auto: true` uses the query source IP and **skips private / CGNAT / loopback** addresses — only enable `auto` on a public resolver.

```yaml
- tag: ecs
  type: ecs
  args:
    auto: false                 # true = use client IP (public only)
    ipv4: 8.8.8.8               # preset, preferred on A queries
    ipv6: "2001:4860:4860::8888"
    mask4: 24                   # default 24
    mask6: 48                   # default 48
    force_overwrite: false      # keep a client-supplied ECS

# later in the sequence:
- exec: $ecs
- exec: $cache
# or drop everything:
- exec: no_ecs
```

Admin `POST /api/query` accepts optional `"ecs": "203.0.113.0/24"` and `"client_ip": "8.8.8.8"` to replay.

### Upstreams

```
udp://8.8.8.8:53
tcp://1.1.1.1:53
tls://1.1.1.1          # DoT, port 853
https://dns.google/dns-query
```

Hostname DoH/DoT can pin the IP so the forwarder does not depend on the system resolver:

```yaml
- addr: https://cloudflare-dns.com/dns-query
  bootstrap: 1.1.1.1          # resolve the hostname via this IP (port 53)
  # dial_addr: 1.1.1.1        # or skip DNS entirely and dial this IP
  # insecure_skip_verify: true
```

`concurrent: N` races the first N upstreams and takes the first successful answer.

TCP and DoT reuse idle RFC 7766 sessions (pool of 8 per upstream). DoH reuses HTTP/2 via reqwest.

### Listeners

```yaml
servers:
  - exec: main
    listeners:
      - protocol: udp
        addr: 0.0.0.0:53
        workers: 4            # SO_REUSEPORT; default min(8, CPU)
      - protocol: tcp
        addr: 0.0.0.0:53
      - protocol: tls         # DoT
        addr: 0.0.0.0:853
        cert: /etc/ferrumdns/fullchain.pem
        key: /etc/ferrumdns/privkey.pem
      - protocol: doh         # DoH — cert+key → HTTPS; omit both for HTTP
        addr: 0.0.0.0:443
        cert: /etc/ferrumdns/fullchain.pem
        key: /etc/ferrumdns/privkey.pem
        url_path: /dns-query
```

SIGHUP (`systemctl reload ferrumdns` / `kill -HUP $pid`) rebuilds plugins from the same config file. Listen address and certificate path changes still need a restart.

### Compatibility

FerrumDNS accepts **mosdns v5-style** plugin lists (`matches` / `exec` / `$tag`) and **mosdns-x-style** `servers:` + `listeners`. Not every mosdns-x plugin is implemented (no nftset, no DoQ/DoH3 yet). The goal is a drop-in subset for the forwarding / split-horizon / ad-block setups people actually run.

Relative `files:` entries (`hosts`, `domain_set`, `ip_set`) and `include:` are resolved against the config file's directory.

### Performance

- Multi-thread tokio runtime, UDP `SO_REUSEPORT` workers (default `min(8, CPU)`)
- 16-way sharded cache to keep LRU locks off the hot path
- Lazy cache: serve a short TTL immediately, refresh in the background
- DoH connection pooling via reqwest/hyper HTTP/2; hostname pin via `bootstrap` / `dial_addr`
- DoT / TCP reuse length-prefixed RFC 7766 sessions (idle pool of 8)
- SIGHUP reloads plugins without dropping sockets
- Release profile: LTO thin, `opt-level=3`, stripped

## API

Bind with `api.http`.

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Liveness |
| GET | `/metrics` | Prometheus text |
| GET | `/api/stats` | JSON counters |
| GET | `/api/plugins` | Loaded tags |
| POST | `/api/query` | `{ "name", "qtype", "entry?", "ecs?", "client_ip?" }` — debug a query with a pipeline trace |
| POST | `/api/cache/flush` | Drop the LRU |

```sh
cargo test --all
cargo run -- start -c examples/dev.yaml
dig @127.0.0.1 -p 5353 router.lan
curl -s http://127.0.0.1:9090/api/stats
curl -s -X POST http://127.0.0.1:9090/api/query \
  -H 'content-type: application/json' \
  -d '{"name":"router.lan","qtype":"A"}'
```

## Maintainers

[@mutsuki14](https://github.com/mutsuki14)

## Contributing

Issues and pull requests are welcome.

Run `cargo test --all` before sending a patch.

If you edit the README, follow the [standard-readme](https://github.com/RichardLitt/standard-readme) specification and keep [README.md](README.md) and [README.zh-CN.md](README.zh-CN.md) in sync.

## License

[MIT © mutsuki14](LICENSE)

Architecture inspired by mosdns / mosdns-x (GPL-3.0); this codebase is original.
