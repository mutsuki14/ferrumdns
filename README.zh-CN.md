# FerrumDNS

[English](README.md) | [**简体中文**](README.zh-CN.md)

[![ci](https://github.com/mutsuki14/ferrumdns/actions/workflows/ci.yml/badge.svg)](https://github.com/mutsuki14/ferrumdns/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/mutsuki14/ferrumdns?style=flat-square)](https://github.com/mutsuki14/ferrumdns/releases/latest)
[![license](https://img.shields.io/badge/license-MIT-steelblue.svg?style=flat-square)](LICENSE)
[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)

用 Rust 编写的高性能插件流水线 DNS 转发器。

配置心智对齐 [mosdns-x](https://github.com/pmkol/mosdns-x)：插件、sequence、matcher。从零实现，延迟可预期，没有 GC 停顿，内存占用小。

## 内容列表

- [安全](#安全)
- [背景](#背景)
- [安装](#安装)
  - [系统二进制](#系统二进制)
  - [无需 root](#无需-root)
  - [Docker](#docker)
  - [systemd](#systemd)
- [使用说明](#使用说明)
  - [快速开始](#快速开始)
  - [架构](#架构)
  - [插件](#插件)
  - [EDNS Client Subnet](#edns-client-subnet)
  - [上游](#上游)
  - [监听](#监听)
  - [兼容性](#兼容性)
  - [性能](#性能)
- [API](#api)
- [维护者](#维护者)
- [如何贡献](#如何贡献)
- [使用许可](#使用许可)

## 安全

- 除非前面有鉴权，否则把 `api.http` 绑在回环地址。管理接口能清空缓存、回放查询。
- `ecs.auto: true` 只适合**公网**解析器。内网 / CGNAT / 回环地址会被跳过，但也不该把局域网 IP 当作子网广播到公网。
- 不要打开 `insecure_skip_verify`。它会关掉 DoT/DoH 上游的 TLS 校验。
- 入站应答（`QR=1`）和非 QUERY 操作码会被丢弃或回 `NOTIMP`，避免成为反射放大器。

## 背景

FerrumDNS 面向局域网 / 家庭实验室 / OpenWrt 级转发。流水线是 mosdns 兼容的 YAML：插件用 tag 引用，经 `sequence` 的 `matches` + `exec` 串联。

v0.1.1。首个 tag 是 0.1.0。已交付：lazy 缓存后台刷新、bootstrap DNS、DoH TLS 监听、UDP `SO_REUSEPORT` worker、TCP/DoT 连接复用、SIGHUP 热加载、EDNS Client Subnet。规划中：DoQ、DoH3、geosite/geoip dat。

| | mosdns-x (Go) | FerrumDNS (Rust) |
|---|---|---|
| 运行时 | GC | 无 GC，tokio |
| 流水线 | 插件序列 | 插件序列（兼容 YAML） |
| 监听 | UDP / TCP / DoT / DoH / DoQ / DoH3 | UDP / TCP / DoT / DoH（`cert`/`key` 开 HTTPS，或前面挂 TLS 终结） |
| 上游 | UDP / TCP / DoT / DoH / DoQ / DoH3 | UDP / TCP / DoT / DoH（`bootstrap` / `dial_addr`） |
| 缓存 | 分片 LRU + lazy TTL | 分片 LRU + lazy TTL + 后台刷新 |
| ECS | `ecs` / `_no_ecs` | RFC 7871；缓存 key 带上子网 |
| 管理口 | HTTP + Prometheus | HTTP JSON + Prometheus |
| 热加载 | SIGHUP | SIGHUP 换插件，套接字不关 |

## 安装

二进制从 [GitHub Releases](https://github.com/mutsuki14/ferrumdns/releases/latest) 下载，或从源码编译（Rust 1.80+，见 [rustup](https://rustup.rs)）。先克隆仓库，再选 **一种** 安装方式。

```sh
git clone https://github.com/mutsuki14/ferrumdns.git
cd ferrumdns
```

### 系统二进制

绑定 `:53`。需要 root 或 `CAP_NET_BIND_SERVICE`（[systemd 单元](systemd/ferrumdns.service) 已经带上该能力）。

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

### 无需 root

`cargo install` 把二进制放到 `~/.cargo/bin`。把该目录加入 `PATH`。**不要**用 `sudo` 跑它 — sudo 的 PATH 不含 `~/.cargo/bin`。

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

镜像内置 `examples/docker.yaml`（管理 API 听 `0.0.0.0:9090`，映射 9090 即可访问）。**不要**挂载一个还不存在的宿主机路径 — Docker 会在那里创建一个目录，进程读配置会失败。

```sh
docker build -t ferrumdns .
docker run --rm --name ferrumdns \
  -p 53:53/udp -p 53:53/tcp -p 9090:9090 \
  ferrumdns
```

覆盖内置配置时，挂载一个已经存在的文件：

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
# 之后改 /etc/ferrumdns/config.yaml，然后
sudo systemctl reload ferrumdns   # SIGHUP — 换插件，套接字不关
```

## 使用说明

### 快速开始

仓库内示例：

| 文件 | 监听 | API | 用途 |
|---|---|---|---|
| [`examples/simple.yaml`](examples/simple.yaml) | `0.0.0.0:53` | `127.0.0.1:9090` | 本机 / systemd |
| [`examples/dev.yaml`](examples/dev.yaml) | `127.0.0.1:5353` | `127.0.0.1:9090` | `cargo run`，无需 root |
| [`examples/docker.yaml`](examples/docker.yaml) | `0.0.0.0:53` | `0.0.0.0:9090` | 容器 |
| [`examples/split-horizon.yaml`](examples/split-horizon.yaml) | `0.0.0.0:53` | `127.0.0.1:9090` | 广告拦截 + 国内分流 + fallback |

YAML 里的 `files:` 相对该文件所在目录解析，所以在仓库根目录执行 `ferrumdns check -c examples/split-horizon.yaml` 即可。

最小流水线（与 `examples/simple.yaml` 同构）：

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

保存为 `config.yaml`，然后 `ferrumdns check -c config.yaml && ferrumdns start -c config.yaml`。

`examples/dev.yaml` 绑定 `127.0.0.1:5353`，无需 root。`examples/simple.yaml` 绑定 `:53`，普通用户会得到 `permission denied`。

### 架构

```
客户端 ──► UDP/TCP/DoT/DoH 监听
              │
              ▼
         sequence (main)
           ├─ matcher  (qname / qtype / client_ip / resp_ip / has_resp / …)
           ├─ hosts / blackhole / redirect / ttl / ecs
           ├─ 分片 LRU 缓存  (lazy TTL + 后台刷新；key 含 ECS)
           ├─ forward  (并发竞速加密上游)
           └─ fallback (主备，可选 always_standby)
```

每条查询带着 `QueryContext` 走过流水线。插件负责填应答、改写问题，或跳转（`accept` / `return` / `goto` / `reject`）。

### 插件

| 类型 | 作用 |
|---|---|
| `sequence` | 带 `matches` + `exec` 的步骤列表 |
| `forward` / `fast_forward` | 并发询问上游 |
| `cache` | 分片 LRU，可选 lazy TTL + 后台刷新 |
| `hosts` | 静态 A/AAAA |
| `domain_set` | 后缀 / `full:` / `keyword:` / `regexp:` / `domain:` |
| `ip_set` | CIDR 集合 |
| `fallback` | 主备，带阈值 |
| `black_hole` | 写死一个 RCODE |
| `redirect` | 改写 qname |
| `ecs` | 附加 EDNS Client Subnet（RFC 7871） |
| `no_ecs` / `_no_ecs` | 从请求和应答里剥掉 ECS |
| `udp_server` / `tcp_server` / `tls_server` / `doh_server` | 监听（也可用 `servers:`） |

内置 `exec`：`accept`、`return`、`reject <rcode>`、`drop_resp`、`ttl min-max`、`prefer_ipv4`、`prefer_ipv6`、`mark N`、`goto $tag`、`no_ecs`。

Matcher：`qname $set`、`qtype A AAAA`、`client_ip $set`、`resp_ip $set`、`has_resp`、`has_wanted_ans`、`rcode`、`mark`、`ecs`。前缀 `!` 取反。

### EDNS Client Subnet

把 `ecs` 放在 **`cache` 前面**，避免不同地区的答案在 LRU 里互相覆盖。若客户端没有带 ECS，插件会从应答里剥掉它（RFC 7871 隐私）。`auto: true` 用来源 IP，并 **跳过内网 / CGNAT / 回环** — 只在公网解析器上开启 `auto`。

```yaml
- tag: ecs
  type: ecs
  args:
    auto: false                 # true = 用客户端公网 IP
    ipv4: 8.8.8.8               # 预设，A 查询优先
    ipv6: "2001:4860:4860::8888"
    mask4: 24                   # 默认 24
    mask6: 48                   # 默认 48
    force_overwrite: false      # 保留客户端自带的 ECS

# 流水线里：
- exec: $ecs
- exec: $cache
# 或者整段剥掉：
- exec: no_ecs
```

管理口 `POST /api/query` 可带 `"ecs": "203.0.113.0/24"` 和 `"client_ip": "8.8.8.8"` 做回放。

### 上游

```
udp://8.8.8.8:53
tcp://1.1.1.1:53
tls://1.1.1.1          # DoT，端口 853
https://dns.google/dns-query
```

DoH/DoT 主机名可以钉死 IP，转发器不必依赖系统 DNS：

```yaml
- addr: https://cloudflare-dns.com/dns-query
  bootstrap: 1.1.1.1          # 用这个 IP 解析主机名（53 端口）
  # dial_addr: 1.1.1.1        # 或完全跳过 DNS，直接拨这个 IP
  # insecure_skip_verify: true
```

`concurrent: N` 竞速前 N 个上游，取第一个成功应答。

TCP / DoT 复用空闲的 RFC 7766 会话（每路上游最多 8 条）。DoH 走 reqwest 的 HTTP/2 连接池。

### 监听

```yaml
servers:
  - exec: main
    listeners:
      - protocol: udp
        addr: 0.0.0.0:53
        workers: 4            # SO_REUSEPORT；默认 min(8, CPU)
      - protocol: tcp
        addr: 0.0.0.0:53
      - protocol: tls         # DoT
        addr: 0.0.0.0:853
        cert: /etc/ferrumdns/fullchain.pem
        key: /etc/ferrumdns/privkey.pem
      - protocol: doh         # DoH — 同时给 cert+key 即 HTTPS；两个都不写则是明文
        addr: 0.0.0.0:443
        cert: /etc/ferrumdns/fullchain.pem
        key: /etc/ferrumdns/privkey.pem
        url_path: /dns-query
```

SIGHUP（`systemctl reload ferrumdns` / `kill -HUP $pid`）从同一份配置重建插件。改监听地址或证书路径仍需重启。

### 兼容性

FerrumDNS 接受 **mosdns v5 风格** 的插件列表（`matches` / `exec` / `$tag`）以及 **mosdns-x 风格** 的 `servers:` + `listeners`。并非所有 mosdns-x 插件都已实现（暂无 nftset、DoQ/DoH3）。目标是覆盖人们实际在跑的转发 / 分流 / 广告拦截配置的可落地子集。

相对路径的 `files:`（`hosts`、`domain_set`、`ip_set`）和 `include:` 相对配置文件所在目录解析。

### 性能

- 多线程 tokio，UDP `SO_REUSEPORT` worker（默认 `min(8, CPU)`）
- 16 路分片缓存，热路径少抢 LRU 锁
- Lazy 缓存：先用短 TTL 应答，后台刷新
- DoH 连接池（reqwest/hyper HTTP/2）；主机名用 `bootstrap` / `dial_addr` 钉 IP
- DoT / TCP 复用带长度前缀的 RFC 7766 会话（空闲池 8）
- SIGHUP 换插件不丢套接字
- Release：thin LTO、`opt-level=3`、strip

## API

用 `api.http` 绑定。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health` | 存活检查 |
| GET | `/metrics` | Prometheus 文本 |
| GET | `/api/stats` | JSON 计数 |
| GET | `/api/plugins` | 已加载的 tag |
| POST | `/api/query` | `{ "name", "qtype", "entry?", "ecs?", "client_ip?" }` — 带流水线 trace 的调试查询 |
| POST | `/api/cache/flush` | 清空 LRU |

```sh
cargo test --all
cargo run -- start -c examples/dev.yaml
dig @127.0.0.1 -p 5353 router.lan
curl -s http://127.0.0.1:9090/api/stats
curl -s -X POST http://127.0.0.1:9090/api/query \
  -H 'content-type: application/json' \
  -d '{"name":"router.lan","qtype":"A"}'
```

## 维护者

[@mutsuki14](https://github.com/mutsuki14)

## 如何贡献

欢迎 Issue 和 Pull Request。

提交补丁前请运行 `cargo test --all`。

若修改 README，请遵循 [standard-readme](https://github.com/RichardLitt/standard-readme) 规范，并同步更新 [README.md](README.md) 与 [README.zh-CN.md](README.zh-CN.md)。

## 使用许可

[MIT © mutsuki14](LICENSE)

架构参考 mosdns / mosdns-x（GPL-3.0）；本仓库代码是全新的 Rust 实现。
