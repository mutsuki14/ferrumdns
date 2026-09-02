# Changelog

## [0.1.0] — 2026-09-02

First tagged release.

### English

Plugin-pipeline DNS forwarder (mosdns v5 / mosdns-x compatible YAML) written in Rust.

- Listen: UDP (`SO_REUSEPORT` workers), TCP, DoT, DoH (HTTP or HTTPS)
- Upstream: UDP, TCP, DoT, DoH with `bootstrap` / `dial_addr`
- Cache: 16-way sharded LRU, lazy TTL, background refresh
- EDNS Client Subnet (RFC 7871): `ecs` / `no_ecs`, cache key includes the subnet
- SIGHUP reloads plugins without dropping sockets
- Admin HTTP JSON + Prometheus

Fixes in this tag:

- Cache hits no longer subtract elapsed time from the OPT record (that field is EDNS flags / DO, not a TTL)
- Concurrent upstream races ignore `REFUSED` the same way they ignore `SERVFAIL`
- `fallback` `always_standby` no longer skips the cache (`clone_for_lazy` was reused by mistake)
- Truncated UDP answers keep the OPT record (RFC 6891)

### 简体中文

用 Rust 写的插件流水线 DNS 转发器（兼容 mosdns v5 / mosdns-x YAML）。

- 监听：UDP（`SO_REUSEPORT` worker）、TCP、DoT、DoH（明文或 HTTPS）
- 上游：UDP / TCP / DoT / DoH，支持 `bootstrap` / `dial_addr`
- 缓存：16 路分片 LRU、lazy TTL、后台刷新
- EDNS Client Subnet（RFC 7871）：`ecs` / `no_ecs`，缓存 key 带上子网
- SIGHUP 热加载插件，套接字不关
- HTTP JSON 管理口 + Prometheus

本 tag 修掉的问题：

- 缓存命中不再把 OPT 记录的 TTL 字段当生存期递减（那是 EDNS 标志 / DO 位）
- 并发竞速把 `REFUSED` 和 `SERVFAIL` 一样视为不可用
- `fallback` 的 `always_standby` 不再误跳过缓存
- UDP 截断应答保留 OPT（RFC 6891）

[0.1.0]: https://github.com/mutsuki14/ferrumdns/releases/tag/v0.1.0
