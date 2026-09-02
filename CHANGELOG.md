# Changelog

## [0.1.1] — 2026-09-02

Cache-poisoning and pipeline-entry fixes found after the 0.1.0 review.

### English

- Only the sequence that actually runs `$cache` writes that LRU (helper sequences no longer fill the global cache)
- Cache hits / lazy hits are not written back (that used to reset the lazy expire window and freeze stale answers)
- Lazy refresh and the admin API re-enter the listener `exec` (`main`), not the first `sequence` in the file
- `fallback` `always_standby` aborts the loser and copies the winner's full context (ECS strip flag, rewritten question, marks)
- `ecs.auto` treats IPv4-mapped IPv6 private / CGNAT addresses as private
- `udp_server` accepts `exec` as an alias of `entry`, strips `$`, rejects a list-valued `listen`, and reads `url_path`
- Sequence `matches` that are not strings fail at load instead of matching everything

### 简体中文

- 只有真正执行了 `$cache` 的 sequence 才会写入该 LRU（辅助 sequence 不再污染全局缓存）
- 缓存命中 / lazy 命中不再回写（以前会重置 lazy 过期窗口，把过期答案“续命”）
- lazy 刷新和管理 API 走监听的 `exec`（`main`），而不是文件里第一条 sequence
- `fallback` `always_standby` 会 abort 落败的那路，并完整拷贝胜者上下文（ECS 剥离标记、改写后的问题、mark）
- `ecs.auto` 把 IPv4-mapped IPv6 的内网 / CGNAT 地址当私网
- `udp_server` 接受 `exec` 作为 `entry` 别名、去掉 `$`、拒绝列表形式的 `listen`、读取 `url_path`
- sequence 的 `matches` 如果不是字符串，加载时直接报错，而不是匹配全部

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

[0.1.1]: https://github.com/mutsuki14/ferrumdns/releases/tag/v0.1.1
[0.1.0]: https://github.com/mutsuki14/ferrumdns/releases/tag/v0.1.0
