# Changelog

## Unreleased

### English

- Remove the Docker deployment path, image recipe, container example and related CI/documentation. Supported installation paths are the native binary, Cargo and systemd.
- Set the minimum Rust version to 1.88 and test both that version and stable against the locked dependencies.
- Bound and parallelize TLS handshakes; preserve the DoH peer address; acquire current rules for each query on persistent TCP/DoT connections.
- Validate upstream source and question identity, retry truncated UDP answers over TCP, and preserve usable partial bootstrap results.
- Write only caches actually reached by a query; separate DNSSEC query modes and prevent request-specific EDNS data from leaking through cached responses.
- Preserve original questions and CNAME chains during redirects; replay the initial pipeline context for lazy refresh.
- Release replaced plugin registries, isolate fallback branches, and cancel losing or abandoned fallback work.
- Reject cyclic includes and invalid configuration before serving; propagate listener failures; normalize entry references; keep working configuration on rejected reloads.
- Validate TTL/ECS bounds, support zero-length ECS prefixes, ignore hosts inline comments, validate diagnostic client addresses, and honor file logging.

### 简体中文

- 删除 Docker 部署入口、镜像文件、容器示例和相关 CI/文档，保留原生二进制、Cargo、systemd 安装方式。
- 最低 Rust 版本调整为 1.88；CI 使用该版本和 stable 分别验证锁定依赖。
- TLS 握手增加并发和超时限制；DoH 保留来源地址；已有 TCP/DoT 连接的每条查询使用当前规则。
- 校验上游响应来源及问题，UDP 截断后回退 TCP，Bootstrap 保留可用的部分结果。
- 只回填实际执行过的缓存步骤，区分 DNSSEC 请求模式，防止客户端专属 EDNS 数据经缓存串用。
- 重定向保留原始问题并补全 CNAME 链，lazy 刷新从流水线的初始上下文重放。
- 释放旧插件注册表，隔离主备分支状态，取消落败或已被放弃的回退任务。
- 在服务启动前拒绝循环 include 和非法配置；传播监听失败；统一入口名称；重载失败时保留旧配置。
- 校验 TTL/ECS 边界，支持 ECS /0，正确处理 Hosts 行内注释，校验诊断接口来源地址，并实现文件日志。

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
