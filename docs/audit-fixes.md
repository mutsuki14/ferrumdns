# 代码检查问题修复记录

对应 `b7a3905d76f53b33f24e4af92610e85b35975e51` 版本检查报告的 F01–F22。
Docker 部署按维护者要求移除；其余问题通过代码修复和回归测试处理。

| 编号 | 修复 | 回归证据 |
|---|---|---|
| F01 | TLS 握手并发执行、限制并发数并设置超时 | `protocol_regressions`：空闲 TLS 连接不阻塞新的 DoH 请求、超时连接关闭 |
| F02 | UDP socket 连接指定 peer，仅接受指定来源 | `protocol_regressions`：伪造来源先响应、合法上游后响应 |
| F03 | 仅对实际执行过的缓存步骤写入，保存该步骤的问题快照 | `cache_regressions`：内外网分流、条件跳过缓存 |
| F04 | 缓存键区分 DO/CD/RD/AD 和 EDNS；命中时重建请求相关字段；带客户端专有 EDNS 选项时绕过缓存 | `cache_regressions`：标志隔离、大小写/ID/EDNS payload、COOKIE |
| F05 | UDP 收到 TC 后在总请求期限内改用 TCP | `protocol_regressions`：真实 UDP 截断后 TCP 完整应答 |
| F06 | 删除 Dockerfile、容器示例和部署文档；最低 Rust 调整至 1.88，CI 验证最低版本与 stable | `Cargo.toml`、CI 矩阵及锁定依赖测试 |
| F07 | 校验响应 QR、ID、opcode 和完整问题元组 | `dnsutil` 单元测试及 `protocol_regressions` 错误问题区实测 |
| F08 | Registry 回引用改为 Weak；监听服务不长期保留首次 Runtime | `cache_regressions` / `config_regressions`：drop、reload 后弱引用失效 |
| F09 | TCP/DoT 每条消息读取当前 Runtime | `protocol_regressions`：同一 TCP、TLS 连接重载前后答案变化 |
| F10 | Bootstrap 并行查询地址族并限定等待时间，保留部分成功 | `protocol_regressions`：A 或 AAAA 丢包、双栈响应先后顺序 |
| F11 | 记录改写链，发出响应前恢复原始问题并添加 CNAME，清除合成别名的 AD | `core_regressions` / `cache_regressions`：原始问题、别名链、目标缓存隔离 |
| F12 | Lazy 刷新从入口前快照恢复问题、marks 和 ECS 状态 | `cache_regressions`：过期刷新不二次改写，恢复初始 marks |
| F13 | Fallback 主备从独立上下文执行，仅合并采用的分支 | `cache_regressions`：失败主路的 mark 不影响备路 |
| F14 | Fallback 与并发 Forward 持有子查询 future，取消和选出赢家时释放其他查询 | `cache_regressions`：取消后分支不继续执行、输家 TCP 连接关闭 |
| F15 | 严格解析 TTL 范围，拒绝反向范围；执行入口也防御非法范围 | `core_regressions`：错误配置被拒绝、有效范围裁剪 |
| F16 | include 使用规范路径检查循环，并限制最大深度 | `config_regressions`：直接循环、符号链接循环、超深 include |
| F17 | 监听器/API 失败向上传递，停止其他监听器，CLI 非零退出 | `config_regressions`：端口占用、兄弟任务释放、进程退出码 |
| F18 | 构建时校验协议、地址、TLS 文件、入口、重复 tag、可执行引用和调用环；CLI 检查可运行端点 | `config_regressions`：无效配置、递归插件、前向引用 |
| F19 | 统一入口的 `$` 处理 | `config_regressions`：真实 UDP 监听及 API 查询 |
| F20 | HTTP/HTTPS DoH 将连接 peer IP 传入 QueryContext | `protocol_regressions`：GET/POST 的 client_ip 匹配及 HTTPS 请求 |
| F21 | ECS 接受 IPv4 的 0–32、IPv6 的 0–128，拒绝非法类型和越界值 | `core_regressions`：/0、最大前缀、非法值 |
| F22 | Hosts 在分词前移除行内注释 | `core_regressions`：别名与反向写法有效，注释不成为主机名 |

附带修复：`log.file` 实际追加写入；API 非法 `client_ip` 返回 400；多重 matcher 否定使用迭代解析以避免递归栈溢出。

## 验证命令

修复后共 89 项测试：36 项单元测试、8 项原有集成测试、45 项新增集成回归；相较检查版本新增 48 项测试。

```sh
cargo test --all --locked
cargo +1.88.0 test --all --locked
cargo build --release --locked
cargo run --quiet --locked -- check -c examples/simple.yaml
cargo run --quiet --locked -- check -c examples/dev.yaml
cargo run --quiet --locked -- check -c examples/split-horizon.yaml
```

网络回归使用回环地址上的受控上游，不依赖公共 DNS。`tests/protocol/` 的证书和私钥是公开的本地测试夹具，不能用于部署。

## 行为变更

- 部署保留本机二进制、无需 root 和 systemd 三种说明。
- 原来被忽略或延迟到请求时失败的非法配置会更早报错。
- SIGHUP 仅替换插件；监听器、入口、API、日志设置以及 TLS 证书更新需要重启。重载失败保留当前配置。
- include 和插件调用链最多 64 层。
- DoH 使用直接 peer IP；反向代理的转发头不参与 client_ip/ECS 判断。

这些测试覆盖本次已确认的问题，不等同于证明整个项目不存在其他缺陷。
