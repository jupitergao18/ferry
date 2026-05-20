## Context

ferry 是一个基于 Rust + Tokio 的内网穿透工具，使用 Noise 协议加密通信，支持 TCP/UDP 转发。当前架构包含 Server 端和 Client 端：Client 端通过持久的 Provider 控制流（Noise 安全通道）向 Server 注册服务，Server 在收到 Visitor 请求时通过该控制流通知 Provider 新建 data_stream 进行数据转发。

当前网络超时策略极不完整：Server 端 `server_handshake` 有 5 秒超时，但 Client 端 `client_handshake` 中 `TcpStream::connect` 和 `initiator_handshake` 均无超时，依赖 OS 默认超时（通常 60~120 秒）。Provider 连接上游服务也无超时。更严重的是，单个 data_stream 握手失败时 Client 直接 `bail!`，导致整根 Provider 控制流重启，所有正在转发的连接全部中断。

## Goals / Non-Goals

**Goals:**
- 引入全局统一的可配置网络超时，覆盖 Client TCP 连接、Noise 握手、Provider 上游连接
- 将单实例 data_stream 握手失败与 Provider 控制流生命周期解耦，提升连接韧性
- 修复 Service 重试等待期间无法响应进程停止信号的问题
- 修复 Server 端向已断开的 Provider 写请求时未立即清理的问题

**Non-Goals:**
- 引入指数退避重试策略（本次仅加超时和基础韧性）
- 修改 UDP 多来源地址路由设计（`from` 单例问题）
- 引入 DNS 动态刷新机制
- 修改 Noise 协议本身的加密逻辑
- 增加自动重连的数据流级别重试（Visitor 连接失败后不重试是设计选择）
- 引入任何新的 `unsafe` 代码块（本次修改仅使用 Tokio 提供的安全 API）

## Decisions

### 1. 统一全局超时配置，而非按操作类型区分

在 `config.json` 最外层新增 `timeout` 字段（单位秒，默认 10 秒），用于所有网络操作。

**理由**：配置简单明了，用户无需理解内部不同操作的差异。10 秒作为默认值足以覆盖绝大多数场景的 TCP connect + Noise 握手，同时不会让用户等待过久。

**替代方案**：按操作区分（如 `connect_timeout`、`handshake_timeout`、`upstream_timeout`），但会增加配置复杂度，且用户往往难以合理设置不同值。

### 2. Client `client_handshake` 签名新增 `timeout_secs` 参数

所有调用 `client_handshake` 的地方都需要显式传入超时秒数。

**理由**：`client_handshake` 是网络入口函数，超时属于其契约的一部分，通过参数传递比从全局静态配置读取更明确、更可测试。

### 3. data_stream 握手失败返回 `Unavailable` 而非重启 Provider 控制流

当 `client_handshake` 为新建 data_stream 而失败（或超时）时，`handle_server_request` 对当前 `ConsumeService` 请求回复 `ClientResponse::Unavailable`，然后继续 `loop` 等待下一个请求。

**理由**：
- Provider 控制流是长连接，其生命周期应与单个 Visitor 的数据流解耦
- 一个实例的失败可能是瞬时的（如服务端瞬间高负载），不应波及所有已有连接
- Server 端已支持 `Unavailable` 响应，会正确通知 Consumer 当前无可用的 Provider

**替代方案**：Client 侧对 data_stream 握手进行几次重试后再放弃。但这样会增加 Visitor 的整体等待时间，且无法区分是瞬时抖动还是持续性故障。选择 A（立即返回 Unavailable）让 Server 有机会选择其他 Provider（未来多 Provider 架构时更重要）。

### 4. Provider 连接上游超时也返回 `Unavailable`

当 `TcpStream::connect`（或 UDP socket bind）到上游地址超时或失败时，同样返回 `Unavailable`。

**理由**：与 data_stream 失败保持一致的原则——单实例问题不扩散。

### 5. Server `write_and_flush` 失败立即清理 Provider

向 Provider 发送 `ConsumeService` 请求时，若 `write_and_flush` 返回 `Err`，立即从 `digest_stream` 中 `remove` 该 Provider。

**理由**：`write_and_flush` 失败（如 `BrokenPipe`）几乎确定 Provider 已断开，延迟清理会导致下一个 Consumer 请求再次尝试使用无效连接，增加延迟和日志噪音。

## Risks / Trade-offs

| 风险 | 缓解措施 |
|------|----------|
| 全局统一的 `timeout` 在某些场景下可能过短（如跨国高延迟网络）或过长（如局域网内希望快速失败） | 用户可通过 `config.json` 自行调整；默认值 10 秒覆盖了绝大多数场景 |
| `timeout` 仅包装异步操作，如果操作在同步代码中阻塞（如 DNS 解析在 `TcpStream::connect` 内部），`tokio::time::timeout` 可能无法及时取消 | `connect` 内部 DNS 解析通常也很快；如确有问题，未来可引入 `tokio::net::lookup_host` 前置解析 |
| data_stream 握手失败后返回 `Unavailable`，Visitor 会立即收到连接失败，无透明重试 | 这是设计选择（决策 3）；如果上游服务确实不可用，快速失败比长时间等待更友好 |
| 为实现超时功能而引入底层 unsafe 代码 | 仅使用 `tokio::time::timeout` 等安全高层 API，无需也不引入任何 `unsafe` |
| Server 立即清理 Provider 后，如果该服务没有其他 Provider，后续 Consumer 请求都会快速失败 | 行为正确——没有可用 Provider 时快速失败优于挂起等待 |

## Migration Plan

本次变更向后兼容：
- `config.json` 中的 `timeout` 字段有默认值 `10`，现有配置无需修改即可继续工作
- 所有修改均在 Client/Server 内部行为层面，不影响 wire 协议
- 部署步骤：
  1. 更新 Server 端代码并重启
  2. 更新 Client 端代码并重启
  3. 如需调整超时，在 `config.json` 中添加 `"timeout": <秒数>`

## Open Questions

- 是否需要在日志中区分 "超时失败" 和 "连接被拒绝"，以便运维排查？（本次实现中会保留不同的 warn 日志文本）
