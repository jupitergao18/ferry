## Why

当前 ferry 在网络异常断线时存在多个缺乏超时和恢复机制的薄弱点：Client 握手（含 TCP connect 和 Noise 握手）全程无超时，可能因网络分区或防火墙丢包而永久挂起；Provider 连接上游服务同样无超时，且单个 data_stream 握手失败会直接 `bail!` 导致整根 Provider 控制流重启，波及所有正在转发的连接。这些问题在高并发或不稳定网络环境下会导致服务不可用和用户体验严重劣化。

## What Changes

- 在 `config.json` 最外层新增全局 `timeout` 字段（单位秒，默认 10 秒），统一控制所有网络操作的超时上限
- 为 `protocol::client_handshake` 中的 `TcpStream::connect` 和 `initiator_handshake` 添加 `tokio::time::timeout` 包装
- 为 Client Provider 连接上游 TCP/UDP 服务添加超时，超时或失败时仅对当前请求返回 `Unavailable`，**不再**触发 Provider 控制流整体重启
- Client data_stream（Noise 数据流）握手失败时改为仅返回 `Unavailable`，`handle_server_request` 继续处理后续请求
- Client Service 重试等待（`time::sleep`）期间增加对 stop 信号的响应，避免进程停止时阻塞
- Server 向 Provider 发送 `ConsumeService` 请求时，若 `write_and_flush` 失败立即从 `digest_stream` 中清理该无效 Provider，避免后续请求继续尝试使用失效连接
- 本次变更全程不引入任何新的 `unsafe` 代码

## Capabilities

### New Capabilities

- `global-network-timeout`: 全局网络超时配置，定义 `config.json` 中 `timeout` 字段的语义、默认值及在 TCP connect / Noise 握手 / 上游连接中的使用方式
- `connection-resilience`: 连接韧性机制，定义 Provider 控制流在遇到单实例 data_stream 握手失败或上游连接超时时的行为：仅返回 `Unavailable`，保持控制流存活，不影响其他实例

### Modified Capabilities

<!-- 现有 specs 目录为空，无需要修改的已有能力 -->

## Impact

- `src/config.rs`: 新增 `timeout` 字段及其默认值
- `src/protocol/mod.rs`: `client_handshake` 及所有调用点增加 `timeout_secs` 参数；`proxy_stream`、`initiator_handshake` 调用处加 `timeout` 包装
- `src/client.rs`: Provider 连上游加超时；data_stream 握手失败不 `bail!`；Service retry sleep 响应 stop；所有 `client_handshake` 调用传入 timeout
- `src/server.rs`: `ConsumeService` 处理中 `write_and_flush` 失败立即清理 Provider
- `README.md`: 更新配置示例，说明新增的 `timeout` 字段
