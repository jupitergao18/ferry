## 1. Configuration

- [x] 1.1 Add `timeout` field to `Config` struct in `src/config.rs` with default value 10
- [x] 1.2 Add `timeout` field to `ClientConfig` (or ensure it is passed from `Config` to `Client`)
- [x] 1.3 Update `config.json` and `README.md` to document the new `timeout` field

## 2. Protocol Layer Timeout

- [x] 2.1 Add `timeout_secs: u64` parameter to `client_handshake` in `src/protocol/mod.rs`
- [x] 2.2 Wrap `TcpStream::connect` call inside `client_handshake` with `tokio::time::timeout`
- [x] 2.3 Wrap `initiator_handshake` call inside `client_handshake` with `tokio::time::timeout`
- [x] 2.4 Update `proxy_stream` usage in `client_handshake` to be wrapped with timeout (if connect itself is inside the timeout block)

## 3. Client Provider Control Flow Resilience

- [x] 3.1 In `src/client.rs` `handle_server_request`, wrap upstream `TcpStream::connect` with `tokio::time::timeout`
- [x] 3.2 On upstream connect failure or timeout, send `ClientResponse::Unavailable` and `continue` instead of returning `Err`
- [x] 3.3 Wrap `client_handshake` call for data_stream in `handle_server_request` with `tokio::time::timeout`
- [x] 3.4 On data_stream handshake failure or timeout, send `ClientResponse::Unavailable` and `continue` instead of `bail!`
- [x] 3.5 Ensure UDP upstream connection in `handle_server_request` also follows the same timeout and `Unavailable` pattern

## 4. Client Service Stop Signal Handling

- [x] 4.1 In `src/client.rs` `Client::run`, replace bare `time::sleep(retry_interval).await` with `tokio::select!` that also listens on `service_stop_rx`
- [x] 4.2 Ensure the stop receiver is correctly held across the retry wait (avoid dropping it before select)

## 5. Server Provider Cleanup

- [x] 5.1 In `src/server.rs` `handle_connection` under `ServerRequest::ConsumeService`, if `write_and_flush` to provider fails, immediately `remove` the provider from `digest_stream`
- [x] 5.2 After removing the provider, send `NoProvider` or equivalent response to the consumer so it does not hang

## 6. Call Site Updates

- [x] 6.1 Update all call sites of `client_handshake` in `src/client.rs` to pass the configured `timeout` value
- [x] 6.2 Verify `src/main.rs` does not directly call `client_handshake` (or update if it does)
- [x] 6.3 Run `cargo check` and fix any compilation errors from signature changes

## 7. Verification

- [x] 7.1 Review all modified files to ensure timeout is applied consistently
- [x] 7.2 Confirm no remaining bare `TcpStream::connect` or `client_handshake` calls without timeout in Client code
- [x] 7.3 Verify `cargo build` succeeds
- [x] 7.4 Run `cargo check` or grep to confirm no new `unsafe` blocks were introduced in the diff
