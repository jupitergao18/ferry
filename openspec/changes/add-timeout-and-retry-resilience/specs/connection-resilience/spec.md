## ADDED Requirements

### Requirement: Data stream handshake failure does not restart Provider control flow
The system SHALL ensure that a failure or timeout during data stream establishment for a single `ConsumeService` request does not cause the Provider control flow to restart. The Provider MUST continue processing subsequent requests.

#### Scenario: Data stream handshake fails for one instance
- **WHEN** the Server sends a `ConsumeService` request to the Provider
- **AND** the Provider fails to establish a new data stream to the Server (e.g., handshake error or timeout)
- **THEN** the Provider sends `Unavailable` to the Server for that request
- **AND** the Provider control flow continues its main loop
- **AND** existing data streams for other instances remain active

#### Scenario: Data stream handshake times out for one instance
- **WHEN** the Server sends a `ConsumeService` request to the Provider
- **AND** the data stream handshake exceeds the configured timeout
- **THEN** the Provider sends `Unavailable` to the Server for that request
- **AND** the Provider control flow continues its main loop

### Requirement: Service retry wait responds to stop signal
The system SHALL ensure that a Service waiting to retry after a failure can be interrupted by a stop signal, allowing graceful shutdown.

#### Scenario: Stop signal during retry wait
- **WHEN** a Service encounters an error and enters its retry wait period
- **AND** a stop signal is sent to that Service
- **THEN** the Service exits immediately without completing the full retry wait
- **AND** the Service task terminates cleanly

### Requirement: Server removes invalid Provider on write failure
The system SHALL remove a Provider from the active provider registry immediately when writing a `ConsumeService` request to it fails.

#### Scenario: Write to Provider fails
- **WHEN** the Server attempts to send a `ConsumeService` request to a registered Provider
- **AND** the write operation fails
- **THEN** the Server removes that Provider from `digest_stream` immediately
- **AND** the Server notifies the Consumer that no provider is available

## MODIFIED Requirements

<!-- No existing requirements modified -->
