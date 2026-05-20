## ADDED Requirements

### Requirement: Global timeout configuration exists
The system SHALL support a global `timeout` field in `config.json` at the root level, measured in seconds, with a default value of 10.

#### Scenario: Config without timeout uses default
- **WHEN** `config.json` does not contain a `timeout` field
- **THEN** the system uses the default timeout of 10 seconds

#### Scenario: Config with custom timeout uses specified value
- **WHEN** `config.json` contains `"timeout": 5`
- **THEN** the system uses a timeout of 5 seconds for all applicable network operations

### Requirement: Client TCP connect respects timeout
The system SHALL enforce the global timeout on all `TcpStream::connect` attempts initiated by the Client, including connections to the Server and connections to upstream services.

#### Scenario: Client connect to server times out
- **WHEN** the Client attempts to connect to the Server address
- **AND** the connection does not complete within the configured timeout
- **THEN** the connect operation fails with a timeout error

#### Scenario: Client connect to upstream times out
- **WHEN** the Client Provider attempts to connect to an upstream TCP address
- **AND** the connection does not complete within the configured timeout
- **THEN** the connect operation fails with a timeout error
- **AND** the Client responds to the Server with `Unavailable`

### Requirement: Noise initiator handshake respects timeout
The system SHALL enforce the global timeout on the Noise protocol initiator handshake performed by the Client.

#### Scenario: Noise initiator handshake times out
- **WHEN** the Client initiates a Noise handshake over an established TCP stream
- **AND** the handshake does not complete within the configured timeout
- **THEN** the handshake fails with a timeout error

### Requirement: Server TCP connect respects timeout
The system SHALL enforce a timeout on TCP connections accepted by the Server during the Noise handshake phase.

#### Scenario: Server handshake with client times out
- **WHEN** the Server accepts a new TCP connection for Noise handshake
- **AND** the handshake does not complete within the existing handshake timeout
- **THEN** the Server closes the connection

## MODIFIED Requirements

<!-- No existing requirements modified -->
