# BitClone Archived Tickets

Completed tickets moved from [tickets.md](tickets.md). Sprint 1 was archived on 2026-07-18.

---

## Completed General Work

### Formatting Tasks

- [x] Each Serializable class will have a table in the docstring containing:
    - [x] variable name
    - [x] data type in python
    - [x] serialized format
    - [x] serialized length

### Implementation Tasks

- [x] Serialized to_dict method
- [x] Have a flag for formatted vs plaintext
- [x] Default will be serialized formatted
- [x] The to_payload and to_dict methods will overlap.
- [x] Needs to be ordered in serialization order
- [x] Modify serializable - have to_dict method to produce the serialized format, and to_data to produce the raw data (for
  display)
- [x] Block Dict
    - [x] Add target as well as bits
- [x] Network
    - [x] Create BitIP class for handling ip addresses
    - [x] Needs to inherit from Serializable.
- [x] Add the CheckLockTimeVerify opcode (redefine NOP2)
- [x] Use the imported formatted class within each file, don't assign these to be file variables, this is unnecessary
  extra work
- [x] Straighten out the is_version bools with NetAddr and Addr and Version Messages
- [x] Add all possible getrand functions to conftest for testing
- [x] Separate scriptpubkey and scriptsig into separate files. Have ScriptType as enum for classification
- [x] Change Transactions to Tx and network related transactions to Txn
- [x] Simplify SignatureEngine - either add abstract methods or just use the functions
- [x] Add ControlBlock validation methods in validate_segwit function in ScriptEngine
- [x] Create a class called `LoadedTx` (or similar) which contains a tx with one or more referenced UTXOs
- [x] Add `close` / `shutdown` methods to `Blockchain`
- [x] Modify `BitCloneDatabase` to use a persistent connection
- [x] Remove runtime artifacts from version control (`__pycache__`, `.pyc`, local sqlite DB files)
- [x] Add `.gitignore` rules for node data directories, block files, sqlite databases, and Python cache files

### Block Validation

- [x] Verify Merkle root against block header
- [x] Enforce proof-of-work target (`bits` → `target` comparison)
- [x] Validate coinbase reward amount per height (halving schedule)
- [x] Enforce block size and weight limits
- [x] Check for duplicate txids within a block
- [x] Median Time Past (MTP) enforcement for block timestamps
- [x] Validate `nLockTime` and `nSequence` fields on transactions
- [x] Validate expected compact target bits at each height
- [x] Validate SegWit witness commitment in coinbase transaction
- [x] Validate coinbase script size and BIP34 height commitment
- [x] Reject duplicate spends within a block
- [x] Support intra-block UTXO dependencies
- [x] Enforce coinbase maturity for spent coinbase outputs

### Chain Management

- [x] Persist block-index entries with cumulative chainwork
- [x] Detect when an indexed side-chain tip has more cumulative work than the active tip

### Mempool

- [x] In-memory pool of validated, unconfirmed transactions
- [x] Basic fee-rate (sat/vbyte) calculation
- [x] Basic ancestor / descendant tracking for CPFP (Child Pays For Parent)
- [x] Reject duplicate mempool txids and simple mempool double spends
- [x] Evict stale transactions by age
- [x] Basic fee-rate ordering and block-template transaction selection

### Mining / Block Template

- [x] Basic proof-of-work mining loop with stop signal and hashrate stats
- [x] Basic coinbase transaction construction with BIP34-style height push

### Wallet

- [x] BIP32 extended key derivation primitives
- [x] BIP39 mnemonic-to-seed wallet creation
- [x] Derivation path helpers for BIP44 / BIP49 / BIP84 / BIP86 addresses
- [x] Initial transaction builder skeleton

### CLI / RPC / API Layer

- [x] CLI entrypoint (`python -m src`)
- [x] CLI config command: initialize data dir
- [x] CLI global `--data-dir` and `--network` options
- [x] CLI `status` command
- [x] CLI `getblock` command
- [x] CLI `gettxout` command
- [x] CLI `getblockheader` command
- [x] CLI `getchaintip` command
- [x] CLI `sendrawtransaction` command
- [x] CLI `getrawmempool` command
- [x] CLI `decoderawtransaction` command
- [x] CLI `build-template` dev command

### Configuration & Operations

- [x] Basic startup and shutdown sequence wiring for Node, Blockchain, MemPool, and Miner
- [x] Node entrypoint (`python -m src`) that wires Blockchain and Mempool through Node
- [x] Fix `Node` runtime wiring so Blockchain, MemPool, wallet, mining, and networking share consistent APIs
- [x] Make Blockchain and MemPool use the same chainstate/UTXO database path
- [x] Add data directory layout for blocks, chainstate, peers, wallet, logs, and config

### Testing

- [x] Block validation unit tests for several consensus checks
- [x] Basic mempool tests

---

## Sprint 1 — Connection & Handshake

**Status: Complete**

### Story 0 — Cleanup and Maintenance
As a developer, I want to address focused refactors, maintenance, and bug fixes discovered during Sprint 1
so that the networking foundation remains consistent as new capabilities are added.

- [x] Remove module-level aliases of format constants such as `DEFAULT_MAGIC = MAGICBYTES.MAINNET`; use the format
  class attributes directly
- [x] Remove the local `ALLOWED_MAGIC` list and stale alias comments from `network/messages/header.py`
- [x] Define shared P2P envelope sizes in `NETWORK` (`MAGIC_LENGTH`, `PAYLOAD_SIZE_LENGTH`, `CHECKSUM_LENGTH`, and
  `HEADER_LENGTH`) and replace duplicated literals in header, message, and transport code
- [x] Use the existing `NETWORK.COMMAND_LENGTH` throughout message-header serialization and validation
- [x] Reconcile supported Bitcoin network magic values: support mainnet, testnet, regtest, and signet; remove Namecoin
  from Bitcoin transport validation
- [x] Centralize protocol-wide limits such as inventory entries, `getblocks` results, `headers` results, and maximum
  payload size in `NETWORK`
- [x] Replace duplicated network wire-field sizes in control messages, data messages, compact-filter messages, and
  network datatypes with shared format constants where doing so improves clarity
- [x] Replace hard-coded values where a matching format constant already exists, such as using `TX.TXID` instead of
  the literal `32` for transaction IDs
- [x] Remove remaining module-level format aliases outside networking, such as `BYTE_LEN = ECC.COORD_BYTES` in
  `cryptography/schnorr.py`
- [x] Add a Bitcoin Core P2P command-coverage audit without using the upstream command list as a framing allowlist
    - [x] Add a public `Message.registered_commands()` method returning an immutable set of imported/registered commands
    - [x] Maintain a reviewed snapshot of Bitcoin Core's `ALL_NET_MESSAGE_TYPES`, including the upstream version or
      commit used to produce it
    - [x] Report commands implemented by BitClone, known upstream but not implemented, and implemented locally but
      absent or deprecated upstream
    - [x] For the Bitcoin Core v31.0 target, report `addrv2` and `sendtxrcncl` as unimplemented and `reject` as a
      deprecated command still implemented by BitClone; track post-v31.0 `feature` separately
    - [x] Add tests that detect command-coverage drift while continuing to deserialize valid unsupported commands as
      `UnknownMessage`
    - [x] Review the snapshot whenever BitClone changes its target Bitcoin Core version
- [x] Add or update focused tests for every cleanup or bug-fix ticket

### Story 1.1 — TCP Peer Connection
As a node, I want to open and accept TCP connections on port 8333 (mainnet)
so that I can communicate with Bitcoin peers.

- [x] Synchronous outbound TCP connection helper
- [x] Connection state tracking for basic outbound connections
- [x] Async TCP listener (asyncio)
- [x] Outbound connection to an explicitly supplied fixed peer using the selected network's default P2P port
- [x] Connection state tracking (CONNECTING → CONNECTED → READY)

### Story 1.2 — Version Handshake
As a node, I want to complete the `version` / `verack` handshake with a peer
so that both sides agree on protocol version and capabilities before exchanging data.

- [x] `version` and `verack` message serialization/deserialization
- [x] Send `version` message on connect
- [x] Receive and validate peer `version`
- [x] Send and receive `verack`
- [x] Reject peers below minimum protocol version (70001)

### Story 1.3 — Message Framing
As a node, I want to parse and serialise the Bitcoin P2P message envelope
(magic bytes, command, length, checksum) so that all message types share a common wire format.

- [x] Message header/envelope serialization with `to_bytes` / `from_bytes`
- [x] Checksum validation (double-SHA256)
- [x] Network magic constants and allowed magic validation
- [x] Strict per-network magic selection instead of accepting all known magic values
- [x] Unknown-command handling and peer misbehavior response
- [x] Maximum payload size enforcement

---

## Completed Groundwork for Upcoming Sprints

### Sprint 2 — Peer Discovery

#### Story 0 — Cleanup and Maintenance

- [x] Support address-family-neutral IPv4 and IPv6 outbound connections
- [x] Make network message encoding and decoding single-pass
- [x] Query independent DNS seeds concurrently with bounded parallelism
- [x] Centralize peer session state and address-book connection bookkeeping
- [x] Consolidate magic bytes, ports, and DNS seeds into immutable network profiles
- [x] Remove duplicated `Addr` display construction and use a natural address-list representation
- [x] Keep node block storage beside an explicit database path unless a data directory is also configured

#### Story 2.1 — DNS Seed Bootstrap
As a node, I want to resolve Bitcoin DNS seeds on first startup
so that I can find an initial set of peers without any configuration.

- [x] Store resolved IPs in a peer address book
- [x] Query hardcoded DNS seeds (`seed.bitcoin.sipa.be`, etc.)

#### Story 2.2 — `addr` / `getaddr` Exchange
As a node, I want to send `getaddr` to peers and handle incoming `addr` messages
so that my peer address book grows organically over time.

- [x] Send `getaddr` after handshake
- [x] Parse `addr` messages and merge into address book
- [x] Relay `addr` messages to a subset of connected peers

#### Story 2.3 — Peer Manager
As a node, I want a peer manager that maintains a target number of outbound connections
and reconnects on disconnect.

- [x] Target outbound slot count (8 by default)
- [x] Reconnect backoff with jitter

### Sprint 3 — Block & Transaction Propagation

#### Story 0 — Cleanup and Maintenance

- [x] Make P2WPKH script-template matching safely reject short redeem scripts instead of raising during P2SH validation

#### Story 3.1 — `inv` / `getdata` Round-Trip
As a node, I want to announce and request inventory items (blocks and transactions)
using `inv` and `getdata` so that I can discover and fetch new data from peers.

- [x] Send `inv` when a new block or transaction enters the mempool or active chain
- [x] Handle incoming `inv` and issue `getdata` for unknown items
- [x] Deduplicate in-flight requests

#### Story 3.2 — `tx` Message Handling
As a node, I want to receive `tx` messages from peers, validate the transaction,
and add it to the mempool so that unconfirmed transactions propagate across the network.

- [x] Run script validation and fee checks
- [x] Add to mempool on success; log and ignore on failure
- [x] Relay accepted transaction inventory to other ready peers without echoing it to the source

#### Propagation Groundwork

- [x] `inv`, `getdata`, `notfound`, block, and tx message serialization/deserialization
- [x] Deserialise `tx` message into `Tx` object
- [x] Deserialise `block` message
- [x] Run append-only block validation (PoW, Merkle, scripts, coinbase)
- [x] Update UTXO set and chain height on successful append-only active-chain block

### Sprint 4 — Blockchain Data Access (No Local IBD)

**Status: Complete**

#### Story 0 — Cleanup and Maintenance

- [x] Make the preferred upstream Bitcoin Core P2P endpoint configurable without hard-coding its changing LAN address
- [x] Define a block-storage interface with archival and pruned/streaming implementations before bulk block download
- [x] Retain the undo data and recent block window required for safe reorganisations in pruned mode

#### Story 4.1 — `getheaders` / `headers` Sync
As a node starting from genesis, I want to download all block headers first
so that I can verify proof-of-work on the full chain before downloading block data.

- [x] Generate block locators for `getheaders` / `getblocks`
- [x] Send `getheaders` with the known tip locator
- [x] Implement a header-first chain-sync state machine
- [x] Validate each header's proof of work and chain linkage
- [x] Track the best header separately from the best active block
- [x] Loop until the peer returns fewer than 2,000 headers
- [x] Add header-sync tests using synthetic chains

#### Story 4.2 — Bitcoin Core Remote Block Store
As a storage-constrained development node, I want to read blockchain data from an existing Bitcoin Core node
so that BitClone can inspect blocks without conducting IBD or duplicating the block archive.

- [x] Add authenticated Bitcoin Core JSON-RPC configuration without persisting passwords
- [x] Fetch chain status, raw headers, and raw blocks by hash or height
- [x] Keep remote block bodies out of local block files
- [x] Preserve archival and pruned modes for future independent-node operation
- [x] Add mocked RPC and remote-store tests plus a bounded optional live check

#### Story 4.3 — Remote Source Health & Trust Reporting
As a node operator, I want BitClone to report the state and trust boundary of its Bitcoin Core source
so that remote-backed development is explicit and failures are easy to diagnose.

- [x] Show remote reachability, chain, tip height/hash, verification progress, and pruning state in node status
- [x] Reject a remote source whose Bitcoin network does not match BitClone's selected network
- [x] Clearly distinguish trusted remote data from independently validated local chainstate
- [x] Delegate remote-mode UTXO queries to Bitcoin Core instead of presenting the incomplete local UTXO set
- [x] Load remote-storage settings from `bitclone.toml` so flags do not need to be repeated

#### Earlier Groundwork

- [x] Parse `headers` response (up to 2000 headers per message)

### Sprint 5 — Network Hardening & Integration Testing

**Status: Complete**

#### Story 5.1 — Network Integration Tests
As a developer, I want automated tests that exercise the full P2P path without hitting the live network.

- [x] Spin up two in-process nodes in regtest mode, complete a handshake, and propagate a block
- [x] Add P2P handshake tests using in-process sockets
- [x] Add an IBD simulation against a local regtest peer

#### Story 5.2 — Peer Misbehaviour Scoring
As a node, I want to assign misbehaviour scores to peers and disconnect or ban those that exceed a threshold
so that the node is resilient to malformed or malicious messages.

- [x] Define peer misbehaviour scores and a disconnect threshold
- [x] Maintain a ban list for peers that send invalid data
- [x] Add malformed-message and ban-expiry tests

#### Story 5.3 — `ping` / `pong` Keepalive
As a node, I want to send periodic `ping` messages and disconnect peers that do not respond with `pong`
within a timeout so that stale connections are cleaned up automatically.

- [x] Schedule periodic `ping` messages for ready peers
- [x] Match `pong` nonces to outstanding pings
- [x] Disconnect peers after the keepalive timeout

### Sprint 6 — Consensus & Script Compliance

**Status: Complete**

#### Story 6.1 — Network-Aware Consensus Rules

- [x] Add explicit mainnet, testnet, regtest, and signet chain-parameter objects
- [x] Add exact historical activation handling for BIP16, BIP34, BIP65, BIP66, SegWit, and Taproot
- [x] Add BIP30 duplicate-transaction edge-case handling
- [x] Enforce standard and consensus script flags by network and height

#### Story 6.2 — Script Engine Hardening

- [x] Replace consensus use of `ExecutionContext` with required, typed script-validation inputs
- [x] Improve nested-signature handling for P2SH, P2WPKH, and P2WSH paths
- [x] Harden sigop accounting for P2SH and P2WSH and enforce tapscript's validation-weight budget

#### Story 6.3 — Bitcoin Core Validation Vectors

- [x] Add Bitcoin Core vectors for blocks, scripts, and transactions where practical
- [x] Expand block-validation tests for Merkle roots, proof of work, coinbase rewards, and witness commitments

### Sprint 7 — Local Control Plane & Browser Console

**Status: Complete**

#### Story 7.1 — Versioned Service API
As a node operator, I want a stable local API so that the browser interface and automation tools can control a running
BitClone process without reaching directly into consensus, wallet, or networking internals.

- [x] Add an application-service layer between transports and node internals
- [x] Serve a versioned REST API under `/api/v1`
- [x] Add health, version, capability, node-status, sync, trust-source, chain, peer, and mempool endpoints
- [x] Define consistent errors, pagination, timestamps, amount units, and API-version compatibility rules
- [x] Publish an OpenAPI document generated from the implementation route registry
- [x] Add endpoint integration and contract tests

#### Story 7.2 — Live Events and Local-First Security

- [x] Stream sync, peer, block, mempool, warning, and lifecycle events using SSE
- [x] Bind HTTP and future RPC services to loopback by default
- [x] Add scoped bearer credentials, CSRF protection, and strict origin rules
- [x] Require explicit configuration, allowed origins, and TLS for access beyond loopback
- [x] Redact cookies, private keys, wallet secrets, and credentials from responses, events, and audit logs
- [x] Add rate limits, sensitive-action audit groundwork, and security-focused integration tests

#### Cleanup 7.0.1 — Quiet Peer Diagnostics and Shutdown Summary

- [x] Add `last_known_message` to each `PeerAddress` and include it in `PeerAddressBook.to_data()`
- [x] Update the message on connection success, connection failure, protocol failure, and disconnect
- [x] Treat expected per-peer connection churn as debug information instead of emitting a warning for every failed peer
- [x] Preserve warnings for systemic conditions such as DNS bootstrap failure, worker failure, or inability to maintain
      any outbound peers
- [x] Expose one structured JSON snapshot through the authenticated `/api/v1/peers/address-book` endpoint
- [x] Add tests for message updates, reduced warning output, redaction-safe JSON, and the address-book endpoint

#### Story 7.3 — Bitcoin-Compatible JSON-RPC and CLI

- [x] Implement a local JSON-RPC server compatible with standard Bitcoin RPC where practical
- [x] Add `getblockchaininfo`, `getnetworkinfo`, `getpeerinfo`, and `getrawmempool`
- [x] Add `getrawtransaction`, `decoderawtransaction`, `sendrawtransaction`, and `gettxout`
- [x] Report unavailable wallet or mining capabilities explicitly until their later sprints are complete
- [x] Route CLI configuration, peer, chain, and transaction commands through the same application-service layer
- [x] Add JSON-RPC and CLI integration tests

#### Story 7.4 — Browser Operator Console

- [x] Serve a same-origin browser application from the BitClone daemon
- [x] Add dashboard, sync, chain, block, transaction, peer, and mempool views
- [x] Prominently distinguish independently validated local data from trusted remote Bitcoin Core data
- [x] Add loading, empty, degraded, offline, and recovery states for long-running node operations
- [x] Add an allowlisted advanced RPC console with warnings and confirmation for mutating commands
- [x] Make the console responsive and keyboard accessible
- [x] Add browser end-to-end tests for the primary operator workflows

#### Cleanup 7.0.2 — Dataclass Conversion for Data Records

- [x] Convert `BlockIndexEntry` to `@dataclass(frozen=True, slots=True)`
- [x] Convert mutable `MemPoolTx` to `@dataclass(slots=True)` with safe list and arrival-time factories
- [x] Preserve `MemPoolTx` byte-to-`Tx` normalization through explicit post-initialization
- [x] Convert `PrefilledTx`, `BlockTxns`, `BlockTxnsRequest`, and `HeaderAndShortIDs` to slotted dataclasses
- [x] Preserve compact-block validation, differential encoding, constructor signatures, and wire serialization
- [x] Explicitly select and test equality, representation, mutability, and hashing behavior instead of accepting
      dataclass defaults implicitly
- [x] Add database-row, mempool-metadata, and compact-block round-trip regression tests

### Sprint 8 — Chain Reorganisation & Storage Integrity

**Status: Complete**

#### Cleanup 8.0.1 — Storage-Aware Mempool View

- [x] Read verbose Bitcoin Core mempool data when block storage is `bitcoin-core-remote`
- [x] Preserve BitClone's independently validated local mempool for archival and pruned modes
- [x] Expose the mempool source and trust model through REST and JSON-RPC
- [x] Display the correct mempool count, source label, empty state, and degraded state in the browser console
- [x] Add RPC-client, service, remote-mode, and browser-console regression tests

#### Story 8.1 — Fork Detection and Reorganisation

- [x] Track competing chain tips by cumulative work during normal block and header processing
- [x] Roll back UTXOs and apply the winning chain during a reorganisation
- [x] Mark active and inactive block-index entries during a reorganisation
- [x] Add reorganisation and fork-simulation tests

#### Story 8.2 — Atomic Chain Updates and Orphans

- [x] Atomically update block files, block index, chain tip, and UTXO set
- [x] Add an orphan-block pool for blocks whose parents are not known
- [x] Add a checkpoint map of hard-coded known-good hashes at key heights

### Chain Reorganisation & Storage Integrity — Early Groundwork

Completed ahead of the active Chain Reorganisation & Storage Integrity sprint.

- [x] Store undo data for every connected block
- [x] Design optional pruning mode while retaining archival-node mode as the default

### Sprint 9 — Mempool Policy & Package Handling

#### Story 9.1 — Active-Chain Admission and Dependencies

- [x] Use the node's active-chain UTXO view for mempool admission
- [x] Finish dependency-aware block-template transaction selection
- [x] Enforce ancestor and descendant count and size limits
- [x] Add an orphan-transaction pool for spends whose parents are not known

#### Story 9.2 — Replacement, Eviction, and Relay Policy

- [x] Implement Replace-by-Fee rules from BIP125
- [x] Evict low-fee transactions under memory pressure
- [x] Maintain a rolling minimum relay fee after eviction
- [x] Reject non-standard transactions separately from consensus-invalid transactions
