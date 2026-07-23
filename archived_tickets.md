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

### Sprint 4 — IBD Groundwork

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

#### Earlier Groundwork

- [x] Parse `headers` response (up to 2000 headers per message)

### Sprint 7 — Chain Reorganisation & Storage Integrity Groundwork

- [x] Store undo data for every connected block
- [x] Design optional pruning mode while retaining archival-node mode as the default
