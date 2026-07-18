# BitClone Active Tickets

This file contains active work only. Completed tickets are maintained in [archived_tickets.md](archived_tickets.md).

---

## 🌐 EPIC — Peer-to-Peer Networking

Connect BitClone to the live Bitcoin network so it can discover peers, download the blockchain,
and propagate transactions and blocks in accordance with the Bitcoin P2P protocol.

---

### Sprint 2 — Peer Discovery

**Story 0 — Cleanup and Maintenance**
Use this story for focused refactors, maintenance tasks, and bug fixes discovered while implementing Sprint 2.
Each item should be handled as a separate ticket with sufficient tests.

**Story 2.2 — `addr` / `getaddr` Exchange**
As a node, I want to send `getaddr` to peers and handle incoming `addr` messages
so that my peer address book grows organically over time.

- [ ] Send `getaddr` after handshake
- [ ] Parse `addr` messages and merge into address book
- [ ] Relay `addr` messages to a subset of connected peers

**Story 2.3 — Peer Manager**
As a node, I want a peer manager that maintains a target number of outbound connections
and reconnects on disconnect.

- [ ] Target outbound slot count (8 by default)
- [ ] Reconnect backoff with jitter

---

### Sprint 3 — Block & Transaction Propagation

**Story 0 — Cleanup and Maintenance**
Use this story for focused refactors, maintenance tasks, and bug fixes discovered while implementing Sprint 3.
Each item should be handled as a separate ticket with sufficient tests.

**Story 3.1 — `inv` / `getdata` Round-Trip**
As a node, I want to announce and request inventory items (blocks and transactions)
using `inv` and `getdata` so that I can discover and fetch new data from peers.

- [ ] Send `inv` when a new block or transaction enters the mempool or active chain
- [ ] Handle incoming `inv` and issue `getdata` for unknown items
- [ ] Deduplicate in-flight requests

**Story 3.2 — `tx` Message Handling**
As a node, I want to receive `tx` messages from peers, validate the transaction,
and add it to the mempool so that unconfirmed transactions propagate across the network.

- [ ] Run script validation and fee checks
- [ ] Add to mempool on success; log and ignore on failure

---

### Sprint 4 — Initial Block Download (IBD)

**Story 0 — Cleanup and Maintenance**
Use this story for focused refactors, maintenance tasks, and bug fixes discovered while implementing Sprint 4.
Each item should be handled as a separate ticket with sufficient tests.

**Story 4.1 — `getheaders` / `headers` Sync**
As a node starting from genesis, I want to download all block headers first
so that I can verify proof-of-work on the full chain before downloading block data.

- [ ] Generate block locators for `getheaders` / `getblocks`
- [ ] Send `getheaders` with the known tip locator
- [ ] Implement a header-first chain-sync state machine
- [ ] Validate each header's proof of work and chain linkage
- [ ] Track the best header separately from the best active block
- [ ] Loop until the peer returns fewer than 2,000 headers
- [ ] Add header-sync tests using synthetic chains

**Story 4.2 — Parallel Block Download**
As a node, I want to download full blocks from multiple peers in parallel during IBD
so that I saturate available bandwidth and sync as fast as possible.

- [ ] Assign block ranges to peers
- [ ] Re-request blocks from alternate peers on timeout
- [ ] Apply blocks in order once downloaded out of order
- [ ] Add block-download tests with out-of-order delivery

**Story 4.3 — IBD State & Progress Reporting**
As a node operator, I want to see IBD progress (height, percentage complete, estimated time remaining, blocks/sec)
in the logs so that I know the sync is healthy.

- [ ] Track sync start time and current height
- [ ] Log progress every N blocks or every M seconds
- [ ] Set an `is_in_ibd` flag and suppress mempool relay until caught up

---

### Sprint 5 — Network Hardening & Integration Testing

**Story 0 — Cleanup and Maintenance**
Use this story for focused refactors, maintenance tasks, and bug fixes discovered while implementing Sprint 5.
Each item should be handled as a separate ticket with sufficient tests.

**Story 5.1 — Network Integration Tests**
As a developer, I want automated tests that exercise the full P2P path without hitting the live network.

- [ ] Spin up two in-process nodes in regtest mode, complete a handshake, and propagate a block
- [ ] Add P2P handshake tests using in-process sockets
- [ ] Add an IBD simulation against a local regtest peer

**Story 5.2 — Peer Misbehaviour Scoring**
As a node, I want to assign misbehaviour scores to peers and disconnect or ban those that exceed a threshold
so that the node is resilient to malformed or malicious messages.

- [ ] Define peer misbehaviour scores and a disconnect threshold
- [ ] Maintain a ban list for peers that send invalid data
- [ ] Add malformed-message and ban-expiry tests

**Story 5.3 — `ping` / `pong` Keepalive**
As a node, I want to send periodic `ping` messages and disconnect peers that do not respond with `pong`
within a timeout so that stale connections are cleaned up automatically.

- [ ] Schedule periodic `ping` messages for ready peers
- [ ] Match `pong` nonces to outstanding pings
- [ ] Disconnect peers after the keepalive timeout

---

### Sprint 6 — Consensus & Script Compliance

**Story 0 — Cleanup and Maintenance**
Use this story for focused refactors, maintenance tasks, and bug fixes discovered while implementing Sprint 6.
Each item should be handled as a separate ticket with sufficient tests.

**Story 6.1 — Network-Aware Consensus Rules**

- [ ] Add explicit mainnet, testnet, regtest, and signet chain-parameter objects
- [ ] Add exact historical activation handling for BIP16, BIP34, BIP65, BIP66, SegWit, and Taproot
- [ ] Add BIP30 duplicate-transaction edge-case handling
- [ ] Enforce standard and consensus script flags by network and height

**Story 6.2 — Script Engine Hardening**

- [ ] Remove or replace `ExecutionContext` with clearer validation inputs
- [ ] Improve nested-signature handling for P2SH and related script types
- [ ] Harden sigop counting for P2SH, P2WSH, and tapscript paths

**Story 6.3 — Bitcoin Core Validation Vectors**

- [ ] Add Bitcoin Core vectors for blocks, scripts, and transactions where practical
- [ ] Expand block-validation tests for Merkle roots, proof of work, coinbase rewards, and witness commitments

---

### Sprint 7 — Chain Reorganisation & Storage Integrity

**Story 0 — Cleanup and Maintenance**
Use this story for focused refactors, maintenance tasks, and bug fixes discovered while implementing Sprint 7.
Each item should be handled as a separate ticket with sufficient tests.

**Story 7.1 — Fork Detection and Reorganisation**

- [ ] Track competing chain tips by cumulative work during normal block and header processing
- [ ] Store undo data for every connected block
- [ ] Roll back UTXOs and apply the winning chain during a reorganisation
- [ ] Mark active and inactive block-index entries during a reorganisation
- [ ] Add reorganisation and fork-simulation tests

**Story 7.2 — Atomic Chain Updates and Orphans**

- [ ] Atomically update block files, block index, chain tip, and UTXO set
- [ ] Add an orphan-block pool for blocks whose parents are not known
- [ ] Add a checkpoint map of hard-coded known-good hashes at key heights

**Story 7.3 — Pruning Design**

- [ ] Design optional pruning mode while retaining archival-node mode as the default

---

### Sprint 8 — Mempool Policy & Package Handling

**Story 0 — Cleanup and Maintenance**
Use this story for focused refactors, maintenance tasks, and bug fixes discovered while implementing Sprint 8.
Each item should be handled as a separate ticket with sufficient tests.

**Story 8.1 — Active-Chain Admission and Dependencies**

- [ ] Use the node's active-chain UTXO view for mempool admission
- [ ] Finish dependency-aware block-template transaction selection
- [ ] Enforce ancestor and descendant count and size limits
- [ ] Add an orphan-transaction pool for spends whose parents are not known

**Story 8.2 — Replacement, Eviction, and Relay Policy**

- [ ] Implement Replace-by-Fee rules from BIP125
- [ ] Evict low-fee transactions under memory pressure
- [ ] Maintain a rolling minimum relay fee after eviction
- [ ] Reject non-standard transactions separately from consensus-invalid transactions

**Story 8.3 — Packages and Persistence**

- [ ] Add package-validation and package-relay groundwork
- [ ] Add optional mempool persistence across restarts
- [ ] Add mempool eviction and RBF tests

---

### Sprint 9 — Mining & Regtest Development

**Story 0 — Cleanup and Maintenance**
Use this story for focused refactors, maintenance tasks, and bug fixes discovered while implementing Sprint 9.
Each item should be handled as a separate ticket with sufficient tests.

**Story 9.1 — Consensus-Correct Mining**

- [ ] Fix mining proof-of-work integer byte order to match consensus validation
- [ ] Wire `Miner` fully into the `Node` lifecycle
- [ ] Build block templates from `MemPool.get_block_template()`
- [ ] Add the correct SegWit witness commitment to mined blocks when needed
- [ ] Use chain-derived `bits` and target values instead of node-local default difficulty
- [ ] Stop and rebuild mining work when the chain tip or mempool changes
- [ ] Add tests proving mined blocks pass `Blockchain.add_block()`

**Story 9.2 — Regtest and Development Commands**

- [ ] Add regtest-only easy-mining mode
- [ ] Add CLI commands for `generateblock`, `wipe-chain`, and `loadblock`
- [ ] Support mining blocks on demand in regtest mode

---

### Sprint 10 — Wallet Completion

**Story 0 — Cleanup and Maintenance**
Use this story for focused refactors, maintenance tasks, and bug fixes discovered while implementing Sprint 10.
Each item should be handled as a separate ticket with sufficient tests.

**Story 10.1 — Accounts, Storage, and Scanning**

- [ ] Complete HD-wallet account scanning and gap-limit handling
- [ ] Encrypt key storage on disk
- [ ] Track UTXOs per address and key
- [ ] Add watch-only wallet mode
- [ ] Persist wallet metadata independently from chainstate

**Story 10.2 — Transaction Construction and Signing**

- [ ] Select UTXOs, construct outputs, and compute change
- [ ] Estimate fees using a mempool fee-rate histogram
- [ ] Sign ECDSA P2PKH/P2WPKH and Schnorr P2TR transactions
- [ ] Add wallet signing and UTXO-selection tests

**Story 10.3 — Wallet Runtime Boundary**

- [ ] Separate the wallet runtime from full-node consensus and node orchestration

---

### Sprint 11 — CLI, RPC & API

**Story 0 — Cleanup and Maintenance**
Use this story for focused refactors, maintenance tasks, and bug fixes discovered while implementing Sprint 11.
Each item should be handled as a separate ticket with sufficient tests.

**Story 11.1 — CLI Completion**

- [ ] Add CLI configuration inspection
- [ ] Add peer commands: `addnode`, `disconnect`, and `peers`
- [ ] Add CLI command-integration tests

**Story 11.2 — Local JSON-RPC Server**

- [ ] Implement a local JSON-RPC server compatible with standard Bitcoin RPC where practical
- [ ] Add `getblockchaininfo`
- [ ] Expose `getrawmempool`
- [ ] Add `getrawtransaction` and `decoderawtransaction`
- [ ] Add `sendrawtransaction` with mempool submission and broadcast
- [ ] Add `getutxo` / `gettxout`
- [ ] Expose regtest `generateblock`
- [ ] Add RPC endpoint integration tests

---

### Sprint 12 — Configuration, Operations & Architecture

**Story 0 — Cleanup and Maintenance**
Use this story for focused refactors, maintenance tasks, and bug fixes discovered while implementing Sprint 12.
Each item should be handled as a separate ticket with sufficient tests.

**Story 12.1 — Configuration and Logging**

- [ ] Load configuration for data directories, ports, network selection, and fixed peers
- [ ] Add configurable logging levels and log rotation
- [ ] Add structured progress output for CLI-first operation

**Story 12.2 — Lifecycle and Recovery**

- [ ] Add clean shutdown for database connections, peer connections, miner threads, and background tasks
- [ ] Add startup recovery checks for interrupted block and UTXO writes
- [ ] Add node lifecycle startup and shutdown tests

**Story 12.3 — Runtime Boundaries**

- [ ] Split consensus logic, policy logic, node orchestration, and wallet concerns into clearer module boundaries

---

## 🖥️ Hardware — Home Node + Mining Setup

> Estimated costs in CAD (Ottawa area). Prices are approximate and subject to change.

### Storage — Full Archival Node

The Bitcoin blockchain (with full transaction index) currently sits around **700 GB** and grows
roughly 60–70 GB per year. A 4 TB drive is comfortable today; 8 TB gives you a longer runway
and room for the database, indexes, and OS.

| Item                     | Capacity | Estimated Cost (CAD) |
|--------------------------|----------|----------------------|
| Samsung 870 EVO SATA SSD | 4 TB     | ~$350                |
| Samsung 870 EVO SATA SSD | 8 TB     | ~$650                |
| WD Red SN700 NVMe SSD    | 4 TB     | ~$380                |
| WD Red SN700 NVMe SSD    | 8 TB     | ~$700                |

**Recommendation:** 4 TB NVMe if your machine has an M.2 slot — faster IBD times. 8 TB if you
want to run a full archival node (no pruning) and keep years of growth without thinking about it.

---

### Mining — BitAxe Setup

BitAxe is an open-source solo ASIC miner. At current network difficulty, solo mining is essentially
a lottery — but it's a fun and educational addition to a home node.

| Item                              | Notes                                    | Estimated Cost (CAD) |
|-----------------------------------|------------------------------------------|----------------------|
| BitAxe Gamma 601 (×1)             | ~1.2 TH/s, ~15W, USB-C powered           | ~$120–$150           |
| BitAxe Gamma 601 (×2)             | Two units for ~2.4 TH/s                  | ~$240–$300           |
| USB-C Power Adapter (65W+)        | One per unit, or a USB hub with PD       | ~$25–$40 each        |
| Small 5V Fan (optional)           | Keeps the ASIC chip cool in an enclosure | ~$15                 |
| Enclosure / Rack Mount (optional) | 3D-printable designs available on GitHub | ~$10–$30 materials   |

---

### Full Setup Budget

| Component             | Choice    | Est. Cost (CAD) |
|-----------------------|-----------|-----------------|
| SSD — Storage         | 4 TB NVMe | ~$380           |
| BitAxe Gamma 601      | ×2 units  | ~$280           |
| USB-C PD Adapters     | ×2        | ~$70            |
| Cooling & misc cables | —         | ~$30            |
| **Total**             |           | **~$760**       |

> **Power draw:** Two BitAxes at ~15W each = ~30W continuous. At Ontario's average residential rate
> (~$0.13/kWh), that's roughly **$3–4/month** in electricity. Negligible, and noise is virtually silent
> compared to traditional ASIC rigs.

> **Solo mining odds:** At ~2.4 TH/s against the current network hashrate (~800 EH/s), you'd expect
> to find a block statistically once every few hundred thousand years. You're buying a lottery ticket
> and learning how mining works — not generating income.
