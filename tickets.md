# BitClone Active Tickets

This file contains active work only. Completed tickets are maintained in [archived_tickets.md](archived_tickets.md).

---

## 🌐 EPIC — Peer-to-Peer Networking

Connect BitClone to the live Bitcoin network so it can discover peers, download the blockchain,
and propagate transactions and blocks in accordance with the Bitcoin P2P protocol.

---

### Sprint 7 — Local Control Plane & Browser Console

This sprint establishes BitClone as downloadable node software operated through a local browser. The daemon owns all
node state; the browser, CLI, and future integrations use the same authenticated service boundary.

**Story 0 — Cleanup and Maintenance**
Use this story for focused refactors, maintenance tasks, and bug fixes discovered while implementing Sprint 7.
Each item should be handled as a separate ticket with sufficient tests.

**Cleanup 7.0.2 — Dataclass Conversion for Data Records**

- [ ] Convert `BlockIndexEntry` to `@dataclass(frozen=True, slots=True)`
- [ ] Convert mutable `MemPoolTx` to `@dataclass(slots=True)` with safe list and arrival-time factories
- [ ] Preserve `MemPoolTx` byte-to-`Tx` normalization through explicit post-initialization
- [ ] Convert `PrefilledTx`, `BlockTxns`, `BlockTxnsRequest`, and `HeaderAndShortIDs` to slotted dataclasses
- [ ] Preserve compact-block validation, differential encoding, constructor signatures, and wire serialization
- [ ] Explicitly select and test equality, representation, mutability, and hashing behavior instead of accepting
      dataclass defaults implicitly
- [ ] Add database-row, mempool-metadata, and compact-block round-trip regression tests

**Story 7.3 — Bitcoin-Compatible JSON-RPC and CLI**

- [ ] Implement a local JSON-RPC server compatible with standard Bitcoin RPC where practical
- [ ] Add `getblockchaininfo`, `getnetworkinfo`, `getpeerinfo`, and `getrawmempool`
- [ ] Add `getrawtransaction`, `decoderawtransaction`, `sendrawtransaction`, and `gettxout`
- [ ] Report unavailable wallet or mining capabilities explicitly until their later sprints are complete
- [ ] Route CLI configuration, peer, chain, and transaction commands through the same application-service layer
- [ ] Add JSON-RPC and CLI integration tests

**Story 7.4 — Browser Operator Console**

- [ ] Serve a same-origin browser application from the BitClone daemon
- [ ] Add dashboard, sync, chain, block, transaction, peer, and mempool views
- [ ] Prominently distinguish independently validated local data from trusted remote Bitcoin Core data
- [ ] Add loading, empty, degraded, offline, and recovery states for long-running node operations
- [ ] Add an allowlisted advanced RPC console with warnings and confirmation for mutating commands
- [ ] Make the console responsive and keyboard accessible
- [ ] Add browser end-to-end tests for the primary operator workflows

---

### Sprint 8 — Chain Reorganisation & Storage Integrity

**Story 0 — Cleanup and Maintenance**
Use this story for focused refactors, maintenance tasks, and bug fixes discovered while implementing Sprint 8.
Each item should be handled as a separate ticket with sufficient tests.

**Story 8.1 — Fork Detection and Reorganisation**

- [ ] Track competing chain tips by cumulative work during normal block and header processing
- [ ] Roll back UTXOs and apply the winning chain during a reorganisation
- [ ] Mark active and inactive block-index entries during a reorganisation
- [ ] Add reorganisation and fork-simulation tests

**Story 8.2 — Atomic Chain Updates and Orphans**

- [ ] Atomically update block files, block index, chain tip, and UTXO set
- [ ] Add an orphan-block pool for blocks whose parents are not known
- [ ] Add a checkpoint map of hard-coded known-good hashes at key heights

### Sprint 9 — Mempool Policy & Package Handling

**Story 0 — Cleanup and Maintenance**
Use this story for focused refactors, maintenance tasks, and bug fixes discovered while implementing Sprint 9.
Each item should be handled as a separate ticket with sufficient tests.

**Story 9.1 — Active-Chain Admission and Dependencies**

- [ ] Use the node's active-chain UTXO view for mempool admission
- [ ] Finish dependency-aware block-template transaction selection
- [ ] Enforce ancestor and descendant count and size limits
- [ ] Add an orphan-transaction pool for spends whose parents are not known

**Story 9.2 — Replacement, Eviction, and Relay Policy**

- [ ] Implement Replace-by-Fee rules from BIP125
- [ ] Evict low-fee transactions under memory pressure
- [ ] Maintain a rolling minimum relay fee after eviction
- [ ] Reject non-standard transactions separately from consensus-invalid transactions

**Story 9.3 — Packages and Persistence**

- [ ] Add package-validation and package-relay groundwork
- [ ] Add optional mempool persistence across restarts
- [ ] Add mempool eviction and RBF tests

---

### Sprint 10 — Mining & Regtest Development

**Story 0 — Cleanup and Maintenance**
Use this story for focused refactors, maintenance tasks, and bug fixes discovered while implementing Sprint 10.
Each item should be handled as a separate ticket with sufficient tests.

**Story 10.1 — Consensus-Correct Mining**

- [ ] Fix mining proof-of-work integer byte order to match consensus validation
- [ ] Wire `Miner` fully into the `Node` lifecycle
- [ ] Build block templates from `MemPool.get_block_template()`
- [ ] Add the correct SegWit witness commitment to mined blocks when needed
- [ ] Use chain-derived `bits` and target values instead of node-local default difficulty
- [ ] Stop and rebuild mining work when the chain tip or mempool changes
- [ ] Add tests proving mined blocks pass `Blockchain.add_block()`

**Story 10.2 — Regtest and Development Commands**

- [ ] Add regtest-only easy-mining mode
- [ ] Add CLI, REST, and RPC commands for `generateblock`, `wipe-chain`, and `loadblock`
- [ ] Support mining blocks on demand in regtest mode

**Story 10.3 — Mining API and Browser Workflows**

- [ ] Expose mining status, block templates, candidate submission, start/stop controls, and found-block results
- [ ] Provide `getblocktemplate` and `submitblock` for external mining software
- [ ] Define a Stratum-compatible solo-mining endpoint or documented bridge for devices such as BitAxe
- [ ] Add browser workflows for regtest generation and mining status
- [ ] Clearly distinguish educational/regtest mining from realistic mainnet ASIC mining

---

### Sprint 11 — Wallet Completion

**Story 0 — Cleanup and Maintenance**
Use this story for focused refactors, maintenance tasks, and bug fixes discovered while implementing Sprint 11.
Each item should be handled as a separate ticket with sufficient tests.

**Story 11.1 — Accounts, Storage, and Scanning**

- [ ] Complete HD-wallet account scanning and gap-limit handling
- [ ] Encrypt key storage on disk
- [ ] Track UTXOs per address and key
- [ ] Add watch-only wallet mode
- [ ] Persist wallet metadata independently from chainstate

**Story 11.2 — Transaction Construction and Signing**

- [ ] Select UTXOs, construct outputs, and compute change
- [ ] Estimate fees using a mempool fee-rate histogram
- [ ] Sign ECDSA P2PKH/P2WPKH and Schnorr P2TR transactions
- [ ] Add wallet signing and UTXO-selection tests

**Story 11.3 — Wallet Runtime, API, and Browser Workflows**

- [ ] Separate the wallet runtime from full-node consensus and node orchestration
- [ ] Expose balances, addresses, UTXOs, transaction creation/signing, history, and rescan controls
- [ ] Add browser workflows for receiving, coin selection, fee review, signing, and broadcasting
- [ ] Require explicit confirmation for signing, broadcasting, key export, and destructive wallet operations
- [ ] Never return seed material or private keys through ordinary API responses
- [ ] Add watch-only and spending-wallet API and browser integration tests

---

### Sprint 12 — Configuration, Operations & Local Packaging

**Story 0 — Cleanup and Maintenance**
Use this story for focused refactors, maintenance tasks, and bug fixes discovered while implementing Sprint 12.
Each item should be handled as a separate ticket with sufficient tests.

**Story 12.1 — Configuration and Logging**

- [ ] Load configuration for data directories, ports, network selection, fixed peers, API binding, and browser launch
- [ ] Add configurable logging levels, log rotation, and structured progress events
- [ ] Expose safe configuration inspection while redacting credentials

**Story 12.2 — Lifecycle and Recovery**

- [ ] Add clean shutdown for database connections, peer connections, miner workers, APIs, and background tasks
- [ ] Add startup recovery checks for interrupted block and UTXO writes
- [ ] Add node lifecycle startup, shutdown, and API reconnection tests

**Story 12.3 — Runtime Boundaries**

- [ ] Split consensus, policy, node orchestration, wallet, transport, and presentation concerns into clear boundaries
- [ ] Ensure HTTP handlers and browser code cannot mutate shared state outside application services

**Story 12.4 — Downloadable Local Application**

- [ ] Package the daemon and version-matched browser assets as one installable distribution
- [ ] Start the local service safely and open the browser console without exposing it publicly
- [ ] Provide sample full-node, pruned-node, and remote-development configurations
- [ ] Add data-directory migrations, upgrade checks, and rollback-safe release procedures
- [ ] Keep a desktop wrapper optional so the browser interface remains the primary client

---

### Sprint 13 — Independent Node Runtime & Release

This is the final local-product integration sprint. Its outcome is a distributable BitClone installation that can
synchronize from the Bitcoin P2P network, operate without Bitcoin Core, remain online after IBD, and expose safe
interfaces for node, wallet, and mining operations.

**Story 0 — Cleanup and Maintenance**
Use this story for focused refactors, maintenance tasks, and bug fixes discovered while implementing Sprint 13.
Each item should be handled as a separate ticket with sufficient tests.

**Story 13.1 — Local Initial Block Download**
As a node operator, I want BitClone to build its own validated chainstate from Bitcoin peers
so that archival and pruned installations can operate independently of Bitcoin Core.

- [ ] Continue from header sync into a bounded parallel block-download scheduler
- [ ] Select, rotate, and penalize download peers when blocks are invalid, unavailable, or stalled
- [ ] Independently validate and atomically connect every downloaded block in chain order
- [ ] Persist IBD checkpoints and resume safely after clean shutdown, interruption, or process failure
- [ ] Support both archival retention and configured pruning throughout IBD
- [ ] Report header, block, chainstate, verification, throughput, and estimated-completion progress through the API
- [ ] Transition automatically from IBD into normal tip-following and relay operation
- [ ] Complete IBD without requiring Bitcoin Core, its RPC service, or its block storage

**Story 13.2 — Concurrent Long-Running Runtime**
As a node operator, I want networking, synchronization, wallet services, mining, and control interfaces to remain
responsive concurrently so that BitClone behaves as a continuously running node.

- [ ] Define one asynchronous node runtime with bounded worker threads or processes for blocking and CPU-heavy work
- [ ] Run peer networking, IBD, block validation, mempool maintenance, wallet scanning, mining coordination, and API
      serving without blocking one another
- [ ] Protect shared chain, mempool, wallet, and mining state with explicit ownership, queues, and synchronization
- [ ] Add cancellation, backpressure, task supervision, and graceful shutdown across all background services
- [ ] Prevent API, mining, and wallet operations from using stale chainstate during tip changes or reorganisations
- [ ] Add concurrency, restart, long-running soak, and controlled-failure tests

**Story 13.3 — Independent-Node Release Qualification**
As a user, I want a documented and tested BitClone distribution
so that I can install it, synchronize it, and keep it operating as a Bitcoin node.

- [ ] Run end-to-end IBD, restart, reorganisation, pruning, API, browser, wallet, relay, and mining scenarios
- [ ] Verify that a synchronized node remains at the network tip and recovers after peers or the API restart
- [ ] Document storage, memory, bandwidth, security, backup, pruning, and upgrade requirements
- [ ] Clearly label experimental features and establish release-readiness criteria for mainnet use
- [ ] Demonstrate a fresh installation synchronizing and operating without any Bitcoin Core dependency

---

### Sprint 14 — Optional Hosted & Fleet Services

This is a post-release commercial layer. It must remain optional: a local BitClone installation continues to work
without an account, subscription, hosted control plane, or custody of wallet keys.

**Story 14.1 — Secure Remote Node Access**

- [ ] Pair a local node with a remote account without exposing the node's RPC port directly to the internet
- [ ] Use end-to-end authenticated channels and revocable, least-privilege device credentials
- [ ] Keep wallet seeds and private keys on the user's node
- [ ] Add remote session, device revocation, and account-recovery security tests

**Story 14.2 — Monitoring and Fleet Management**

- [ ] Add opt-in uptime, sync, storage, peer, and warning telemetry
- [ ] Add alerts, historical health views, and multi-node fleet administration
- [ ] Make every transmitted field visible to the operator and disable telemetry by default

**Story 14.3 — Hosted Developer Environments**

- [ ] Offer isolated, disposable regtest and signet BitClone environments through the same API
- [ ] Add tenant isolation, quotas, usage metering, audit logs, and abuse controls
- [ ] Validate demand before adding billing, hosted mainnet nodes, or managed wallet functionality

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
