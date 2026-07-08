# BitClone ToDo List

---

## Formatting Tasks

- ~~Each Serializable class will have a table in the docstring containing:~~
    - ~~variable name~~
    - ~~data type in python~~
    - ~~serialized format~~
    - ~~serialized length~~

---

## Implementation Tasks

~~Serialized to_dict method~~

- ~~Have a flag for formatted vs plaintext~~
- ~~Default will be serialized formatted~~
- ~~The to_payload and to_dict methods will overlap.~~
- ~~Needs to be ordered in serialization order~~
- ~~Modify serializable - have to_dict method to produce the serialized format, and to_data to produce the raw data (for
  display)~~
- ~~Block Dict~~
    - ~~Add target as well as bits~~
- ~~Network~~
    - ~~Create BitIP class for handling ip addresses~~
    - ~~Needs to inherit from Serializable.~~
- ~~Add the CheckLockTimeVerify opcode (redefine NOP2)~~
- ~~Use the imported formatted class within each file, don't assign these to be file variables, this is unnecessary
  extra work~~
- ~~Straighten out the is_version bools with NetAddr and Addr and Version Messages~~
- ~~Add all possible getrand functions to conftest for testing~~
- ~~Separate scriptpubkey and scriptsig into separate files. Have ScriptType as enum for classification~~
- ~~Change Transactions to Tx and network related transactions to Txn~~
- ~~Simplify SignatureEngine - either add abstract methods or just use the functions~~
- ~~Add ControlBlock validation methods in validate_segwit function in ScriptEngine~~
- [ ] Get rid of Execution context
- [x] ~~Create a class called `LoadedTx` (or similar) which contains a tx with one or more referenced UTXOs~~
- [ ] Add `close` / `shutdown` methods to `Blockchain`
- [x] Modify `BitCloneDatabase` to use a persistent connection
- [ ] Improve P2SH and other script methods using signatures within signatures, or other script types for
  locking/unlocking
- [ ] Remove runtime artifacts from version control (`__pycache__`, `.pyc`, local sqlite DB files)
- [ ] Add `.gitignore` rules for node data directories, block files, sqlite databases, and Python cache files
- [ ] Split consensus logic, policy logic, node orchestration, and wallet concerns into clearer module boundaries

---

## Block Validation

- [x] ~~Verify Merkle root against block header~~
- [x] ~~Enforce proof-of-work target (`bits` → `target` comparison)~~
- [x] ~~Validate coinbase reward amount per height (halving schedule)~~
- [x] ~~Enforce block size / weight limits~~
- [x] ~~Check for duplicate txids within a block~~
- [x] ~~Median Time Past (MTP) enforcement for block timestamps~~
- [x] ~~Validate `nLockTime` and `nSequence` fields on transactions~~
- [x] ~~Validate expected compact target bits at each height~~
- [x] ~~Validate SegWit witness commitment in coinbase transaction~~
- [x] ~~Validate coinbase script size and BIP34 height commitment~~
- [x] ~~Reject duplicate spends within a block~~
- [x] ~~Support intra-block UTXO dependencies during validation~~
- [x] ~~Enforce coinbase maturity for spent coinbase outputs~~
- [ ] Add exact historical consensus activation handling (BIP16, BIP34, BIP65, BIP66, SegWit, Taproot)
- [ ] Add BIP30 duplicate transaction edge-case handling
- [ ] Harden sigop counting for P2SH, P2WSH, and tapscript paths
- [ ] Enforce standard and consensus script flags by network/height
- [ ] Add test vectors from Bitcoin Core where practical for blocks, scripts, and transactions
- [ ] Add explicit mainnet/testnet/regtest chain parameter objects

---

## Chain Management

- [x] ~~Persist block index entries with cumulative chainwork~~
- [x] ~~Detect when an indexed side-chain tip has more cumulative work than the active tip~~
- [ ] Fork detection — track competing chain tips by cumulative work during normal block/header processing
- [ ] Reorganisation (reorg) logic — rollback UTXOs and re-apply the winning chain
- [ ] Store undo data for every connected block so UTXO changes can be reversed
- [ ] Mark active/inactive block index entries during reorg
- [ ] Atomically update block files, block index, chain tip, and UTXO set
- [ ] Orphan block pool — hold blocks whose parent is not yet known
- [ ] Header-first chain sync state machine
- [ ] Block locator generation for `getheaders` / `getblocks`
- [ ] Best-header tracking separate from best-active-block tracking
- [ ] Checkpoint map — hard-coded known-good hashes at key heights
- [ ] Pruning mode design (optional later; archival node first)

---

## Mempool

- [x] ~~In-memory pool of validated, unconfirmed transactions~~
- [x] ~~Basic fee-rate (sat/vbyte) calculation~~
- [x] ~~Basic ancestor / descendant tracking for CPFP (Child Pays For Parent)~~
- [x] ~~Reject duplicate mempool txids and simple mempool double spends~~
- [x] ~~Evict stale transactions by age~~
- [ ] Use the node's active-chain UTXO database instead of a separate test DB
- [ ] Enable full script validation for mempool admission
- [ ] Finish fee-rate ordering and block-template transaction selection
- [ ] Enforce ancestor/descendant count and size limits
- [ ] Add orphan transaction pool for spends whose parents are not known yet
- [ ] Replace-by-Fee (RBF) logic — BIP 125
- [ ] Eviction policy for low-fee transactions under memory pressure
- [ ] Rolling minimum relay fee after eviction
- [ ] Package validation and package relay groundwork
- [ ] Reject non-standard transactions separately from consensus-invalid transactions
- [ ] Mempool persistence across restarts (optional dump/load)

---

## Mining / Block Template

- [x] ~~Basic proof-of-work mining loop with stop signal and hashrate stats~~
- [x] ~~Basic coinbase transaction construction with BIP34-style height push~~
- [ ] Fix mining proof-of-work integer byte order to match consensus validation
- [ ] Wire `Miner` into `Node` lifecycle and CLI commands
- [ ] Build block templates from `MemPool.get_block_template()`
- [ ] Add correct SegWit witness commitment to mined blocks when needed
- [ ] Use chain-derived `bits` / target instead of a node-local default difficulty field
- [ ] Stop and rebuild mining work when the chain tip or mempool changes
- [ ] Add regtest-only easy-mining mode for development
- [ ] Add tests that mined blocks pass `Blockchain.add_block()`

---

## Wallet

- [x] ~~BIP32 extended key derivation primitives~~
- [x] ~~BIP39 mnemonic-to-seed wallet creation~~
- [x] ~~Derivation path helpers for BIP44 / BIP49 / BIP84 / BIP86 addresses~~
- [ ] Complete HD wallet account scanning and gap-limit handling
- [ ] Key storage (encrypted on disk)
- [ ] UTXO tracking per address/key
- [x] ~~Initial transaction builder skeleton~~
- [ ] Complete transaction builder — select UTXOs, construct outputs, compute change
- [ ] Fee estimation using mempool fee-rate histogram
- [ ] Sign transactions (ECDSA P2PKH/P2WPKH, Schnorr P2TR)
- [ ] Watch-only wallet mode
- [ ] Separate wallet runtime from full-node consensus/runtime code
- [ ] Persist wallet metadata independently from chainstate

---

## CLI / RPC / API Layer

- [ ] CLI entrypoint (`main.py`, `python -m src`, or console script)
- [ ] CLI config commands: initialize data dir, select network, inspect config
- [ ] CLI chain commands: `status`, `getblock`, `getblockheader`, `gettxout`, `getchaintip`
- [ ] CLI mempool commands: `sendrawtransaction`, `getrawmempool`, `decoderawtransaction`
- [ ] CLI peer commands: `addnode`, `disconnect`, `peers`
- [ ] CLI regtest/dev commands: `generateblock`, `wipe-chain`, `loadblock`
- [ ] Local JSON-RPC server (standard Bitcoin RPC interface where possible)
- [ ] `getblockchaininfo` — height, tip hash, IBD status
- [ ] `getrawmempool` — list unconfirmed txids
- [ ] `getrawtransaction` / `decoderawtransaction`
- [ ] `sendrawtransaction` — submit a signed tx to mempool + broadcast
- [ ] `getutxo` / `gettxout`
- [ ] `generateblock` (regtest mode only)

---

## Configuration & Operations

- [ ] Config file loading — data directory, ports, network (mainnet / testnet / regtest), peers
- [ ] Regtest mode — mine blocks on demand for local testing
- [ ] Logging levels (DEBUG / INFO / WARNING) and log rotation
- [ ] Graceful startup and shutdown sequence wiring all components together
- [ ] Node entrypoint (`main.py` or CLI) that wires Blockchain, Mempool, Network, RPC together
- [ ] Fix `Node` runtime wiring so Blockchain, MemPool, wallet, mining, and networking share consistent APIs
- [ ] Make Blockchain and MemPool use the same chainstate/UTXO database
- [ ] Add clean shutdown for database connections, peer connections, miner threads, and background tasks
- [ ] Add data directory layout for blocks, chainstate, peers, wallet, logs, and config
- [ ] Add startup recovery checks for interrupted block/UTXO writes
- [ ] Add structured progress output for CLI-first operation

---

## Testing

- [x] ~~Block validation unit tests for several consensus checks~~
- [ ] Expand block validation unit tests with Bitcoin Core vectors (Merkle, PoW, coinbase reward, witness commitment)
- [ ] Reorg and fork simulation tests
- [x] ~~Basic mempool tests~~
- [ ] Mempool eviction and RBF tests
- [ ] Wallet signing and UTXO selection tests
- [ ] RPC endpoint integration tests
- [ ] IBD simulation against a local regtest peer
- [ ] CLI command integration tests
- [ ] Node lifecycle startup/shutdown tests
- [ ] P2P handshake tests using in-process sockets
- [ ] Header sync tests with synthetic chains
- [ ] Block download tests with out-of-order delivery

---

## 🌐 EPIC — Peer-to-Peer Networking

Connect BitClone to the live Bitcoin network so it can discover peers, download the blockchain,
and propagate transactions and blocks in accordance with the Bitcoin P2P protocol.

---

### Sprint 1 — Connection & Handshake

**Story 1.1 — TCP Peer Connection**
As a node, I want to open and accept TCP connections on port 8333 (mainnet)
so that I can communicate with Bitcoin peers.

- [x] ~~Synchronous outbound TCP connection helper~~
- [x] ~~Connection state tracking for basic outbound connections~~
- Async TCP listener (asyncio)
- Outbound connection to a hardcoded seed peer
- Connection state tracking (CONNECTING → CONNECTED → READY)

**Story 1.2 — Version Handshake**
As a node, I want to complete the `version` / `verack` handshake with a peer
so that both sides agree on protocol version and capabilities before exchanging data.

- [x] ~~`version` and `verack` message serialization/deserialization~~
- Send `version` message on connect
- Receive and validate peer `version`
- Send and receive `verack`
- Reject peers below minimum protocol version (70001)

**Story 1.3 — Message Framing**
As a node, I want to parse and serialise the Bitcoin P2P message envelope
(magic bytes, command, length, checksum) so that all message types share a common wire format.

- [x] ~~Message header/envelope serialization with `to_bytes` / `from_bytes`~~
- [x] ~~Checksum validation (double-SHA256)~~
- [x] ~~Network magic constants and allowed magic validation~~
- [ ] Strict per-network magic selection instead of accepting all known magic values
- [ ] Unknown-command handling and peer misbehavior response
- [ ] Maximum payload size enforcement

---

### Sprint 2 — Peer Discovery

**Story 2.1 — DNS Seed Bootstrap**
As a node, I want to resolve Bitcoin DNS seeds on first startup
so that I can find an initial set of peers without any configuration.

- Query hardcoded DNS seeds (`seed.bitcoin.sipa.be`, etc.)
- Store resolved IPs in a peer address book

**Story 2.2 — `addr` / `getaddr` Exchange**
As a node, I want to send `getaddr` to peers and handle incoming `addr` messages
so that my peer address book grows organically over time.

- Send `getaddr` after handshake
- Parse `addr` messages and merge into address book
- Relay `addr` messages to a subset of connected peers

**Story 2.3 — Peer Manager**
As a node, I want a peer manager that maintains a target number of outbound connections,
evicts misbehaving or stale peers, and reconnects on disconnect.

- Target outbound slot count (8 by default)
- Ban list for peers that send invalid data
- Reconnect backoff with jitter

---

### Sprint 3 — Block & Transaction Propagation

**Story 3.1 — `inv` / `getdata` Round-Trip**
As a node, I want to announce and request inventory items (blocks and transactions)
using `inv` and `getdata` so that I can discover and fetch new data from peers.

- [x] ~~`inv`, `getdata`, `notfound`, block, and tx message serialization/deserialization~~
- Send `inv` when a new block or tx enters the mempool
- Handle incoming `inv` and issue `getdata` for unknown items
- Deduplicate in-flight requests

**Story 3.2 — `tx` Message Handling**
As a node, I want to receive `tx` messages from peers, validate the transaction,
and add it to the mempool so that unconfirmed transactions propagate across the network.

- [x] ~~Deserialise `tx` message into `Tx` object~~
- Run script validation and fee checks
- Add to mempool on success; log and ignore on failure

**Story 3.3 — `block` Message Handling**
As a node, I want to receive `block` messages, validate the full block,
and extend the chain so that I stay in sync with the network tip.

- [x] ~~Deserialise `block` message~~
- [x] ~~Run append-only block validation (PoW, Merkle, scripts, coinbase)~~
- [x] ~~Update UTXO set and chain height on successful append-only active-chain block~~
- Trigger reorg logic if needed

---

### Sprint 4 — Initial Block Download (IBD)

**Story 4.1 — `getheaders` / `headers` Sync**
As a node starting from genesis, I want to download all block headers first
so that I can verify proof-of-work on the full chain before downloading block data.

- Send `getheaders` with known tip locator
- [x] ~~Parse `headers` response (up to 2000 headers per message)~~
- Validate each header's PoW and chain linkage
- Loop until peer returns fewer than 2000 headers

**Story 4.2 — Parallel Block Download**
As a node, I want to download full blocks from multiple peers in parallel during IBD
so that I saturate available bandwidth and sync as fast as possible.

- Assign block ranges to peers
- Re-request blocks from alternate peers on timeout
- Apply blocks in order once downloaded out-of-order

**Story 4.3 — IBD State & Progress Reporting**
As a node operator, I want to see IBD progress (height, % complete, estimated time remaining, blocks/sec)
in the logs so that I know the sync is healthy.

- Track sync start time and current height
- Log progress every N blocks or every M seconds
- Set `is_in_ibd` flag — suppress mempool relay until caught up

---

### Sprint 5 — Hardening & Testing

**Story 5.1 — Network Integration Tests**
As a developer, I want automated tests that spin up two in-process nodes in regtest mode,
perform a handshake, and propagate a block between them
so that the full P2P path is covered without hitting the live network.

**Story 5.2 — Peer Misbehaviour Scoring**
As a node, I want to assign misbehaviour scores to peers and disconnect/ban those that exceed a threshold
so that the node is resilient to malformed or malicious messages.

**Story 5.3 — `ping` / `pong` Keepalive**
As a node, I want to send periodic `ping` messages and disconnect peers that do not respond with `pong`
within a timeout so that stale connections are cleaned up automatically.

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
