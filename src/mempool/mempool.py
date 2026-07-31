"""
The MemPool class
"""
import time
from math import ceil
from dataclasses import dataclass, field
from pathlib import Path

from src.core import TX, ReadError, get_logger, TransactionError
from src.database.database import BitCloneDatabase
from src.database.bitcoin_core_rpc import BitcoinCoreRPC
from src.tx import LoadedTx, Tx, UTXO
from src.core import ChainParams, NetworkName, get_chain_params
from src.mempool.orphan_pool import OrphanTransactionPool
from src.mempool.policy import (
    AdmissionCategory,
    AdmissionResult,
    check_transaction_standardness,
)
from src.tx.validation import TxValidationContext, validate_loaded_tx, validate_tx_scripts

logger = get_logger(__name__)

# --- TEST DB PATH FOR DEVELOPMENT --- #
TEST_DB_PATH = Path(__file__).parent / "db_files" / "test_db.sqlite3"


@dataclass(slots=True, eq=False, repr=False, unsafe_hash=False)
class MemPoolTx:
    """
    A transaction along with mutable mempool metadata.

    Equality, hashing, and representation intentionally retain object identity
    semantics because ancestor and descendant relationships can form cycles.
    """
    tx: bytes | Tx
    fee: int
    ancestors: list["MemPoolTx"] = field(default_factory=list)
    descendants: list["MemPoolTx"] = field(default_factory=list)
    arrival_time: int = field(default_factory=lambda: int(time.time()), init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.tx, Tx):
            self.tx = Tx.from_bytes(self.tx)
        if self.ancestors is None:
            self.ancestors = []
        if self.descendants is None:
            self.descendants = []

    @property
    def feerate(self) -> float:
        return self.fee / self.tx.vbytes

    @property
    def ancestor_feerate(self) -> float:
        ancestor_fees = sum(a.fee for a in self.ancestors)
        ancestor_vbytes = sum(a.tx.vbytes for a in self.ancestors)
        return (self.fee + ancestor_fees) / (self.tx.vbytes + ancestor_vbytes)

    @property
    def bip125_replaceable(self) -> bool:
        """Return whether this entry explicitly or inheritably signals RBF."""
        return any(
            txin.sequence < 0xFFFFFFFE
            for entry in [self, *self.ancestors]
            for txin in entry.tx.inputs
        )


class MemPool:
    """
    The holding area for incoming transactions.
    """
    MAX_SIZE = 300_000
    MAX_TIME = 3_600 * 336  # 336 hours = 2 weeks
    MIN_FEE = 1  # sats/vbyte = feerate
    MAX_BLOCK_WEIGHT = 4_000_000  # 4 million wu
    MAX_ANCESTOR_COUNT = 25
    MAX_ANCESTOR_VBYTES = 101_000
    MAX_DESCENDANT_COUNT = 25
    MAX_DESCENDANT_VBYTES = 101_000
    MAX_REPLACEMENT_EVICTIONS = 100
    RBF_SEQUENCE_THRESHOLD = 0xFFFFFFFE
    ROLLING_FEE_HALFLIFE = 12 * 60 * 60

    def __init__(
            self,
            db_path: Path = TEST_DB_PATH,
            blocks_dir: Path | None = None,
            storage_mode: str = "archival",
            prune_keep_blocks: int = 288,
            core_rpc: BitcoinCoreRPC | None = None,
            network: NetworkName | str = NetworkName.MAINNET,
            chain_params: ChainParams | None = None,
            coin_view: BitCloneDatabase | None = None,
    ) -> None:
        self.chain_params = chain_params or get_chain_params(network)
        # --- MemPool constants
        self.max_size = MemPool.MAX_SIZE
        self.max_time = MemPool.MAX_TIME
        self.min_fee = MemPool.MIN_FEE
        self.max_block_weight = MemPool.MAX_BLOCK_WEIGHT
        self.max_ancestor_count = MemPool.MAX_ANCESTOR_COUNT
        self.max_ancestor_vbytes = MemPool.MAX_ANCESTOR_VBYTES
        self.max_descendant_count = MemPool.MAX_DESCENDANT_COUNT
        self.max_descendant_vbytes = MemPool.MAX_DESCENDANT_VBYTES
        self.max_replacement_evictions = MemPool.MAX_REPLACEMENT_EVICTIONS

        # The node injects its blockchain database here so admission always
        # observes the active chain selected by that exact node instance.
        self._owns_btcdb = coin_view is None
        self.btcdb = coin_view or BitCloneDatabase(
                db_path,
                blocks_dir=blocks_dir,
                storage_mode=storage_mode,
                prune_keep_blocks=prune_keep_blocks,
                core_rpc=core_rpc,
            )

        # --- MemPool storage
        self.mempool = {}  # Dict where the key will be the txid

        # --- Metadata
        self.total_vbytes = 0  # Update with every tx added or removed
        self.spent_outpoints = set()  # Update with every tx added or removed
        self.spends: dict[bytes, bytes] = {}
        self.orphans = OrphanTransactionPool()
        self.rolling_min_fee = 0.0
        self.rolling_fee_updated_at = int(time.time())
        self.last_admission = AdmissionResult(
            False,
            AdmissionCategory.POLICY,
            "no transaction has been submitted",
        )

    def __len__(self) -> int:
        return len(self.mempool)

    def __contains__(self, txid: bytes) -> bool:
        return txid in self.mempool

    def add_tx(self, candidate_tx: bytes | Tx, *, _reconsidering: bool = False) -> bool:
        """
        We validate the candidate_tx and return True or False based on whether the transaction was added to the pool.
        """
        result = self.accept_tx(candidate_tx, _reconsidering=_reconsidering)
        self.last_admission = result
        return result.accepted

    def accept_tx(
            self,
            candidate_tx: bytes | Tx,
            *,
            _reconsidering: bool = False,
    ) -> AdmissionResult:
        """Evaluate and, when accepted, insert a transaction into the mempool."""
        # --- Evict expired transactions
        self.evict_expired()

        # --- Get the Transaction object
        try:
            tx = Tx.from_bytes(candidate_tx) if isinstance(candidate_tx, bytes) else candidate_tx
        except (ReadError, ValueError) as e:
            logger.error(f"Failed to decode tx from byte stream: {e}")
            return self._result(AdmissionCategory.CONSENSUS_INVALID, f"transaction decode failed: {e}")

        precheck = self._precheck_tx(tx)
        if precheck is not None:
            return precheck

        direct_conflicts = self._get_direct_conflicts(tx)

        try:
            utxos = self._get_utxos(tx)
        except ReadError as error:
            logger.error(f"Validation error: {error}")
            return self._result(AdmissionCategory.CONSENSUS_INVALID, str(error))

        if utxos is None:
            missing_parents = {
                txin.txid
                for txin in tx.inputs
                if self._get_utxo(txin.outpoint) is None
            }
            orphan_pool = self._orphan_pool()
            stored = orphan_pool.add(tx, missing_parents)
            if stored:
                logger.info(
                    f"Stored orphan tx {tx.txid.hex()} waiting for "
                    f"{len(missing_parents)} parent(s)"
                )
            return self._result(AdmissionCategory.ORPHAN, "transaction inputs are not known")

        try:
            loaded_tx = LoadedTx(tx, utxos)
            tx_fee = loaded_tx.fee
        except (ReadError, TransactionError, ValueError) as error:
            logger.error(f"Validation error: {error}")
            return self._result(AdmissionCategory.CONSENSUS_INVALID, str(error))
        if not self._validate_tx(tx, utxos):
            logger.error("Failed consensus validation")
            return self._result(AdmissionCategory.CONSENSUS_INVALID, "transaction failed consensus validation")
        standard_reason = self._check_standardness(loaded_tx)
        if standard_reason is not None:
            logger.error(f"Non-standard transaction {tx.txid.hex()}: {standard_reason}")
            return self._result(AdmissionCategory.NONSTANDARD, standard_reason)

        minimum_feerate = self.get_min_relay_feerate()
        required_fee = ceil(minimum_feerate * tx.vbytes)
        if tx_fee < required_fee:
            reason = (
                f"fee too low: {tx_fee} sats, requires {required_fee} sats "
                f"at {minimum_feerate:.2f} sat/vB"
            )
            logger.error(reason)
            return self._result(AdmissionCategory.POLICY, reason)

        eviction_set: set[bytes] = set()
        if direct_conflicts:
            replacement_reason, eviction_set = self._check_replacement(
                tx,
                tx_fee,
                direct_conflicts,
            )
            if replacement_reason is not None:
                logger.error(f"Replacement rejected: {replacement_reason}")
                return self._result(AdmissionCategory.POLICY, replacement_reason)

        ancestors = self._get_ancestors(tx, excluded_txids=eviction_set)
        if not self._check_package_limits(tx, ancestors, ignored_txids=eviction_set):
            return self._result(AdmissionCategory.POLICY, "transaction exceeds package limits")

        replaced_txids = tuple(sorted(eviction_set))
        self._remove_entries(eviction_set)

        # --- Create MemPoolTx
        mempool_tx = MemPoolTx(
            tx=tx,
            fee=tx_fee,
            ancestors=ancestors,
        )

        # Every transitive ancestor tracks this transaction as a transitive
        # descendant. That keeps package-limit checks constant-time per entry.
        for ancestor in ancestors:
            ancestor.descendants.append(mempool_tx)

        # --- Add tx
        self.mempool.update({tx.txid: mempool_tx})
        self._add_metadata(tx)
        self._trim_to_size()
        if tx.txid not in self.mempool:
            return self._result(
                AdmissionCategory.POLICY,
                "transaction evicted because the mempool is full",
                replaced_txids,
            )
        self._orphan_pool().remove(tx.txid)
        if not _reconsidering:
            self._reconsider_orphans(tx.txid)

        return AdmissionResult(
            True,
            AdmissionCategory.ACCEPTED,
            "transaction accepted",
            replaced_txids,
        )

    def confirm_block(self, confirmed_txids: list[bytes]) -> None:
        for txid in confirmed_txids:
            if txid in self.mempool:
                self._remove_tx(txid)
                logger.info(f"Confirmed tx removed from mempool: {txid.hex()}")
            # A parent can first become known by arriving inside a block rather
            # than through the mempool. Its outputs are now in the active view.
            self._reconsider_orphans(txid)

    def evict_expired(self) -> int:
        """
        We look through mempool and remove any txs older than 2 weeks
        """
        now = int(time.time())
        expired_txids = [txid for txid, mptx in self.mempool.items() if now - mptx.arrival_time > self.max_time]

        for txid in expired_txids:
            self._remove_tx(txid, remove_descendants=True)
            logger.info(f"Evicted expired tx {txid.hex()}")
        self._orphan_pool().evict_expired(now)
        return len(expired_txids)

    def get_block_template(self):
        """
        We select a list of txs to be included in a block.
        """
        selected: list[Tx] = []
        selected_txids: set[bytes] = set()
        block_weight = 0
        remaining = set(self.mempool)

        while remaining:
            packages: list[tuple[float, bytes, list[MemPoolTx]]] = []
            for txid in remaining:
                entry = self.mempool[txid]
                package = [
                    ancestor for ancestor in entry.ancestors
                    if ancestor.tx.txid not in selected_txids
                ]
                package.append(entry)
                package = self._topological_order(package)
                package_weight = sum(member.tx.wu for member in package)
                if block_weight + package_weight > self.max_block_weight:
                    continue
                package_fee = sum(member.fee for member in package)
                package_vbytes = sum(member.tx.vbytes for member in package)
                packages.append((package_fee / package_vbytes, txid, package))

            if not packages:
                break
            _, _, best_package = max(packages, key=lambda item: (item[0], item[1]))
            for entry in best_package:
                txid = entry.tx.txid
                if txid in selected_txids:
                    continue
                selected.append(entry.tx)
                selected_txids.add(txid)
                remaining.discard(txid)
                block_weight += entry.tx.wu

        return selected

    def get_fee(self, txid: bytes) -> int:
        """
        Return the fee for a transaction currently in the mempool.
        """
        return self.mempool[txid].fee

    def get_tx(self, txid: bytes) -> Tx | None:
        """Return a transaction currently held in the mempool."""
        entry = self.mempool.get(txid)
        return entry.tx if entry is not None else None

    def get_txids(self) -> list[str]:
        """
        Return mempool transaction ids in display byte order.
        """
        return [txid[::-1].hex() for txid in self.mempool]

    def to_data(self, verbose: bool = False):
        """
        Return mempool contents for CLI/RPC display.
        """
        if not verbose:
            return self.get_txids()

        return {
            txid[::-1].hex(): {
                "fee": mptx.fee,
                "vbytes": mptx.tx.vbytes,
                "feerate": mptx.feerate,
                "ancestor_feerate": mptx.ancestor_feerate,
                "arrival_time": mptx.arrival_time,
                "ancestor_count": len(mptx.ancestors),
                "descendant_count": len(mptx.descendants),
                "bip125_replaceable": mptx.bip125_replaceable,
            }
            for txid, mptx in self.mempool.items()
        }

    def close(self) -> None:
        """
        Close resources owned by the mempool.
        """
        if getattr(self, "_owns_btcdb", True):
            self.btcdb.close()

    def _precheck_tx(self, tx: Tx) -> AdmissionResult | None:
        # --- Check if tx is in mempool
        if tx.txid in self.mempool:
            logger.error(f"Transaction with id {tx.txid} already exists in mempool.")
            return self._result(AdmissionCategory.POLICY, "transaction already exists in mempool")

        # --- Check not coinbase
        if tx.is_coinbase:
            logger.error(f"Cannot add coinbase tx to the mempool")
            return self._result(AdmissionCategory.CONSENSUS_INVALID, "coinbase transaction is not valid in mempool")
        return None

    def _validate_tx(self, tx: Tx, utxos: list[UTXO] | None = None) -> bool:
        try:
            resolved_utxos = utxos if utxos is not None else self._get_utxos(tx)
            if resolved_utxos is None:
                return False
            loaded_tx = LoadedTx(tx, resolved_utxos)
        except (ReadError, TransactionError, ValueError) as e:
            logger.error(f"Validation error: {e}")
            return False

        try:
            chain_params = getattr(self, "chain_params", get_chain_params(NetworkName.MAINNET))
            chain_height = self.btcdb.get_chain_height()
            next_height = chain_height + 1 if isinstance(chain_height, int) else 0
            tip = self.btcdb.get_latest_block()
            tip_time = getattr(tip, "timestamp", None)
            consensus_flags = chain_params.consensus_script_flags(
                next_height,
                block_time=tip_time if isinstance(tip_time, int) else None,
            )
            if not validate_loaded_tx(
                    loaded_tx,
                    TxValidationContext(
                        validate_scripts=True,
                        script_validator=lambda candidate: validate_tx_scripts(
                            candidate,
                            flags=consensus_flags,
                        ),
                    ),
            ):
                return False
        except Exception as e:
            # Candidate transactions are untrusted network input. Script parsing
            # and execution failures reject the transaction; they must not escape
            # mempool admission and tear down the peer session.
            logger.error(f"Transaction validation failed for {tx.txid.hex()}: {e}")
            return False

        return True

    def _check_standardness(self, loaded_tx: LoadedTx) -> str | None:
        """Apply relay policy after the transaction has passed consensus checks."""
        shape_reason = check_transaction_standardness(loaded_tx.tx)
        if shape_reason is not None:
            return shape_reason
        try:
            chain_params = getattr(self, "chain_params", get_chain_params(NetworkName.MAINNET))
            chain_height = self.btcdb.get_chain_height()
            next_height = chain_height + 1 if isinstance(chain_height, int) else 0
            tip = self.btcdb.get_latest_block()
            tip_time = getattr(tip, "timestamp", None)
            standard_flags = chain_params.standard_script_flags(
                next_height,
                block_time=tip_time if isinstance(tip_time, int) else None,
            )
            if not validate_tx_scripts(loaded_tx, flags=standard_flags):
                return "transaction scripts fail standard relay flags"
        except Exception as error:
            return f"standard script validation failed: {error}"
        return None

    def _get_utxo(self, outpoint: bytes) -> UTXO | None:
        """Resolve an output from an unconfirmed parent, then the active chain."""
        parent = self.mempool.get(outpoint[:TX.TXID])
        if parent is not None:
            vout = int.from_bytes(outpoint[TX.TXID:], "little")
            if vout >= len(parent.tx.outputs):
                raise ReadError(
                    f"Outpoint references missing output {vout} of mempool tx "
                    f"{parent.tx.txid.hex()}"
                )
            chain_height = self.btcdb.get_chain_height()
            return UTXO.from_txoutput(
                outpoint,
                parent.tx.outputs[vout],
                (chain_height + 1) if isinstance(chain_height, int) else 0,
            )
        return self.btcdb.get_utxo(outpoint)

    def _get_utxos(self, tx: Tx) -> list[UTXO] | None:
        """
        Resolve inputs against the mempool overlay and active-chain coin view.

        ``None`` identifies a transaction with unknown parents so it can enter
        the orphan pool. A malformed reference to a known parent raises.
        """
        utxos = []
        missing_input = False
        for txin in tx.inputs:
            temp_utxo = self._get_utxo(txin.outpoint)
            if temp_utxo is None:
                missing_input = True
            else:
                utxos.append(temp_utxo)
        return None if missing_input else utxos

    def _get_fee(self, tx: Tx) -> int:
        """
        We return the tx fee amount in sats
        """
        utxos = self._get_utxos(tx)
        if utxos is None:
            raise ReadError("Cannot calculate fee with missing inputs")
        return LoadedTx(tx, utxos).fee

    def _remove_tx(self, txid: bytes, *, remove_descendants: bool = False) -> None:
        """Remove a tx from the mempool and clean up all references."""
        mempool_tx = self.mempool[txid]
        if remove_descendants:
            for descendant in reversed(mempool_tx.descendants.copy()):
                descendant_txid = descendant.tx.txid
                if descendant_txid in self.mempool:
                    self._remove_tx(descendant_txid, remove_descendants=True)
        for ancestor in mempool_tx.ancestors:
            if mempool_tx in ancestor.descendants:
                ancestor.descendants.remove(mempool_tx)
        for descendant in mempool_tx.descendants:
            if mempool_tx in descendant.ancestors:
                descendant.ancestors.remove(mempool_tx)
        self._remove_metadata(mempool_tx.tx)
        del self.mempool[txid]

    def _get_ancestors(
            self,
            tx: Tx,
            *,
            excluded_txids: set[bytes] | None = None,
    ) -> list[MemPoolTx]:
        """Return all in-mempool ancestors in topological order."""
        excluded_txids = excluded_txids or set()
        ancestors: list[MemPoolTx] = []
        seen: set[bytes] = set()
        for txin in tx.inputs:
            parent = self.mempool.get(txin.txid)
            if parent is None or parent.tx.txid in excluded_txids:
                continue
            for ancestor in [*parent.ancestors, parent]:
                if ancestor.tx.txid in seen or ancestor.tx.txid in excluded_txids:
                    continue
                ancestors.append(ancestor)
                seen.add(ancestor.tx.txid)
        return self._topological_order(ancestors)

    @staticmethod
    def _topological_order(entries: list[MemPoolTx]) -> list[MemPoolTx]:
        """Order a dependency-closed entry list with every parent first."""
        return sorted(
            entries,
            key=lambda entry: (
                len(entry.ancestors),
                entry.arrival_time,
                entry.tx.txid,
            ),
        )

    def _check_package_limits(
            self,
            tx: Tx,
            ancestors: list[MemPoolTx],
            *,
            ignored_txids: set[bytes] | None = None,
    ) -> bool:
        """Enforce count and virtual-size limits in both graph directions."""
        ignored_txids = ignored_txids or set()
        ancestor_count = len(ancestors) + 1
        ancestor_vbytes = tx.vbytes + sum(entry.tx.vbytes for entry in ancestors)
        if ancestor_count > getattr(self, "max_ancestor_count", self.MAX_ANCESTOR_COUNT):
            logger.error(f"Transaction exceeds ancestor count limit: {ancestor_count}")
            return False
        if ancestor_vbytes > getattr(self, "max_ancestor_vbytes", self.MAX_ANCESTOR_VBYTES):
            logger.error(f"Transaction exceeds ancestor size limit: {ancestor_vbytes} vbytes")
            return False

        for ancestor in ancestors:
            retained_descendants = [
                entry
                for entry in ancestor.descendants
                if entry.tx.txid not in ignored_txids
            ]
            descendant_count = len(retained_descendants) + 2
            descendant_vbytes = (
                ancestor.tx.vbytes
                + sum(entry.tx.vbytes for entry in retained_descendants)
                + tx.vbytes
            )
            if descendant_count > getattr(
                    self, "max_descendant_count", self.MAX_DESCENDANT_COUNT
            ):
                logger.error(
                    f"Transaction exceeds descendant count limit for "
                    f"{ancestor.tx.txid.hex()}: {descendant_count}"
                )
                return False
            if descendant_vbytes > getattr(
                    self, "max_descendant_vbytes", self.MAX_DESCENDANT_VBYTES
            ):
                logger.error(
                    f"Transaction exceeds descendant size limit for "
                    f"{ancestor.tx.txid.hex()}: {descendant_vbytes} vbytes"
                )
                return False
        return True

    def _get_direct_conflicts(self, tx: Tx) -> list[MemPoolTx]:
        """Return mempool entries spending any candidate input."""
        spend_index = self._spend_index()
        conflict_txids = {
            spend_index[txin.outpoint]
            for txin in tx.inputs
            if txin.outpoint in spend_index
        }
        return [self.mempool[txid] for txid in conflict_txids if txid in self.mempool]

    def _check_replacement(
            self,
            tx: Tx,
            tx_fee: int,
            direct_conflicts: list[MemPoolTx],
    ) -> tuple[str | None, set[bytes]]:
        """Apply the five opt-in full-RBF rules from BIP125."""
        if any(not self._signals_replaceability(entry) for entry in direct_conflicts):
            return "conflicting transaction does not signal replaceability", set()

        eviction_set: set[bytes] = set()
        for conflict in direct_conflicts:
            eviction_set.add(conflict.tx.txid)
            eviction_set.update(entry.tx.txid for entry in conflict.descendants)
        eviction_limit = getattr(
            self,
            "max_replacement_evictions",
            self.MAX_REPLACEMENT_EVICTIONS,
        )
        if len(eviction_set) > eviction_limit:
            return (
                f"replacement would evict {len(eviction_set)} transactions; "
                f"limit is {eviction_limit}"
            ), set()

        original_unconfirmed_inputs = {
            txin.outpoint
            for conflict in direct_conflicts
            for txin in conflict.tx.inputs
            if txin.txid in self.mempool
        }
        for txin in tx.inputs:
            if txin.txid in self.mempool and txin.outpoint not in original_unconfirmed_inputs:
                return "replacement adds a new unconfirmed input", set()

        evicted_fee = sum(self.mempool[txid].fee for txid in eviction_set)
        if tx_fee < evicted_fee:
            return (
                f"replacement fee {tx_fee} is below evicted fee {evicted_fee}"
            ), set()
        incremental_fee = ceil(self.min_fee * tx.vbytes)
        if tx_fee - evicted_fee < incremental_fee:
            return (
                f"replacement fee increase {tx_fee - evicted_fee} is below "
                f"incremental relay fee {incremental_fee}"
            ), set()
        return None, eviction_set

    def _signals_replaceability(self, entry: MemPoolTx) -> bool:
        """Check explicit or inherited opt-in RBF signaling."""
        return any(
            txin.sequence < self.RBF_SEQUENCE_THRESHOLD
            for candidate in [entry, *entry.ancestors]
            for txin in candidate.tx.inputs
        )

    def _remove_entries(self, txids: set[bytes]) -> None:
        """Remove a known dependency-closed set, descendants before parents."""
        entries = [
            self.mempool[txid]
            for txid in txids
            if txid in self.mempool
        ]
        for entry in sorted(entries, key=lambda item: len(item.ancestors), reverse=True):
            if entry.tx.txid in self.mempool:
                self._remove_tx(entry.tx.txid)

    def get_min_relay_feerate(self, now: int | None = None) -> float:
        """Return the base or decayed rolling relay floor in sat/vB."""
        current_time = int(time.time()) if now is None else now
        rolling_fee = getattr(self, "rolling_min_fee", 0.0)
        updated_at = getattr(self, "rolling_fee_updated_at", current_time)
        elapsed = max(0, current_time - updated_at)
        if rolling_fee > 0 and elapsed:
            rolling_fee *= 0.5 ** (elapsed / self.ROLLING_FEE_HALFLIFE)
            if rolling_fee < self.min_fee / 2:
                rolling_fee = 0.0
            self.rolling_min_fee = rolling_fee
            self.rolling_fee_updated_at = current_time
        return max(float(self.min_fee), rolling_fee)

    def _trim_to_size(self) -> tuple[bytes, ...]:
        """Evict the lowest descendant-feerate packages until within limits."""
        evicted: list[bytes] = []
        while self.total_vbytes > self.max_size and self.mempool:
            candidates: list[tuple[float, bytes, set[bytes]]] = []
            for txid, entry in self.mempool.items():
                package_txids = {
                    txid,
                    *(descendant.tx.txid for descendant in entry.descendants),
                }
                package_fee = sum(self.mempool[item].fee for item in package_txids)
                package_vbytes = sum(self.mempool[item].tx.vbytes for item in package_txids)
                candidates.append((package_fee / package_vbytes, txid, package_txids))
            package_feerate, _, package_txids = min(
                candidates,
                key=lambda item: (item[0], item[1]),
            )
            self._remove_entries(package_txids)
            evicted.extend(sorted(package_txids))
            self.rolling_min_fee = max(
                getattr(self, "rolling_min_fee", 0.0),
                package_feerate + self.min_fee,
            )
            self.rolling_fee_updated_at = int(time.time())
        return tuple(evicted)

    @staticmethod
    def _result(
            category: AdmissionCategory,
            reason: str,
            replaced_txids: tuple[bytes, ...] = (),
    ) -> AdmissionResult:
        return AdmissionResult(False, category, reason, replaced_txids)

    def _spend_index(self) -> dict[bytes, bytes]:
        """Return the outpoint index, rebuilding lightweight legacy fixtures."""
        if not hasattr(self, "spends"):
            self.spends = {
                txin.outpoint: txid
                for txid, entry in self.mempool.items()
                for txin in entry.tx.inputs
            }
        return self.spends

    def _orphan_pool(self) -> OrphanTransactionPool:
        """Lazily initialize for compatibility with lightweight test fixtures."""
        if not hasattr(self, "orphans"):
            self.orphans = OrphanTransactionPool()
        return self.orphans

    def _reconsider_orphans(self, accepted_parent_txid: bytes) -> None:
        """Retry orphan descendants as their parents become available."""
        queue = [accepted_parent_txid]
        while queue:
            parent_txid = queue.pop(0)
            for orphan in self._orphan_pool().pop_dependents(parent_txid):
                if self.add_tx(orphan.tx, _reconsidering=True):
                    queue.append(orphan.tx.txid)

    def _add_metadata(self, tx: Tx) -> None:
        """
        When a tx is to be added to the pool, we track some metadata for the pool.
        """
        # --- total_vbytes
        self.total_vbytes += tx.vbytes

        # --- spent_outpoints
        for txin in tx.inputs:
            self.spent_outpoints.add(txin.outpoint)
            self._spend_index()[txin.outpoint] = tx.txid

    def _remove_metadata(self, tx: Tx) -> None:
        """
        When a tx is removed from the pool, we also remove its tracked metadata.
        """
        # --- total_vbytes
        self.total_vbytes -= tx.vbytes

        # --- spent_outpoints
        for txin in tx.inputs:
            self.spent_outpoints.discard(txin.outpoint)
            self._spend_index().pop(txin.outpoint, None)


# ---TESING --- #
if __name__ == "__main__":
    # testing db capabilities
    test_mempool = MemPool()
