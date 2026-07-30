"""
The MemPool class
"""
import time
from dataclasses import dataclass, field
from pathlib import Path

from src.core import TX, ReadError, get_logger, TransactionError
from src.database.database import BitCloneDatabase
from src.database.bitcoin_core_rpc import BitcoinCoreRPC
from src.tx import LoadedTx, Tx, UTXO
from src.core import ChainParams, NetworkName, get_chain_params
from src.mempool.orphan_pool import OrphanTransactionPool
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
        self.orphans = OrphanTransactionPool()

    def __len__(self) -> int:
        return len(self.mempool)

    def __contains__(self, txid: bytes) -> bool:
        return txid in self.mempool

    def add_tx(self, candidate_tx: bytes | Tx, *, _reconsidering: bool = False) -> bool:
        """
        We validate the candidate_tx and return True or False based on whether the transaction was added to the pool.
        """
        # --- Evict expired transactions
        self.evict_expired()

        # --- Get the Transaction object
        try:
            tx = Tx.from_bytes(candidate_tx) if isinstance(candidate_tx, bytes) else candidate_tx
        except (ReadError, ValueError) as e:
            logger.error(f"Failed to decode tx from byte stream: {e}")
            return False

        if not self._precheck_tx(tx):
            return False

        try:
            utxos = self._get_utxos(tx)
        except ReadError as error:
            logger.error(f"Validation error: {error}")
            return False

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
            return False

        # --- Validate tx
        if not self._validate_tx(tx, utxos):
            logger.error("Failed to validate tx")
            return False

        ancestors = self._get_ancestors(tx)
        if not self._check_package_limits(tx, ancestors):
            return False

        # --- Create MemPoolTx
        mempool_tx = MemPoolTx(
            tx=tx,
            fee=LoadedTx(tx, utxos).fee,
            ancestors=ancestors,
        )

        # Every transitive ancestor tracks this transaction as a transitive
        # descendant. That keeps package-limit checks constant-time per entry.
        for ancestor in ancestors:
            ancestor.descendants.append(mempool_tx)

        # --- Add tx
        self.mempool.update({tx.txid: mempool_tx})
        self._add_metadata(tx)
        self._orphan_pool().remove(tx.txid)
        if not _reconsidering:
            self._reconsider_orphans(tx.txid)

        return True

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
            }
            for txid, mptx in self.mempool.items()
        }

    def close(self) -> None:
        """
        Close resources owned by the mempool.
        """
        if getattr(self, "_owns_btcdb", True):
            self.btcdb.close()

    def _precheck_tx(self, tx: Tx) -> bool:
        # --- Check if tx is in mempool
        if tx.txid in self.mempool:
            logger.error(f"Transaction with id {tx.txid} already exists in mempool.")
            return False

        # --- Check not coinbase
        if tx.is_coinbase:
            logger.error(f"Cannot add coinbase tx to the mempool")
            return False

        # --- Mempool double-spend policy
        for txin in tx.inputs:
            if txin.outpoint in self.spent_outpoints:
                logger.error(f"Double spend detected: {txin.outpoint.hex()}")
                return False
        return True

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
            standard_flags = chain_params.standard_script_flags(
                next_height,
                block_time=tip_time if isinstance(tip_time, int) else None,
            )
            if not validate_loaded_tx(
                    loaded_tx,
                    TxValidationContext(
                        validate_scripts=True,
                        script_validator=lambda candidate: validate_tx_scripts(
                            candidate,
                            flags=standard_flags,
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

        tx_fee = loaded_tx.fee

        # --- Check fees
        if tx_fee < self.min_fee * tx.vbytes:
            logger.error(
                f"Fee too low: {tx_fee} sats ({tx_fee / tx.vbytes:.2f} sat/vb), minimum is {self.min_fee} sat/vb")
            return False

        # --- Check size
        if self.total_vbytes + tx.vbytes > self.max_size:
            logger.error(f"Mempool full. Rejecting tx {tx.txid.hex()}")
            return False

        return True

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

    def _get_ancestors(self, tx: Tx) -> list[MemPoolTx]:
        """Return all in-mempool ancestors in topological order."""
        ancestors: list[MemPoolTx] = []
        seen: set[bytes] = set()
        for txin in tx.inputs:
            parent = self.mempool.get(txin.txid)
            if parent is None:
                continue
            for ancestor in [*parent.ancestors, parent]:
                if ancestor.tx.txid in seen:
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

    def _check_package_limits(self, tx: Tx, ancestors: list[MemPoolTx]) -> bool:
        """Enforce count and virtual-size limits in both graph directions."""
        ancestor_count = len(ancestors) + 1
        ancestor_vbytes = tx.vbytes + sum(entry.tx.vbytes for entry in ancestors)
        if ancestor_count > getattr(self, "max_ancestor_count", self.MAX_ANCESTOR_COUNT):
            logger.error(f"Transaction exceeds ancestor count limit: {ancestor_count}")
            return False
        if ancestor_vbytes > getattr(self, "max_ancestor_vbytes", self.MAX_ANCESTOR_VBYTES):
            logger.error(f"Transaction exceeds ancestor size limit: {ancestor_vbytes} vbytes")
            return False

        for ancestor in ancestors:
            descendant_count = len(ancestor.descendants) + 2
            descendant_vbytes = (
                ancestor.tx.vbytes
                + sum(entry.tx.vbytes for entry in ancestor.descendants)
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

    def _remove_metadata(self, tx: Tx) -> None:
        """
        When a tx is removed from the pool, we also remove its tracked metadata.
        """
        # --- total_vbytes
        self.total_vbytes -= tx.vbytes

        # --- spent_outpoints
        for txin in tx.inputs:
            self.spent_outpoints.remove(txin.outpoint)


# ---TESING --- #
if __name__ == "__main__":
    # testing db capabilities
    test_mempool = MemPool()
