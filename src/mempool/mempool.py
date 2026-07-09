"""
The MemPool class
"""
import time
from pathlib import Path

from src.core import ReadError, get_logger, TransactionError
from src.database.database import BitCloneDatabase
from src.script import ScriptEngine
from src.tx import LoadedTx, Tx
from src.tx.validation import TxValidationContext, validate_loaded_tx

logger = get_logger(__name__)

# --- TEST DB PATH FOR DEVELOPMENT --- #
TEST_DB_PATH = Path(__file__).parent / "db_files" / "test_db.sqlite3"


class MemPoolTx:
    """
    A transaction along with mempool metadata
    """

    def __init__(self, tx: bytes | Tx, fee: int, ancestors: list = None, descendants: list = None) -> None:
        self.tx = tx if isinstance(tx, Tx) else Tx.from_bytes(tx)
        self.fee = fee
        self.ancestors = ancestors or []
        self.descendants = descendants or []
        self.arrival_time = int(time.time())

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

    def __init__(self, db_path: Path = TEST_DB_PATH, blocks_dir: Path | None = None) -> None:
        # --- MemPool constants
        self.max_size = MemPool.MAX_SIZE
        self.max_time = MemPool.MAX_TIME
        self.min_fee = MemPool.MIN_FEE
        self.max_block_weight = MemPool.MAX_BLOCK_WEIGHT

        # --- UTXO set
        self.btcdb = BitCloneDatabase(db_path, blocks_dir=blocks_dir)

        # --- Script Engine for Tx Validation
        self.script_engine = ScriptEngine()

        # --- MemPool storage
        self.mempool = {}  # Dict where the key will be the txid

        # --- Metadata
        self.total_vbytes = 0  # Update with every tx added or removed
        self.spent_outpoints = set()  # Update with every tx added or removed

    def __len__(self) -> int:
        return len(self.mempool)

    def __contains__(self, txid: bytes) -> bool:
        return txid in self.mempool

    def add_tx(self, candidate_tx: bytes | Tx) -> bool:
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

        # --- Validate tx
        if not self._validate_tx(tx):
            logger.error("Failed to validate tx")
            return False

        # --- Find ancestors
        # --- If a Tx has an ancestor, that means the input references one of the outputs of the ancestor. Hence for
        # each input, we want to strip away the txid from its outpoint and look for that tx in the mempool
        ancestors: list[MemPoolTx] = []
        for txin in tx.inputs:
            temp_id = txin.outpoint[:32]  # outpoint = txid (32 bytes) + vout (4 bytes)
            if temp_id in self.mempool.keys():
                ancestors.append(self.mempool[temp_id])

        # --- Create MemPoolTx
        mempool_tx = MemPoolTx(
            tx=tx,
            fee=self._get_fee(tx),
            ancestors=ancestors,
        )

        # --- Add descendent
        # --- For each ancestor found in the mempool, we add the current tx to its descendents.
        # --- Each ancestor and descendent is a MemPoolTx
        for ancestor in ancestors:
            ancestor.descendants.append(mempool_tx)

        # --- Add tx
        self.mempool.update({tx.txid: mempool_tx})
        self._add_metadata(tx)

        return True

    def confirm_block(self, confirmed_txids: list[bytes]) -> None:
        for txid in confirmed_txids:
            if txid not in self.mempool:
                continue
            self._remove_tx(txid)
            logger.info(f"Confirmed tx removed from mempool: {txid.hex()}")

    def evict_expired(self) -> int:
        """
        We look through mempool and remove any txs older than 2 weeks
        """
        now = int(time.time())
        expired_txids = [txid for txid, mptx in self.mempool.items() if now - mptx.arrival_time > self.max_time]

        for txid in expired_txids:
            self._remove_tx(txid)
            logger.info(f"Evicted expired tx {txid.hex()}")
        return len(expired_txids)

    def get_block_template(self):
        """
        We select a list of txs to be included in a block.
        """
        # --- Get list sorted by ancestor_feerate
        selected: list[Tx] = []
        block_weight = 0
        tx_list = sorted(self.mempool.values(), key=lambda mptx: mptx.ancestor_feerate, reverse=True)

        for mptx in tx_list:
            next_weight = block_weight + mptx.tx.wu
            if next_weight > self.max_block_weight:
                continue
            selected.append(mptx.tx)
            block_weight = next_weight

        return selected

    def get_fee(self, txid: bytes) -> int:
        """
        Return the fee for a transaction currently in the mempool.
        """
        return self.mempool[txid].fee

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
        self.btcdb.close()

    def _validate_tx(self, tx: Tx) -> bool:
        # --- Check if tx is in mempool
        if tx.txid in self.mempool.keys():
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

        try:
            loaded_tx = LoadedTx(tx, self._get_utxos(tx))
        except (ReadError, TransactionError, ValueError) as e:
            logger.error(f"Validation error: {e}")
            return False

        if not validate_loaded_tx(loaded_tx, TxValidationContext(validate_scripts=False)):
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

        # --- Validate Scripts

        return True

    def _get_utxos(self, tx: Tx) -> list:
        """
        We obtain a list of utxos from the given transaction. Raise error if the utxo cannot be retrieved.
        """
        utxos = []
        for txin in tx.inputs:
            temp_utxo = self.btcdb.get_utxo(txin.outpoint)
            if temp_utxo is None:
                raise ReadError(f"Failed to find utxo with outpoint {txin.outpoint}")
            utxos.append(temp_utxo)
        return utxos

    def _get_fee(self, tx: Tx) -> int:
        """
        We return the tx fee amount in sats
        """
        return LoadedTx(tx, self._get_utxos(tx)).fee

    def _remove_tx(self, txid: bytes) -> None:
        """Remove a tx from the mempool and clean up all references."""
        mempool_tx = self.mempool[txid]
        for ancestor in mempool_tx.ancestors:
            ancestor.descendants.remove(mempool_tx)
        self._remove_metadata(mempool_tx.tx)
        del self.mempool[txid]

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
