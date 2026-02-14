"""
The MemPool class
"""
from pathlib import Path

from src.core import ReadError, get_logger, TransactionError
from src.database.database import BitCloneDatabase
from src.script import ScriptEngine
from src.tx import Transaction

logger = get_logger(__name__)

# --- TEST DB PATH FOR DEVELOPMENT --- #
TEST_DB_PATH = Path(__file__).parent / "db_files" / "test_db.sqlite3"


class MemPoolTx:
    """
    A transaction along with mempool metadata
    """

    def __init__(self, tx: bytes | Transaction, fee: int, ancestors: list = None, descendants: list = None) -> None:
        self.tx = tx if isinstance(tx, Transaction) else Transaction.from_bytes(tx)
        self.fee = fee
        self.ancestors = ancestors or []
        self.descendants = descendants or []


class MemPool:
    """
    The holding area for incoming transactions.
    """
    MAX_SIZE = 300000
    MAX_TIME = 3600 * 336  # 336 hours = 2 weeks
    MIN_FEE = 1  # sats/vbyte = feerate

    def __init__(self, db_path: Path = TEST_DB_PATH) -> None:
        # --- MemPool constants
        self.max_size = MemPool.MAX_SIZE
        self.max_time = MemPool.MAX_TIME
        self.min_fee = MemPool.MIN_FEE

        # --- UTXO set
        self.btcdb = BitCloneDatabase(db_path)

        # --- Script Engine for Tx Validation
        self.script_engine = ScriptEngine()

        # --- MemPool storage
        self.mempool = {}  # Dict where the key will be the txid

    def add_tx(self, candidate_tx: bytes) -> bool:
        """
        We validate the candidate_tx and return True or False based on whether the transaction was added to the pool.
        """
        # --- Get the Transaction object
        try:
            tx = Transaction.from_bytes(candidate_tx)
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
        ancestors = []
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

        # --- Add tx
        self.mempool.update({tx.txid: mempool_tx})
        return True

    def _validate_tx(self, tx: Transaction) -> bool:
        # --- Check if tx is in mempool
        if tx.txid in self.mempool.keys():
            logger.error(f"Transaction with id {tx.txid} already exists in mempool.")
            return False

        # --- Check not coinbase
        if tx.is_coinbase:
            logger.error(f"Cannot add coinbase tx to the mempool")
            return False

        # --- Check fees
        try:
            tx_fee = self._get_fee(tx)
        except (ReadError, TransactionError) as e:
            logger.error(f"Validation error: {e}")
            return False

        if tx_fee < self.min_fee:
            logger.error(f"Transaction fee {tx_fee} exceeds minimum fee {self.min_fee}")
            return False

        # --- Validate Scripts

        return True

    def _get_utxos(self, tx: Transaction) -> list:
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

    def _get_fee(self, tx: Transaction) -> int:
        """
        We return the tx fee amount in sats
        """
        # setup
        utxos = self._get_utxos(tx)
        input_total = 0
        output_total = 0
        for utxo in utxos:
            input_total += utxo.amount
        for output in tx.outputs:
            output_total += output.amount
        tx_fee = input_total - output_total
        if tx_fee < 0:
            raise TransactionError("Output total exceeds input total")
        return tx_fee


# ---TESING --- #
if __name__ == "__main__":
    # testing db capabilities
    test_mempool = MemPool()
