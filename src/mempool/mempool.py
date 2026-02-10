"""
The MemPool class
"""
from pathlib import Path

from src.core import ReadError, get_logger
from src.database.database import BitCloneDatabase, DB_PATH
from src.tx import Transaction

logger = get_logger(__name__)


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

    def __init__(self, db_path: Path = DB_PATH) -> None:
        # --- MemPool constants
        self.max_size = MemPool.MAX_SIZE
        self.max_time = MemPool.MAX_TIME
        self.min_fee = MemPool.MIN_FEE

        # --- UTXO set
        self.btcdb = BitCloneDatabase(db_path)

        # --- MemPool storage
        self.mempool = {}  # Dict where the key will be the txid

    def add_tx(self, candidate_tx: bytes) -> bool:
        """
        We validate the candidate_tx and return True or False based on whether the transaction was added to the pool.
        """
        # --- Get the Transaction object
        try:
            tx = Transaction.from_bytes(candidate_tx)
        except [ReadError, ValueError] as e:
            raise "Failed to read tx byte stream" from e

        # --- Validate tx
        if not self._validate_tx(tx):
            logger.error("Failed to validate tx")
            return False

    def _validate_tx(self, candidate_tx: Transaction) -> bool:
        return True
