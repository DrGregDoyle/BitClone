"""
The Database class - holds the UTXO set
"""
import sqlite3
from pathlib import Path

from src.block.block import Block
from src.core import get_logger
from src.database.block_files import BlockFileManager
from src.tx.tx import Tx, UTXO

DB_PATH = Path(__file__).parent / "db_files" / "bitclone.db"

__all__ = ["BitCloneDatabase", "DB_PATH"]
logger = get_logger(__name__)


class BitCloneDatabase:
    def __init__(self, db_path=DB_PATH, testing=False):
        # --- Establish db path
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # --- testing bool
        self.testing = testing

        # --- Block file manager
        blocks_dir = self.db_path.parent / "blocks"
        self.block_files = BlockFileManager(blocks_dir)

        # --- Persistent connection
        self.conn: sqlite3.Connection | None = sqlite3.connect(self.db_path)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._initialize_database()

    def _require_conn(self) -> sqlite3.Connection:
        """Return the active connection or raise if the database is closed."""
        if self.conn is None:
            raise RuntimeError("Database connection is closed.")
        return self.conn

    def _initialize_database(self) -> None:
        """Create necessary tables if they do not exist."""
        conn = self._require_conn()
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS utxos
                (
                    outpoint BLOB NOT NULL,
                    amount INTEGER NOT NULL,
                    script_pubkey BLOB NOT NULL,
                    height INTEGER NOT NULL,
                    coinbase INTEGER NOT NULL DEFAULT 0
                        CHECK (coinbase IN (0, 1)),
                    PRIMARY KEY (outpoint)
                ) WITHOUT ROWID
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS blocks
                (
                    height INTEGER PRIMARY KEY,
                    block_hash BLOB NOT NULL UNIQUE,
                    prev_hash BLOB NOT NULL,
                    timestamp INTEGER NOT NULL,
                    file_number INTEGER NOT NULL,
                    file_offset INTEGER NOT NULL,
                    block_size INTEGER NOT NULL
                )
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_block_hash
                ON blocks(block_hash)
            """)

    def _clear_db(self) -> None:
        """Wipe the database and recreate a fresh schema."""
        conn = self._require_conn()
        with conn:
            conn.execute("DROP TABLE IF EXISTS utxos")
            conn.execute("DROP TABLE IF EXISTS blocks")

        # Remove all .dat block files to keep storage in sync with the DB
        deleted = self.block_files.clear_block_files()
        logger.info(f"Cleared {deleted} block file(s) from disk).")

        self._initialize_database()

    # --- UTXOS --- #
    def add_utxo(self, u: UTXO) -> None:
        """Insert a UTXO."""
        conn = self._require_conn()
        with conn:
            conn.execute(
                """
                INSERT INTO utxos(outpoint, amount, script_pubkey, height, coinbase)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    u.outpoint,
                    u.amount,
                    u.scriptpubkey,
                    u.block_height or 0,
                    1 if u.is_coinbase else 0,
                ),
            )

    def get_utxo(self, outpoint: bytes) -> UTXO | None:
        """Fetch a UTXO by outpoint."""
        conn = self._require_conn()
        row = conn.execute(
            """
            SELECT outpoint, amount, script_pubkey, height, coinbase
            FROM utxos
            WHERE outpoint = ?
            """,
            (outpoint,),
        ).fetchone()

        if row is None:
            return None

        row_outpoint, amount, scriptpubkey, height, coinbase = row
        return UTXO(row_outpoint, amount, scriptpubkey, height, bool(coinbase))

    def remove_utxo(self, outpoint: bytes) -> None:
        """Remove a UTXO from the set."""
        conn = self._require_conn()
        with conn:
            conn.execute(
                "DELETE FROM utxos WHERE outpoint = ?",
                (outpoint,),
            )

    def count_utxos(self) -> int:
        """Return the total number of UTXOs in the database."""
        conn = self._require_conn()
        row = conn.execute("SELECT COUNT(*) FROM utxos").fetchone()
        return row[0] if row is not None else 0

    def get_utxos(self, tx: Tx) -> list[UTXO] | None:
        """Return the UTXOs for tx inputs, or None if any are missing."""
        utxos = []
        for txin in tx.inputs:
            utxo = self.get_utxo(txin.outpoint)
            if utxo is None:
                logger.error(f"Missing utxo for outpoint {txin.outpoint.hex()}. Invalid tx.")
                return None
            utxos.append(utxo)
        return utxos

    # --- BLOCKS --- #
    def add_block(self, block: Block, block_height: int) -> None:
        """Add a block to storage."""
        block_bytes = block.to_bytes()
        file_num, offset, size = self.block_files.write_block(block_bytes)

        header = block.get_header()
        conn = self._require_conn()
        with conn:
            conn.execute(
                """
                INSERT INTO blocks (
                    height, block_hash, prev_hash, timestamp,
                    file_number, file_offset, block_size
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    block_height,
                    header.block_id,
                    block.prev_block,
                    block.timestamp,
                    file_num,
                    offset,
                    size,
                ),
            )

    def get_block(self, block_hash: bytes) -> Block | None:
        """Retrieve a block by hash."""
        conn = self._require_conn()
        row = conn.execute(
            """
            SELECT file_number, file_offset, block_size
            FROM blocks
            WHERE block_hash = ?
            """,
            (block_hash,),
        ).fetchone()

        if row is None:
            return None

        file_num, offset, size = row
        block_bytes = self.block_files.read_block(file_num, offset, size)
        return Block.from_bytes(block_bytes)

    def get_block_at_height(self, height: int) -> Block | None:
        """Retrieve a block by height."""
        conn = self._require_conn()
        row = conn.execute(
            """
            SELECT file_number, file_offset, block_size
            FROM blocks
            WHERE height = ?
            """,
            (height,),
        ).fetchone()

        if row is None:
            return None

        file_num, offset, size = row
        block_bytes = self.block_files.read_block(file_num, offset, size)
        return Block.from_bytes(block_bytes)

    def get_chain_height(self) -> int:
        """Return the current blockchain height."""
        conn = self._require_conn()
        row = conn.execute("SELECT MAX(height) FROM blocks").fetchone()
        return row[0] if row and row[0] is not None else -1

    def get_latest_block(self) -> Block | None:
        """Return the tip of the blockchain."""
        height = self.get_chain_height()
        if height < 0:
            return None
        return self.get_block_at_height(height)

    # --- DB MAINTENANCE --- #
    def wipe_db(self) -> None:
        """Primarily used in testing."""
        self._clear_db()

    def close(self) -> None:
        """Close owned resources."""
        if self.conn is not None:
            self.conn.close()
            self.conn = None

        if hasattr(self.block_files, "close"):
            self.block_files.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
