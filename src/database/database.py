"""
The Database class - holds the UTXO set
"""
import sqlite3
from pathlib import Path

from src.block.block import Block
from src.core import get_logger
from src.database.block_files import BlockFileManager
from src.tx.tx import UTXO, Transaction

DB_PATH = Path(__file__).parent / "db_files" / "bitclone.db"

__all__ = ["BitCloneDatabase", "DB_PATH"]
logger = get_logger(__name__)


class BitCloneDatabase:
    def __init__(self, db_path=DB_PATH, testing=False):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Block file manager
        blocks_dir = self.db_path.parent / "blocks"
        self.block_files = BlockFileManager(blocks_dir)

        self._initialize_database()

    def _initialize_database(self):
        """Creates necessary tables if they do not exist."""
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute('''
                      CREATE TABLE IF NOT EXISTS utxos
                      (
                          outpoint
                          BLOB
                          NOT
                          NULL, -- 36 bytes
                          amount
                          INTEGER
                          NOT
                          NULL, -- satoshis
                          script_pubkey
                          BLOB
                          NOT
                          NULL, -- raw bytes
                          height
                          INTEGER
                          NOT
                          NULL,
                          coinbase
                          INTEGER
                          NOT
                          NULL
                          DEFAULT
                          0
                          CHECK (
                          coinbase
                          IN
                      (
                          0,
                          1
                      )),
                          PRIMARY KEY
                      (
                          outpoint
                      )
                          ) WITHOUT ROWID
                      ''')
            # Blocks metadata table
            c.execute('''
                      CREATE TABLE IF NOT EXISTS blocks
                      (
                          height
                          INTEGER
                          PRIMARY
                          KEY,
                          block_hash
                          BLOB
                          NOT
                          NULL
                          UNIQUE,
                          prev_hash
                          BLOB
                          NOT
                          NULL,
                          timestamp
                          INTEGER
                          NOT
                          NULL,
                          file_number
                          INTEGER
                          NOT
                          NULL,
                          file_offset
                          INTEGER
                          NOT
                          NULL,
                          block_size
                          INTEGER
                          NOT
                          NULL
                      )
                      ''')

            # Index for faster lookups by hash
            c.execute('''
                      CREATE INDEX IF NOT EXISTS idx_block_hash
                          ON blocks(block_hash)
                      ''')

            conn.commit()

    def _clear_db(self):
        """Wipes the database and creates a fresh one."""
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute("DROP TABLE IF EXISTS utxos")
            c.execute("DROP TABLE IF EXISTS blocks")
            conn.commit()
        self._initialize_database()

    # --- UTXOS --- #
    def add_utxo(self, u: UTXO) -> None:
        """Insert a UTXO (fails on duplicate outpoint)."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO utxos(outpoint, amount, script_pubkey, height, coinbase) "
                "VALUES (?, ?, ?, ?, ?)",
                (u.outpoint(), u.amount, u.scriptpubkey, u.block_height or 0, 1 if u.is_coinbase else 0),
            )
            conn.commit()

    def get_utxo(self, outpoint: bytes) -> UTXO | None:
        """Fetch a UTXO by (txid, vout) or None."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT outpoint, amount, script_pubkey, height, coinbase "
                "FROM utxos WHERE outpoint=?",
                (outpoint,),
            ).fetchone()
        if not row:
            return None
        outpoint, amt, spk, h, cb = row
        txid_b = outpoint[:32]
        vout_i = int.from_bytes(outpoint[-4:], "little")
        return UTXO(txid_b, vout_i, amt, spk, h, bool(cb))

    def remove_utxo(self, outpoint: bytes):
        """Remove a UTXO from the set"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "DELETE FROM utxos WHERE outpoint=?",
                (outpoint,),
            )
            conn.commit()

    def count_utxos(self) -> int:
        """Return the total number of UTXOs in the database."""
        with sqlite3.connect(self.db_path) as conn:
            result = conn.execute("SELECT COUNT(*) FROM utxos").fetchone()
            return result[0] if result else 0

    def get_utxos(self, tx: Transaction) -> list[UTXO] | None:
        """
        We return a list of UTXOS associated with the tx inputs. If any are missing we return None.
        """
        utxos = []
        for txin in tx.inputs:
            temp_utxo = self.get_utxo(txin.outpoint)
            if temp_utxo is None:
                logger.error(f"Missing utxo for oupoint {txin.outpoint.hex()}. Invalid tx.")
                return None
            utxos.append(temp_utxo)
        return utxos

    # --- BLOCKS --- #
    def add_block(self, block, block_height: int):
        """
        Add block to storage

        Args:
            block: Block object
            block_height: Height in the blockchain
        """
        # Serialize block
        block_bytes = block.to_bytes()

        # Write to file
        file_num, offset, size = self.block_files.write_block(block_bytes)

        # Store metadata in database
        header = block.get_header()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO blocks (height, block_hash, prev_hash, timestamp, "
                "file_number, file_offset, block_size) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (block_height,
                 header.block_id,
                 block.prev_block,
                 block.timestamp,
                 file_num,
                 offset,
                 size)
            )
            conn.commit()

    def get_block(self, block_hash: bytes):
        """Retrieve block by hash"""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT file_number, file_offset, block_size "
                "FROM blocks WHERE block_hash=?",
                (block_hash,)
            ).fetchone()

        if not row:
            return None

        file_num, offset, size = row
        block_bytes = self.block_files.read_block(file_num, offset, size)

        return Block.from_bytes(block_bytes)

    def get_block_at_height(self, height: int):
        """Retrieve block by height"""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT file_number, file_offset, block_size "
                "FROM blocks WHERE height=?",
                (height,)
            ).fetchone()

        if not row:
            return None

        file_num, offset, size = row
        block_bytes = self.block_files.read_block(file_num, offset, size)

        return Block.from_bytes(block_bytes)

    def get_chain_height(self) -> int:
        """Get current blockchain height"""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT MAX(height) FROM blocks").fetchone()
            return row[0] if row[0] is not None else -1

    def get_latest_block(self):
        """Get the tip of the blockchain"""
        height = self.get_chain_height()
        if height < 0:
            return None
        return self.get_block_at_height(height)

    # --- DB MAINTENANCE --- #
    def wipe_db(self):
        """Primarily used in testing"""
        self._clear_db()


# --- TESTING --- #
if __name__ == "__main__":
    test_db = BitCloneDatabase()

    test_utxo = UTXO(
        txid=b'deadbeef' * 8,
        vout=0,
        amount=0xfff,
        scriptpubkey=b'beefdead',
        block_height=1,
        is_coinbase=False
    )
    test_db.add_utxo(test_utxo)
