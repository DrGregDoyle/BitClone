"""
The Database class - holds the UTXO set
"""
import sqlite3
from pathlib import Path

from src.tx import UTXO

DB_PATH = Path(__file__).parent / "db_files" / "bitclone.db"

__all__ = ["BitCloneDatabase"]


class BitCloneDatabase:
    def __init__(self, db_path=DB_PATH, testing=False):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)  # Make sure file folder exists
        self._initialize_database()

    def _initialize_database(self):
        """Creates necessary tables if they do not exist."""
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute('''
                CREATE TABLE IF NOT EXISTS utxos (
                    outpoint      BLOB    NOT NULL,   -- 36 bytes
                    amount        INTEGER NOT NULL,   -- satoshis
                    script_pubkey BLOB    NOT NULL,   -- raw bytes
                    height        INTEGER NOT NULL,
                    coinbase      INTEGER NOT NULL DEFAULT 0 CHECK (coinbase IN (0,1)),
                    PRIMARY KEY (outpoint)
                ) WITHOUT ROWID
            ''')
            conn.commit()

    def _clear_db(self):
        """Wipes the database and creates a fresh one."""
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute("DROP TABLE IF EXISTS utxos")
            conn.commit()
        self._initialize_database()

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
        return UTXO(txid_b, vout_i, amt, spk, h, False if cb else True)

    def remove_utxo(self, outpoint: bytes):
        """Remove a UTXO from the set"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "DELETE FROM utxos WHERE outpoint=?",
                (outpoint,),
            )
            conn.commit()

    def wipe_db(self):
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
