"""
DB class. Handles Txs, UTXOs and Blocks
"""

import sqlite3
from pathlib import Path

# Database file path
DB_PATH = Path(__file__).parent / "bitclone_db" / "bitclone.db"


class BitCloneDatabase:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._initialize_database()

    def _initialize_database(self):
        """Creates necessary tables if they do not exist."""
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()

            # UTXO Table
            c.execute('''
                CREATE TABLE IF NOT EXISTS utxos (
                    txid TEXT NOT NULL,
                    vout INTEGER NOT NULL,
                    address TEXT NOT NULL,
                    amount INTEGER NOT NULL,
                    script_pubkey TEXT NOT NULL,
                    spent INTEGER DEFAULT 0,
                    PRIMARY KEY (txid, vout)
                )
            ''')

            # Blocks Table
            c.execute('''
                CREATE TABLE IF NOT EXISTS blocks (
                    height INTEGER PRIMARY KEY,
                    block_hash BLOB UNIQUE NOT NULL,
                    prev_hash BLOB NOT NULL,
                    timestamp INTEGER NOT NULL,
                    merkle_root BLOB NOT NULL,
                    nonce INTEGER NOT NULL
                )
            ''')

            # Transactions Table
            c.execute('''
                CREATE TABLE IF NOT EXISTS transactions (
                    txid TEXT PRIMARY KEY,
                    block_hash TEXT,
                    timestamp INTEGER NOT NULL,
                    FOREIGN KEY (block_hash) REFERENCES blocks (block_hash)
                )
            ''')

            # Index for faster UTXO lookups
            c.execute("CREATE INDEX IF NOT EXISTS utxo_address_idx ON utxos(address)")
            conn.commit()

    def _clear_db(self):
        """Wipes the database and creates a fresh one."""
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute("DROP TABLE IF EXISTS utxos")
            c.execute("DROP TABLE IF EXISTS blocks")
            c.execute("DROP TABLE IF EXISTS transactions")
            conn.commit()
        self._initialize_database()

    def add_utxo(self, txid, vout, address, amount, script_pubkey):
        """Adds a new UTXO to the database."""
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            try:
                c.execute("""
                    INSERT INTO utxos (txid, vout, address, amount, script_pubkey, spent)
                    VALUES (?, ?, ?, ?, ?, 0)
                """, (txid, vout, address, amount, script_pubkey))
                conn.commit()
            except sqlite3.IntegrityError:
                print(f"UTXO {txid}:{vout} already exists.")

    def spend_utxo(self, txid, vout):
        """Marks a UTXO as spent."""
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute("UPDATE utxos SET spent = 1 WHERE txid = ? AND vout = ?", (txid, vout))
            conn.commit()

    def get_unspent_utxos(self, address):
        """Returns all unspent UTXOs for a given address."""
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute("SELECT txid, vout, amount, script_pubkey FROM utxos WHERE address = ? AND spent = 0", (address,))
            return c.fetchall()

    def add_block(self, height, block_hash, prev_hash, timestamp, merkle_root, nonce):
        """Adds a new block to the database."""
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO blocks (height, block_hash, prev_hash, timestamp, merkle_root, nonce)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (height, block_hash, prev_hash, timestamp, merkle_root, nonce))
            conn.commit()

    def add_transaction(self, txid, block_hash, timestamp):
        """Adds a transaction to the transactions table."""
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO transactions (txid, block_hash, timestamp)
                VALUES (?, ?, ?)
            """, (txid, block_hash, timestamp))
            conn.commit()

    def get_block_by_hash(self, block_hash):
        """Returns a block given its hash."""
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM blocks WHERE block_hash = ?", (block_hash,))
            return c.fetchone()

    def get_latest_block(self):
        """Returns the latest block in the blockchain."""
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM blocks ORDER BY height DESC LIMIT 1")
            return c.fetchone()

    def get_transaction(self, txid):
        """Returns a transaction by txid."""
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM transactions WHERE txid = ?", (txid,))
            return c.fetchone()

    def get_block_height(self):
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute("""
                SELECT COUNT(*) FROM blocks
            """)
            return c.fetchone()[0]
