"""
The Database class - holds the UTXO set
"""
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from src.block.block import Block, BlockHeader
from src.core import get_logger
from src.data import bits_to_target
from src.database.bitcoin_core_rpc import BitcoinCoreRPC
from src.database.block_store import (
    ArchivalBlockStore,
    BitcoinCoreRemoteBlockStore,
    BlockLocation,
    BlockStore,
    PrunedBlockStore,
)
from src.tx.tx import Tx, UTXO

DB_PATH = Path(__file__).parent / "db_files" / "bitclone.db"

__all__ = ["BitCloneDatabase", "BlockIndexEntry", "BlockUndo", "DB_PATH", "calc_block_work"]
logger = get_logger(__name__)

MAX_TARGET_PLUS_ONE = 1 << 256
CHAINWORK_BYTES = 32
ARCHIVAL_STORAGE = "archival"
PRUNED_STORAGE = "pruned"
REMOTE_STORAGE = "bitcoin-core-remote"


@dataclass(frozen=True, slots=True)
class BlockUndo:
    spent_utxos: tuple[UTXO, ...]
    created_outpoints: tuple[bytes, ...]


class BlockIndexEntry:
    """
    Metadata for a block/header in the chain index.
    """
    __slots__ = ("block_hash", "prev_hash", "height", "bits", "timestamp", "work", "chainwork", "active", "status")

    def __init__(
            self,
            block_hash: bytes,
            prev_hash: bytes,
            height: int,
            bits: bytes,
            timestamp: int,
            work: int,
            chainwork: int,
            active: bool,
            status: str,
    ):
        self.block_hash = block_hash
        self.prev_hash = prev_hash
        self.height = height
        self.bits = bits
        self.timestamp = timestamp
        self.work = work
        self.chainwork = chainwork
        self.active = active
        self.status = status


def calc_block_work(bits: bytes) -> int:
    """
    Return the amount of chainwork represented by a block target.
    """
    target = int.from_bytes(bits_to_target(bits), "big")
    if target <= 0:
        return 0
    return MAX_TARGET_PLUS_ONE // (target + 1)


class BitCloneDatabase:
    def __init__(
            self,
            db_path=DB_PATH,
            testing=False,
            blocks_dir: Path | None = None,
            storage_mode: str = ARCHIVAL_STORAGE,
            prune_keep_blocks: int = 288,
            core_rpc: BitcoinCoreRPC | None = None,
    ):
        # --- Establish db path
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # --- testing bool
        self.testing = testing

        if storage_mode not in {ARCHIVAL_STORAGE, PRUNED_STORAGE, REMOTE_STORAGE}:
            raise ValueError(f"Unsupported block storage mode: {storage_mode}")
        if prune_keep_blocks < 1:
            raise ValueError("prune_keep_blocks must be at least 1")
        self.storage_mode = storage_mode
        self.prune_keep_blocks = prune_keep_blocks

        # --- Block body store
        blocks_dir = blocks_dir or self.db_path.parent / "blocks"
        if storage_mode == ARCHIVAL_STORAGE:
            self.block_store = ArchivalBlockStore(blocks_dir)
        elif storage_mode == PRUNED_STORAGE:
            self.block_store = PrunedBlockStore(blocks_dir)
        else:
            if core_rpc is None:
                raise ValueError("bitcoin-core-remote storage requires a Bitcoin Core RPC client")
            self.block_store = BitcoinCoreRemoteBlockStore(blocks_dir, core_rpc)
        # Compatibility for existing callers that inspect archival rollover.
        self.block_files = getattr(self.block_store, "manager", self.block_store)

        # --- Persistent connection
        self.conn: sqlite3.Connection | None = sqlite3.connect(self.db_path)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._initialize_database()
        try:
            self._validate_storage_mode()
        except Exception:
            self.conn.close()
            self.conn = None
            raise

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
                CREATE TABLE IF NOT EXISTS metadata
                (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                ) WITHOUT ROWID
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS block_undo_spent
                (
                    block_hash BLOB NOT NULL,
                    sequence INTEGER NOT NULL,
                    outpoint BLOB NOT NULL,
                    amount INTEGER NOT NULL,
                    script_pubkey BLOB NOT NULL,
                    height INTEGER NOT NULL,
                    coinbase INTEGER NOT NULL CHECK (coinbase IN (0, 1)),
                    PRIMARY KEY (block_hash, sequence)
                ) WITHOUT ROWID
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS block_undo_created
                (
                    block_hash BLOB NOT NULL,
                    sequence INTEGER NOT NULL,
                    outpoint BLOB NOT NULL,
                    PRIMARY KEY (block_hash, sequence)
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

            conn.execute("""
                CREATE TABLE IF NOT EXISTS block_index
                (
                    block_hash BLOB PRIMARY KEY,
                    prev_hash BLOB NOT NULL,
                    height INTEGER NOT NULL,
                    bits BLOB NOT NULL,
                    timestamp INTEGER NOT NULL,
                    work BLOB NOT NULL,
                    chainwork BLOB NOT NULL,
                    active INTEGER NOT NULL DEFAULT 0
                        CHECK (active IN (0, 1)),
                    status TEXT NOT NULL DEFAULT 'valid'
                ) WITHOUT ROWID
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_block_index_active_height
                ON block_index(active, height)
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_block_index_chainwork
                ON block_index(chainwork)
            """)

    def _clear_db(self) -> None:
        """Wipe the database and recreate a fresh schema."""
        conn = self._require_conn()
        with conn:
            conn.execute("DROP TABLE IF EXISTS utxos")
            conn.execute("DROP TABLE IF EXISTS blocks")
            conn.execute("DROP TABLE IF EXISTS block_index")
            conn.execute("DROP TABLE IF EXISTS block_undo_spent")
            conn.execute("DROP TABLE IF EXISTS block_undo_created")
            conn.execute("DROP TABLE IF EXISTS metadata")

        # Remove all .dat block files to keep storage in sync with the DB
        deleted = self.block_store.clear()
        logger.info(f"Cleared {deleted} block file(s) from disk).")

        self._initialize_database()
        self._validate_storage_mode()

    def _validate_storage_mode(self) -> None:
        conn = self._require_conn()
        row = conn.execute("SELECT value FROM metadata WHERE key = 'block_storage_mode'").fetchone()
        if row is not None:
            if row[0] != self.storage_mode:
                raise ValueError(
                    f"Database uses {row[0]!r} block storage and cannot be opened as {self.storage_mode!r}"
                )
            return

        block_count = conn.execute("SELECT COUNT(*) FROM blocks").fetchone()[0]
        if block_count and self.storage_mode != ARCHIVAL_STORAGE:
            raise ValueError("Existing block data must be migrated before enabling pruned storage")
        with conn:
            conn.execute(
                "INSERT INTO metadata(key, value) VALUES ('block_storage_mode', ?)",
                (self.storage_mode,),
            )

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
    def add_block(self, block: Block, block_height: int, undo: BlockUndo | None = None) -> None:
        """Add a block to storage."""
        block_bytes = block.to_bytes()
        location = self.block_store.write_block(block.block_id, block_bytes)

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
                    location.file_number,
                    location.file_offset,
                    location.block_size,
                ),
            )

            self._add_block_index_entry(block, block_height, active=True, conn=conn)
            if undo is not None:
                self._add_block_undo(header.block_id, undo, conn)

    @staticmethod
    def _add_block_undo(block_hash: bytes, undo: BlockUndo, conn: sqlite3.Connection) -> None:
        conn.executemany(
            """
            INSERT INTO block_undo_spent(
                block_hash, sequence, outpoint, amount, script_pubkey, height, coinbase
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    block_hash,
                    sequence,
                    utxo.outpoint,
                    utxo.amount,
                    utxo.scriptpubkey,
                    utxo.block_height,
                    1 if utxo.is_coinbase else 0,
                )
                for sequence, utxo in enumerate(undo.spent_utxos)
            ],
        )
        conn.executemany(
            "INSERT INTO block_undo_created(block_hash, sequence, outpoint) VALUES (?, ?, ?)",
            [
                (block_hash, sequence, outpoint)
                for sequence, outpoint in enumerate(undo.created_outpoints)
            ],
        )

    def get_block_undo(self, block_hash: bytes) -> BlockUndo | None:
        conn = self._require_conn()
        spent_rows = conn.execute(
            """
            SELECT outpoint, amount, script_pubkey, height, coinbase
            FROM block_undo_spent WHERE block_hash = ? ORDER BY sequence
            """,
            (block_hash,),
        ).fetchall()
        created_rows = conn.execute(
            "SELECT outpoint FROM block_undo_created WHERE block_hash = ? ORDER BY sequence",
            (block_hash,),
        ).fetchall()
        if not spent_rows and not created_rows:
            return None
        return BlockUndo(
            spent_utxos=tuple(
                UTXO(outpoint, amount, scriptpubkey, height, bool(coinbase))
                for outpoint, amount, scriptpubkey, height, coinbase in spent_rows
            ),
            created_outpoints=tuple(row[0] for row in created_rows),
        )

    def prune_blocks(self, tip_height: int) -> tuple[int, ...]:
        """Delete block bodies and undo data older than the configured safety window."""
        if self.storage_mode != PRUNED_STORAGE:
            return ()
        cutoff_height = tip_height - self.prune_keep_blocks
        if cutoff_height < 0:
            return ()

        conn = self._require_conn()
        rows = conn.execute(
            """
            SELECT height, block_hash, file_number, file_offset, block_size
            FROM blocks WHERE height <= ? ORDER BY height
            """,
            (cutoff_height,),
        ).fetchall()
        if not rows:
            return ()

        with conn:
            conn.executemany("DELETE FROM block_undo_spent WHERE block_hash = ?", [(row[1],) for row in rows])
            conn.executemany("DELETE FROM block_undo_created WHERE block_hash = ?", [(row[1],) for row in rows])
            conn.execute("DELETE FROM blocks WHERE height <= ?", (cutoff_height,))

        for _, _, file_number, file_offset, block_size in rows:
            self.block_store.delete_block(BlockLocation(file_number, file_offset, block_size))
        return tuple(row[0] for row in rows)

    def _add_block_index_entry(
            self,
            block: Block | BlockHeader,
            block_height: int,
            active: bool,
            conn: sqlite3.Connection | None = None,
            status: str = "valid",
    ) -> None:
        header = block.get_header() if isinstance(block, Block) else block
        conn = conn or self._require_conn()
        parent_entry = self.get_block_index(header.prev_block)
        work = calc_block_work(header.bits)
        parent_chainwork = parent_entry.chainwork if parent_entry is not None else 0
        chainwork = parent_chainwork + work

        conn.execute(
            """
            INSERT OR REPLACE INTO block_index (
                block_hash, prev_hash, height, bits, timestamp,
                work, chainwork, active, status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                header.block_id,
                header.prev_block,
                block_height,
                header.bits,
                header.timestamp,
                work.to_bytes(CHAINWORK_BYTES, "big"),
                chainwork.to_bytes(CHAINWORK_BYTES, "big"),
                1 if active else 0,
                status,
            ),
        )

    def add_block_index(self, block: Block, block_height: int, active: bool = False) -> None:
        """
        Add or update block/header metadata without writing full block data.
        """
        conn = self._require_conn()
        with conn:
            self._add_block_index_entry(block, block_height, active=active, conn=conn)

    def add_block_header(self, header: BlockHeader, block_height: int) -> None:
        """Persist a validated header without writing a full block body."""
        conn = self._require_conn()
        with conn:
            self._add_block_index_entry(
                header,
                block_height,
                active=False,
                conn=conn,
                status="headers-only",
            )

    def get_block_index(self, block_hash: bytes) -> BlockIndexEntry | None:
        conn = self._require_conn()
        row = conn.execute(
            """
            SELECT block_hash, prev_hash, height, bits, timestamp, work, chainwork, active, status
            FROM block_index
            WHERE block_hash = ?
            """,
            (block_hash,),
        ).fetchone()

        return self._row_to_block_index_entry(row)

    def get_best_header(self) -> BlockIndexEntry | None:
        conn = self._require_conn()
        row = conn.execute(
            """
            SELECT block_hash, prev_hash, height, bits, timestamp, work, chainwork, active, status
            FROM block_index
            ORDER BY chainwork DESC, height DESC
            LIMIT 1
            """
        ).fetchone()

        return self._row_to_block_index_entry(row)

    def get_block_index_ancestor(self, block_hash: bytes, height: int) -> BlockIndexEntry | None:
        """Walk a block-index branch back to its entry at ``height``."""
        entry = self.get_block_index(block_hash)
        if entry is None or height < 0 or height > entry.height:
            return None
        while entry.height > height:
            entry = self.get_block_index(entry.prev_hash)
            if entry is None:
                return None
        return entry

    def get_active_tip(self) -> BlockIndexEntry | None:
        conn = self._require_conn()
        row = conn.execute(
            """
            SELECT block_hash, prev_hash, height, bits, timestamp, work, chainwork, active, status
            FROM block_index
            WHERE active = 1
            ORDER BY height DESC
            LIMIT 1
            """
        ).fetchone()

        return self._row_to_block_index_entry(row)

    @staticmethod
    def _row_to_block_index_entry(row) -> BlockIndexEntry | None:
        if row is None:
            return None

        block_hash, prev_hash, height, bits, timestamp, work, chainwork, active, status = row
        return BlockIndexEntry(
            block_hash=block_hash,
            prev_hash=prev_hash,
            height=height,
            bits=bits,
            timestamp=timestamp,
            work=int.from_bytes(work, "big"),
            chainwork=int.from_bytes(chainwork, "big"),
            active=bool(active),
            status=status,
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

        location = BlockLocation(*row) if row is not None else None
        block_bytes = self.block_store.read_block(block_hash, location)
        if block_bytes is None:
            return None
        return Block.from_bytes(block_bytes)

    def get_block_at_height(self, height: int) -> Block | None:
        """Retrieve a block by height."""
        conn = self._require_conn()
        row = conn.execute(
            """
            SELECT block_hash, file_number, file_offset, block_size
            FROM blocks
            WHERE height = ?
            """,
            (height,),
        ).fetchone()

        if row is None:
            block_hash = self.block_store.get_block_hash(height)
            if block_hash is None:
                return None
            location = None
        else:
            block_hash, file_num, offset, size = row
            location = BlockLocation(file_num, offset, size)
        block_bytes = self.block_store.read_block(block_hash, location)
        if block_bytes is None:
            return None
        return Block.from_bytes(block_bytes)

    def get_remote_blockchain_info(self) -> dict | None:
        """Return source-node chain status when using a remote block store."""
        return self.block_store.get_blockchain_info()

    def get_remote_block_header(self, block_hash: bytes) -> BlockHeader | None:
        """Fetch a raw header from the remote source without a block body."""
        header_bytes = self.block_store.read_header(block_hash)
        return BlockHeader.from_bytes(header_bytes) if header_bytes is not None else None

    def get_chain_height(self) -> int:
        """Return the current blockchain height."""
        active_tip = self.get_active_tip()
        return active_tip.height if active_tip is not None else -1

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
