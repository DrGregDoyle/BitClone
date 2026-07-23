import pytest

from src.block.block import Block
from src.blockchain.blockchain import Blockchain
from src.database.block_store import ArchivalBlockStore, PrunedBlockStore
from src.database.database import BitCloneDatabase, BlockUndo
from src.tx import Tx, TxIn, TxOut, UTXO


def _coinbase(height: int) -> Tx:
    return Tx(
        inputs=[TxIn(b"\x00" * 32, 0xffffffff, b"\x02" + height.to_bytes(1, "little") + b"\x00", 0xffffffff)],
        outputs=[TxOut(50_0000_0000, b"\x51")],
    )


def _block(previous_hash: bytes, height: int) -> Block:
    return Block(
        version=4,
        prev_block=previous_hash,
        timestamp=1_700_000_000 + height,
        bits=bytes.fromhex("207fffff"),
        nonce=height,
        txs=[_coinbase(height)],
    )


def _store_chain(db: BitCloneDatabase, count: int) -> list[Block]:
    blocks = []
    previous_hash = b"\x00" * 32
    for height in range(count):
        block = _block(previous_hash, height)
        undo = BlockUndo((), (block.txs[0].txid + (0).to_bytes(4, "little"),))
        db.add_block(block, height, undo=undo)
        db.prune_blocks(height)
        blocks.append(block)
        previous_hash = block.block_id
    return blocks


def test_archival_store_remains_default_and_never_prunes(tmp_path):
    db = BitCloneDatabase(tmp_path / "chain.db", blocks_dir=tmp_path / "blocks")
    try:
        blocks = _store_chain(db, 4)

        assert isinstance(db.block_store, ArchivalBlockStore)
        assert db.prune_blocks(10_000) == ()
        assert all(db.get_block_at_height(height) is not None for height in range(4))
        assert db.get_block_undo(blocks[0].block_id) is not None
    finally:
        db.close()


def test_pruned_store_keeps_recent_window_and_full_header_index(tmp_path):
    db_path = tmp_path / "chain.db"
    blocks_dir = tmp_path / "blocks"
    db = BitCloneDatabase(
        db_path,
        blocks_dir=blocks_dir,
        storage_mode="pruned",
        prune_keep_blocks=2,
    )
    blocks = _store_chain(db, 5)
    db.close()

    reopened = BitCloneDatabase(
        db_path,
        blocks_dir=blocks_dir,
        storage_mode="pruned",
        prune_keep_blocks=2,
    )
    try:
        assert isinstance(reopened.block_store, PrunedBlockStore)
        assert [reopened.get_block_at_height(height) for height in range(3)] == [None, None, None]
        assert reopened.get_block_at_height(3).block_id == blocks[3].block_id
        assert reopened.get_block_at_height(4).block_id == blocks[4].block_id
        assert all(reopened.get_block_index(block.block_id) is not None for block in blocks)
        assert reopened.get_block_undo(blocks[2].block_id) is None
        assert reopened.get_block_undo(blocks[3].block_id) is not None
        assert len(list(blocks_dir.glob("blk*.dat"))) == 2
        assert reopened.get_chain_height() == 4
        assert reopened.get_latest_block().block_id == blocks[4].block_id
    finally:
        reopened.close()


def test_storage_mode_marker_prevents_reopening_with_incompatible_store(tmp_path):
    db_path = tmp_path / "chain.db"
    blocks_dir = tmp_path / "blocks"
    db = BitCloneDatabase(db_path, blocks_dir=blocks_dir, storage_mode="pruned", prune_keep_blocks=2)
    db.close()

    with pytest.raises(ValueError, match="cannot be opened"):
        BitCloneDatabase(db_path, blocks_dir=blocks_dir, storage_mode="archival")


def test_undo_roundtrip_preserves_spent_utxos_and_created_outpoints(tmp_path):
    db = BitCloneDatabase(
        tmp_path / "chain.db",
        blocks_dir=tmp_path / "blocks",
        storage_mode="pruned",
        prune_keep_blocks=2,
    )
    spent = UTXO(b"\x11" * 36, 42_000, b"\x51", 7, True)
    created = (b"\x22" * 36, b"\x33" * 36)
    block = _block(b"\x00" * 32, 0)
    try:
        db.add_block(block, 0, undo=BlockUndo((spent,), created))

        assert db.get_block_undo(block.block_id) == BlockUndo((spent,), created)
    finally:
        db.close()


def test_block_undo_excludes_outputs_created_and_spent_inside_same_block(tmp_path):
    chain = Blockchain(db_path=tmp_path / "chain.db")
    funding = UTXO(b"\x44" * 32 + (0).to_bytes(4, "little"), 100_000, b"\x51", 0)
    chain.db.add_utxo(funding)
    parent = Tx(
        inputs=[TxIn(funding.outpoint[:32], funding.outpoint[32:], b"", 0xffffffff)],
        outputs=[TxOut(90_000, b"\x51")],
    )
    parent_outpoint = parent.txid + (0).to_bytes(4, "little")
    child = Tx(
        inputs=[TxIn(parent.txid, 0, b"", 0xffffffff)],
        outputs=[TxOut(80_000, b"\x51")],
    )
    block = Block(prev_block=chain.tip.block_id, txs=[_coinbase(1), parent, child])
    try:
        undo = chain._build_block_undo(block)

        assert undo.spent_utxos == (funding,)
        assert parent_outpoint in undo.created_outpoints
        assert all(utxo.outpoint != parent_outpoint for utxo in undo.spent_utxos)
    finally:
        chain.close()


def test_blockchain_connection_automatically_prunes_beyond_window(tmp_path):
    chain = Blockchain(
        db_path=tmp_path / "chain.db",
        blocks_dir=tmp_path / "blocks",
        storage_mode="pruned",
        prune_keep_blocks=2,
    )
    chain._validate_block = lambda block: True
    connected = []
    try:
        for height in range(1, 4):
            block = _block(chain.tip.block_id, height)
            assert chain.add_block(block)
            connected.append(block)

        assert chain.height == 3
        assert chain.get_block_at_height(0) is None
        assert chain.get_block_at_height(1) is None
        assert chain.get_block_at_height(2).block_id == connected[1].block_id
        assert chain.get_block_at_height(3).block_id == connected[2].block_id
        assert chain.db.get_block_undo(connected[0].block_id) is None
        assert chain.db.get_block_undo(connected[1].block_id) is not None
    finally:
        chain.close()
