from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from src.block.block import Block
from src.blockchain.genesis_block import genesis_block
from src.cli import _handle_command
from src.config import BitCloneConfig, BlockStorageMode
from src.database.block_store import BitcoinCoreRemoteBlockStore
from src.database.database import BitCloneDatabase
from src.node.node import Node
from src.tx import Tx, TxIn, TxOut


def _coinbase() -> Tx:
    return Tx(
        inputs=[TxIn(b"\x00" * 32, 0xffffffff, b"\x02\x01\x00", 0xffffffff)],
        outputs=[TxOut(5_000_000_000, b"\x51")],
    )


def _block() -> Block:
    return Block(
        prev_block=genesis_block.block_id,
        timestamp=genesis_block.timestamp + 1,
        bits=genesis_block.bits,
        nonce=1,
        txs=[_coinbase()],
    )


class FakeCoreRPC:
    def __init__(self, blocks: list[Block]):
        self.blocks = {block.block_id: block.to_bytes() for block in blocks}
        self.heights = {height: block.block_id for height, block in enumerate(blocks)}
        self.info = {
            "chain": "main",
            "blocks": len(blocks) - 1,
            "headers": len(blocks) - 1,
            "initialblockdownload": False,
            "pruned": False,
        }
        self.get_block = MagicMock(side_effect=lambda block_hash: self.blocks[block_hash])
        self.get_block_hash = MagicMock(side_effect=lambda height: self.heights[height])
        self.get_block_header = MagicMock(
            side_effect=lambda block_hash: Block.from_bytes(self.blocks[block_hash]).get_header().to_bytes()
        )
        self.get_blockchain_info = MagicMock(return_value=self.info)


def test_remote_store_reads_by_hash_and_height_without_local_block_files(tmp_path):
    block = _block()
    rpc = FakeCoreRPC([genesis_block, block])
    blocks_dir = tmp_path / "blocks"
    db = BitCloneDatabase(
        tmp_path / "chain.db",
        blocks_dir=blocks_dir,
        storage_mode="bitcoin-core-remote",
        core_rpc=rpc,
    )
    try:
        assert isinstance(db.block_store, BitcoinCoreRemoteBlockStore)
        assert db.get_block(block.block_id).block_id == block.block_id
        assert db.get_block_at_height(1).block_id == block.block_id
        assert db.get_remote_block_header(block.block_id).block_id == block.block_id
        assert db.get_remote_blockchain_info() == rpc.info
        assert list(blocks_dir.glob("blk*.dat")) == []
    finally:
        db.close()


def test_remote_store_records_connected_metadata_without_writing_body(tmp_path):
    block = _block()
    rpc = FakeCoreRPC([genesis_block, block])
    blocks_dir = tmp_path / "blocks"
    db = BitCloneDatabase(
        tmp_path / "chain.db",
        blocks_dir=blocks_dir,
        storage_mode="bitcoin-core-remote",
        core_rpc=rpc,
    )
    try:
        db.add_block(block, 1)

        row = db.conn.execute(
            "SELECT file_number, file_offset, block_size FROM blocks WHERE block_hash = ?",
            (block.block_id,),
        ).fetchone()
        assert row == (-1, 0, len(block.to_bytes()))
        assert list(blocks_dir.glob("blk*.dat")) == []
        assert db.get_block(block.block_id).block_id == block.block_id
    finally:
        db.close()


def test_remote_mode_requires_rpc_client_and_cannot_reopen_as_archival(tmp_path):
    db_path = tmp_path / "chain.db"
    with pytest.raises(ValueError, match="RPC client"):
        BitCloneDatabase(db_path, storage_mode="bitcoin-core-remote")

    rpc = FakeCoreRPC([genesis_block])
    db = BitCloneDatabase(db_path, storage_mode="bitcoin-core-remote", core_rpc=rpc)
    db.close()
    with pytest.raises(ValueError, match="cannot be opened"):
        BitCloneDatabase(db_path, storage_mode="archival")


def test_node_remote_mode_queries_core_without_starting_ibd(tmp_path):
    rpc = FakeCoreRPC([genesis_block, _block()])
    config = BitCloneConfig.from_options(
        data_dir=tmp_path,
        block_storage="bitcoin-core-remote",
        core_rpc_url="http://Skyscraper:8332",
        core_rpc_user="bitclone",
        core_rpc_password="secret",
    )
    node = Node(config=config, core_rpc=rpc)
    try:
        assert node.config.block_storage is BlockStorageMode.BITCOIN_CORE_REMOTE
        assert node.remote_blockchain_info() == rpc.info
        assert node.blockchain.get_block_at_height(1).block_id == rpc.heights[1]
        assert node.blockchain.height == 0
        assert list(config.blocks_dir.glob("blk*.dat")) == []
    finally:
        node.close()


def test_remote_config_never_serializes_password(tmp_path):
    config = BitCloneConfig.from_options(
        data_dir=tmp_path,
        block_storage="bitcoin-core-remote",
        core_rpc_url="http://Skyscraper:8332",
        core_rpc_user="bitclone",
        core_rpc_password="do-not-write-this",
    )

    config.initialize()

    assert "core_rpc_password" not in config.to_data()
    assert "do-not-write-this" not in config.config_path.read_text(encoding="utf-8")


def test_remote_chain_info_cli_command_delegates_without_ibd(tmp_path):
    rpc = FakeCoreRPC([genesis_block])
    config = BitCloneConfig.from_options(
        data_dir=tmp_path,
        block_storage="bitcoin-core-remote",
        core_rpc_url="http://Skyscraper:8332",
        core_rpc_user="bitclone",
        core_rpc_password="secret",
    )
    node = Node(config=config, core_rpc=rpc)
    try:
        result = _handle_command(node, SimpleNamespace(command="getremotechaininfo"))

        assert result == {"configured": True, "blockchain": rpc.info}
        assert node.blockchain.height == 0
    finally:
        node.close()
