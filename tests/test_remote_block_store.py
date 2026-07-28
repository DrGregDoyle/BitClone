from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from src.api import NodeApplicationService
from src.block.block import Block
from src.blockchain.genesis_block import genesis_block
from src.cli import _handle_command
from src.config import BitCloneConfig, BlockStorageMode
from src.database.bitcoin_core_rpc import BitcoinCoreRPCError
from src.database.block_store import BitcoinCoreRemoteBlockStore
from src.database.database import BitCloneDatabase
from src.node.node import Node
from src.tx import Tx, TxIn, TxOut, UTXO


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
            "bestblockhash": blocks[-1].block_id[::-1].hex(),
            "verificationprogress": 0.999,
            "initialblockdownload": False,
            "pruned": False,
        }
        self.get_block = MagicMock(side_effect=lambda block_hash: self.blocks[block_hash])
        self.get_block_hash = MagicMock(side_effect=lambda height: self.heights[height])
        self.get_block_header = MagicMock(
            side_effect=lambda block_hash: Block.from_bytes(self.blocks[block_hash]).get_header().to_bytes()
        )
        self.get_blockchain_info = MagicMock(return_value=self.info)
        self.mempool = {}
        self.get_raw_mempool = MagicMock(
            side_effect=lambda verbose=False: self.mempool if verbose else list(self.mempool)
        )
        self.get_mempool_entry = MagicMock(
            side_effect=lambda txid: self.mempool[txid]
        )
        self.get_raw_transaction = MagicMock(
            side_effect=lambda txid, verbose=False: {"txid": txid} if verbose else "00"
        )
        self.tx_outs = {}
        self.block_header_infos = {}
        self.get_tx_out = MagicMock(
            side_effect=lambda txid, vout: self.tx_outs.get((txid, vout))
        )
        self.get_block_header_info = MagicMock(
            side_effect=lambda display_hash: self.block_header_infos[display_hash]
        )


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


def test_remote_mode_delegates_utxo_lookup_and_converts_core_data(tmp_path):
    rpc = FakeCoreRPC([genesis_block])
    txid = bytes(range(32))
    vout = 7
    outpoint = txid + vout.to_bytes(4, "little")
    bestblock = "11" * 32
    rpc.tx_outs[(txid, vout)] = {
        "bestblock": bestblock,
        "confirmations": 6,
        "value": 1.23456789,
        "scriptPubKey": {"hex": "0014" + "22" * 20},
        "coinbase": True,
    }
    rpc.block_header_infos[bestblock] = {"height": 100}
    db = BitCloneDatabase(
        tmp_path / "chain.db",
        storage_mode="bitcoin-core-remote",
        core_rpc=rpc,
    )
    try:
        utxo = db.get_utxo(outpoint)

        assert utxo == UTXO(
            outpoint=outpoint,
            amount=123_456_789,
            scriptpubkey=bytes.fromhex("0014" + "22" * 20),
            block_height=95,
            is_coinbase=True,
        )
        rpc.get_tx_out.assert_called_once_with(txid, vout)
        rpc.get_block_header_info.assert_called_once_with(bestblock)
    finally:
        db.close()


def test_remote_mode_does_not_fall_back_to_incomplete_local_utxo_set(tmp_path):
    rpc = FakeCoreRPC([genesis_block])
    txid = b"\x33" * 32
    outpoint = txid + (1).to_bytes(4, "little")
    db = BitCloneDatabase(
        tmp_path / "chain.db",
        storage_mode="bitcoin-core-remote",
        core_rpc=rpc,
    )
    try:
        db.add_utxo(UTXO(outpoint, 50_000, b"\x51", 1))

        assert db.get_utxo(outpoint) is None
        rpc.get_tx_out.assert_called_once_with(txid, 1)
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


def test_remote_mode_exposes_trusted_bitcoin_core_mempool(tmp_path):
    txid = "22" * 32
    rpc = FakeCoreRPC([genesis_block])
    rpc.mempool[txid] = {
        "vsize": 141,
        "time": 1_700_000_000,
        "ancestorcount": 2,
        "descendantcount": 3,
        "fees": {"base": 0.00001410},
    }
    config = BitCloneConfig.from_options(
        data_dir=tmp_path,
        block_storage="bitcoin-core-remote",
        core_rpc_url="http://Skyscraper:8332",
        core_rpc_user="bitclone",
        core_rpc_password="secret",
    )
    node = Node(config=config, core_rpc=rpc)
    service = NodeApplicationService(node)
    try:
        collection = service.list_mempool({}, {"limit": ["50"], "offset": ["0"]})
        detail = service.get_mempool_transaction({"txid": txid}, {})
        compatibility = service.dispatch_rpc("getrawmempool", [True])

        assert collection["source"] == {
            "type": "bitcoin-core-remote",
            "trust": "trusted-remote",
            "independently_validated": False,
        }
        assert collection["page"]["total"] == 1
        assert collection["items"][0] == {
            "txid": txid,
            "fee_sats": 1410,
            "virtual_size_vbytes": 141,
            "feerate_sats_per_vbyte": 10.0,
            "arrival_at": "2023-11-14T22:13:20Z",
            "ancestor_count": 2,
            "descendant_count": 3,
        }
        assert detail["transaction"] == {"txid": txid}
        assert detail["source"]["trust"] == "trusted-remote"
        assert compatibility == rpc.mempool
        rpc.get_raw_mempool.assert_any_call(True)
    finally:
        node.close()


@pytest.mark.parametrize(
    ("network", "core_chain"),
    [
        ("mainnet", "main"),
        ("testnet", "test"),
        ("regtest", "regtest"),
        ("signet", "signet"),
    ],
)
def test_remote_mode_accepts_matching_bitcoin_core_network(tmp_path, network, core_chain):
    rpc = FakeCoreRPC([genesis_block])
    rpc.info["chain"] = core_chain
    config = BitCloneConfig.from_options(
        data_dir=tmp_path,
        network=network,
        block_storage="bitcoin-core-remote",
        core_rpc_url="http://Skyscraper:8332",
        core_rpc_user="bitclone",
        core_rpc_password="secret",
    )

    node = Node(config=config, core_rpc=rpc)
    try:
        assert node.status()["remote_source"]["chain"] == core_chain
    finally:
        node.close()


def test_remote_mode_rejects_bitcoin_core_network_mismatch(tmp_path):
    rpc = FakeCoreRPC([genesis_block])
    rpc.info["chain"] = "regtest"
    config = BitCloneConfig.from_options(
        data_dir=tmp_path,
        network="mainnet",
        block_storage="bitcoin-core-remote",
        core_rpc_url="http://Skyscraper:8332",
        core_rpc_user="bitclone",
        core_rpc_password="secret",
    )

    with pytest.raises(
            ValueError,
            match="Bitcoin Core network mismatch: BitClone=mainnet, Core=regtest",
    ):
        Node(config=config, core_rpc=rpc)


def test_node_status_reports_normalized_remote_source_health_and_trust(tmp_path, capsys):
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
        status = node.status()
        assert status["block_data"] == {
            "source": "bitcoin-core-remote",
            "trust": "trusted-remote",
            "independently_validated": False,
        }
        assert status["utxo_count"] is None
        assert status["remote_source"] == {
            "reachable": True,
            "chain": "main",
            "tip_height": 1,
            "tip_hash": rpc.info["bestblockhash"],
            "verification_progress": 0.999,
            "pruned": False,
            "trust": "trusted-remote",
            "error": None,
        }
        node.print_info()
        assert "UTXO Count:        remote" in capsys.readouterr().out
    finally:
        node.close()


def test_node_status_reports_unreachable_remote_source_without_failing(tmp_path):
    rpc = FakeCoreRPC([genesis_block])
    rpc.get_blockchain_info.side_effect = BitcoinCoreRPCError(
        "Bitcoin Core RPC unavailable: connection refused"
    )
    config = BitCloneConfig.from_options(
        data_dir=tmp_path,
        block_storage="bitcoin-core-remote",
        core_rpc_url="http://Skyscraper:8332",
        core_rpc_user="bitclone",
        core_rpc_password="secret",
    )
    node = Node(config=config, core_rpc=rpc)
    try:
        assert node.status()["remote_source"] == {
            "reachable": False,
            "chain": None,
            "tip_height": None,
            "tip_hash": None,
            "verification_progress": None,
            "pruned": None,
            "trust": "trusted-remote",
            "error": "Bitcoin Core RPC unavailable: connection refused",
        }
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


def test_remote_gettxout_cli_command_delegates_to_core(tmp_path):
    rpc = FakeCoreRPC([genesis_block])
    txid = b"\x44" * 32
    bestblock = "55" * 32
    rpc.tx_outs[(txid, 2)] = {
        "bestblock": bestblock,
        "confirmations": 2,
        "value": 0.00001001,
        "scriptPubKey": {"hex": "51"},
        "coinbase": False,
    }
    rpc.block_header_infos[bestblock] = {"height": 20}
    config = BitCloneConfig.from_options(
        data_dir=tmp_path,
        block_storage="bitcoin-core-remote",
        core_rpc_url="http://Skyscraper:8332",
        core_rpc_user="bitclone",
        core_rpc_password="secret",
    )
    node = Node(config=config, core_rpc=rpc)
    try:
        result = _handle_command(
            node,
            SimpleNamespace(command="gettxout", txid=txid[::-1].hex(), vout=2),
        )

        assert result == {
            "found": True,
            "utxo": {
                "outpoint": (txid + (2).to_bytes(4, "little")).hex(),
                "txid": txid[::-1].hex(),
                "vout": 2,
                "amount": 1001,
                "scriptpubkey": "51",
                "block_height": 19,
                "is_coinbase": False,
            },
        }
    finally:
        node.close()
