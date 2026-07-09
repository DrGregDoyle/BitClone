from unittest.mock import MagicMock

from src.block.block import Block
from src.core import MAGICBYTES
from src.node.node import Node
from src.tx.tx import Tx, TxIn, TxOut


def _coinbase_tx() -> Tx:
    return Tx(
        inputs=[TxIn(b"\x00" * 32, 0xffffffff, b"\x01\x01", 0xffffffff)],
        outputs=[TxOut(1, b"\x51")],
    )


def test_node_initializes_components_with_shared_db_path(tmp_path):
    db_path = tmp_path / "node.db"
    node = Node(db_path=db_path)

    try:
        assert node.blockchain.db.db_path == db_path
        assert node.mempool.btcdb.db_path == db_path
        assert node.wallet is None
        assert node.miner is not None
        assert node.transport is not None
        assert node.transport.magic_bytes == MAGICBYTES.MAINNET
    finally:
        node.close()


def test_node_status_returns_structured_runtime_data(tmp_path):
    node = Node(db_path=tmp_path / "node.db")

    try:
        status = node.status()

        assert status["started"] is False
        assert status["height"] == node.blockchain.height
        assert status["tip"] == node.blockchain.tip.block_id[::-1].hex()
        assert status["utxo_count"] == node.blockchain.utxo_count()
        assert status["mempool_size"] == 0
        assert status["bits"] == node.blockchain.bits.hex()
        assert status["magic_bytes"] == MAGICBYTES.MAINNET.hex()
        assert status["mining"] is False
    finally:
        node.close()


def test_node_uses_configured_network_magic(tmp_path):
    node = Node(data_dir=tmp_path, network="regtest")

    try:
        assert node.config.magic_bytes == MAGICBYTES.REGTEST
        assert node.transport.magic_bytes == MAGICBYTES.REGTEST
        assert node.status()["magic_bytes"] == MAGICBYTES.REGTEST.hex()
    finally:
        node.close()


def test_submit_tx_delegates_to_mempool(tmp_path):
    node = Node(db_path=tmp_path / "node.db")
    tx = _coinbase_tx()
    node.mempool.add_tx = MagicMock(return_value=True)

    try:
        assert node.submit_tx(tx)
        node.mempool.add_tx.assert_called_once_with(tx)
    finally:
        node.close()


def test_submit_block_confirms_mempool_transactions_after_acceptance(tmp_path):
    node = Node(db_path=tmp_path / "node.db")
    block = Block(prev_block=node.blockchain.tip.block_id, bits=node.blockchain.bits, txs=[_coinbase_tx()])
    node.blockchain.add_block = MagicMock(return_value=True)
    node.mempool.confirm_block = MagicMock()

    try:
        assert node.submit_block(block)
        node.blockchain.add_block.assert_called_once_with(block)
        node.mempool.confirm_block.assert_called_once_with([tx.txid for tx in block.txs])
    finally:
        node.close()


def test_build_block_template_uses_chain_tip_bits_and_mempool_selection(tmp_path):
    node = Node(db_path=tmp_path / "node.db")
    node.mempool.get_block_template = MagicMock(return_value=[])

    try:
        template = node.build_block_template()

        assert template.prev_block == node.blockchain.tip.block_id
        assert template.bits == node.blockchain.bits
        assert len(template.txs) == 1
        assert template.txs[0].is_coinbase
        node.mempool.get_block_template.assert_called_once_with()
    finally:
        node.close()
