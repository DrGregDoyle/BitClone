from unittest.mock import MagicMock

import pytest

from src.block.block import Block
from src.core import MAGICBYTES, NETWORK
from src.network.datatypes.network_types import PeerState, Services
from src.network.messages.ctrl_msg import Version
from src.node.node import Node
from src.tx.tx import Tx, TxIn, TxOut

FAKE_ENDPOINT = "192.0.2.10"
EPHEMERAL_PORT = 49152
KNOWN_TEST_ENDPOINT = "198.51.100.20"
ALTERNATE_TEST_ENDPOINT = "198.51.100.21"
FIXED_TIMESTAMP = 1_700_000_000
FIXED_NONCE = 123456789
FIRST_NONCE = 11
SECOND_NONCE = 22


class _RecordingSocket:
    def __init__(self, *, connect_error=None, send_error=None):
        self.connect_error = connect_error
        self.send_error = send_error
        self.connected_to = None
        self.sent = []
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, endpoint):
        if self.connect_error:
            raise self.connect_error
        self.connected_to = endpoint

    def getsockname(self):
        return FAKE_ENDPOINT, EPHEMERAL_PORT

    def sendall(self, data):
        if self.send_error:
            raise self.send_error
        self.sent.append(data)

    def close(self):
        self.closed = True


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


def test_connect_peer_sends_version_first_with_node_state(monkeypatch, tmp_path):
    fake_socket = _RecordingSocket()
    monkeypatch.setattr("src.network.transport.socket.socket", lambda *args, **kwargs: fake_socket)
    monkeypatch.setattr("src.node.node.time.time", lambda: FIXED_TIMESTAMP)
    monkeypatch.setattr("src.node.node.secrets.randbits", lambda bits: FIXED_NONCE)
    node = Node(data_dir=tmp_path, network="regtest")

    try:
        peer = node.connect_peer(KNOWN_TEST_ENDPOINT, NETWORK.REGTEST_PORT)
        version = Version.from_bytes(fake_socket.sent[0])

        assert len(fake_socket.sent) == 1
        assert fake_socket.sent[0][:4] == MAGICBYTES.REGTEST
        assert peer.state is PeerState.HANDSHAKING
        assert peer.local_nonce == FIXED_NONCE
        assert version.protocol_version == NETWORK.PROTOCOL_VERSION
        assert version.services is Services.UNNAMED
        assert version.timestamp == FIXED_TIMESTAMP
        assert version.remote_net_addr.to_data()["ip_addr"] == KNOWN_TEST_ENDPOINT
        assert version.remote_net_addr.port == NETWORK.REGTEST_PORT
        assert version.local_net_addr.to_data()["ip_addr"] == FAKE_ENDPOINT
        assert version.local_net_addr.port == EPHEMERAL_PORT
        assert version.nonce == peer.local_nonce
        assert version.user_agent == NETWORK.USER_AGENT
        assert version.last_block == node.blockchain.height
    finally:
        node.close()


def test_connect_peer_uses_fresh_nonce_for_each_handshake(monkeypatch, tmp_path):
    sockets = [_RecordingSocket(), _RecordingSocket()]
    nonces = iter([FIRST_NONCE, SECOND_NONCE])
    monkeypatch.setattr("src.network.transport.socket.socket", lambda *args, **kwargs: sockets.pop(0))
    monkeypatch.setattr("src.node.node.secrets.randbits", lambda bits: next(nonces))
    node = Node(data_dir=tmp_path)

    try:
        first_peer = node.connect_peer(KNOWN_TEST_ENDPOINT, NETWORK.MAINNET_PORT)
        second_peer = node.connect_peer(ALTERNATE_TEST_ENDPOINT, NETWORK.MAINNET_PORT)

        assert first_peer.local_nonce == FIRST_NONCE
        assert second_peer.local_nonce == SECOND_NONCE
    finally:
        node.close()


def test_connect_peer_disconnects_and_records_send_failure(monkeypatch, tmp_path):
    fake_socket = _RecordingSocket(send_error=OSError("send failed"))
    monkeypatch.setattr("src.network.transport.socket.socket", lambda *args, **kwargs: fake_socket)
    node = Node(data_dir=tmp_path)
    captured_peer = None
    original_connect = node.transport.connect

    def capture_connect(peer):
        nonlocal captured_peer
        captured_peer = peer
        original_connect(peer)

    monkeypatch.setattr(node.transport, "connect", capture_connect)

    try:
        with pytest.raises(OSError, match="send failed"):
            node.connect_peer(KNOWN_TEST_ENDPOINT, NETWORK.MAINNET_PORT)

        assert captured_peer.state is PeerState.DISCONNECTED
        assert captured_peer.fail_count == 1
        assert captured_peer.last_fail is not None
        assert fake_socket.closed
    finally:
        node.close()


def test_connect_peer_preserves_transport_connect_failure_state(monkeypatch, tmp_path):
    fake_socket = _RecordingSocket(connect_error=OSError("connect failed"))
    monkeypatch.setattr("src.network.transport.socket.socket", lambda *args, **kwargs: fake_socket)
    node = Node(data_dir=tmp_path)
    captured_peer = None
    original_connect = node.transport.connect

    def capture_connect(peer):
        nonlocal captured_peer
        captured_peer = peer
        original_connect(peer)

    monkeypatch.setattr(node.transport, "connect", capture_connect)

    try:
        with pytest.raises(ConnectionError, match="Failed to connect"):
            node.connect_peer(KNOWN_TEST_ENDPOINT, NETWORK.MAINNET_PORT)

        assert captured_peer.state is PeerState.DISCONNECTED
        assert captured_peer.fail_count == 1
        assert captured_peer.last_fail is not None
        assert fake_socket.sent == []
        assert fake_socket.closed
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
