from unittest.mock import MagicMock

import pytest

from src.block.block import Block
from src.core import MAGICBYTES, NETWORK, NetworkError
from src.network.datatypes.network_data import NetAddr
from src.network.datatypes.network_types import PeerState, Services
from src.network.messages.ctrl_msg import GetAddr, Ping, SendAddrV2, VerAck, Version, WtxidRelay
from src.network.messages.message import UnknownMessage
from src.network.peer_address_book import PeerSource
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
PEER_NONCE = 987654321
PEER_USER_AGENT = "/Satoshi:test/"
PEER_BLOCK_HEIGHT = 850_000
PEER_SERVICES = Services.NODE_NETWORK | Services.NODE_WITNESS
BELOW_MIN_PROTOCOL_VERSION = NETWORK.MIN_PROTOCOL_VERSION - 1


class _RecordingSocket:
    def __init__(self, *, incoming=b"", connect_error=None, send_error=None):
        self.incoming = incoming
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

    def recv(self, size):
        chunk = self.incoming[:size]
        self.incoming = self.incoming[size:]
        return chunk

    def close(self):
        self.closed = True


def _peer_version_bytes(
        magic_bytes=MAGICBYTES.MAINNET,
        protocol_version=NETWORK.PROTOCOL_VERSION,
):
    version = Version(
        version=protocol_version,
        services=PEER_SERVICES,
        timestamp=FIXED_TIMESTAMP,
        remote_addr=NetAddr(FAKE_ENDPOINT, EPHEMERAL_PORT, Services.UNNAMED),
        local_addr=NetAddr(KNOWN_TEST_ENDPOINT, NETWORK.MAINNET_PORT, PEER_SERVICES),
        nonce=PEER_NONCE,
        user_agent=PEER_USER_AGENT,
        last_block=PEER_BLOCK_HEIGHT,
    )
    version.magic_bytes = magic_bytes
    return version.to_bytes()


def _peer_handshake_bytes(
        magic_bytes=MAGICBYTES.MAINNET,
        protocol_version=NETWORK.PROTOCOL_VERSION,
        pre_verack_messages=(),
):
    messages = [_peer_version_bytes(magic_bytes, protocol_version)]
    for message_type in (*pre_verack_messages, VerAck):
        message = message_type()
        message.magic_bytes = magic_bytes
        messages.append(message.to_bytes())
    return b"".join(messages)


def _oversized_message_header() -> bytes:
    return b"".join([
        MAGICBYTES.MAINNET,
        b"block".ljust(NETWORK.COMMAND_LENGTH, b"\x00"),
        (NETWORK.MAX_PAYLOAD_SIZE + 1).to_bytes(NETWORK.PAYLOAD_SIZE_LENGTH, "little"),
        b"\x00" * NETWORK.CHECKSUM_LENGTH,
    ])


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
        assert node.config.data_dir == tmp_path
        assert node.config.blocks_dir.is_relative_to(tmp_path)
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
        assert status["outbound_peers"] == 0
        assert status["target_outbound"] == 8
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


def test_node_lifecycle_starts_and_stops_injected_peer_manager(tmp_path):
    peer_manager = MagicMock()
    node = Node(db_path=tmp_path / "node.db", peer_manager=peer_manager)

    try:
        node.start()
        node.start()

        assert node.started
        peer_manager.start.assert_called_once_with()

        node.stop()

        assert not node.started
        peer_manager.stop.assert_called_once_with()
    finally:
        node.close()


def test_connect_peer_sends_version_first_with_node_state(monkeypatch, tmp_path):
    fake_socket = _RecordingSocket(incoming=_peer_handshake_bytes(MAGICBYTES.REGTEST))
    monkeypatch.setattr("src.network.transport.socket.socket", lambda *args, **kwargs: fake_socket)
    monkeypatch.setattr("src.node.node.time.time", lambda: FIXED_TIMESTAMP)
    monkeypatch.setattr("src.node.node.secrets.randbits", lambda bits: FIXED_NONCE)
    node = Node(data_dir=tmp_path, network="regtest")

    try:
        peer = node.connect_peer(KNOWN_TEST_ENDPOINT, NETWORK.REGTEST_PORT)
        version = Version.from_bytes(fake_socket.sent[0])
        verack = VerAck.from_bytes(fake_socket.sent[1])
        getaddr = GetAddr.from_bytes(fake_socket.sent[2])

        assert len(fake_socket.sent) == 3
        assert fake_socket.sent[0][:4] == MAGICBYTES.REGTEST
        assert fake_socket.sent[1][:4] == MAGICBYTES.REGTEST
        assert isinstance(verack, VerAck)
        assert isinstance(getaddr, GetAddr)
        assert peer.state is PeerState.READY
        assert peer.local_nonce == FIXED_NONCE
        assert peer.protocol_version == NETWORK.PROTOCOL_VERSION
        assert peer.services == PEER_SERVICES
        assert peer.user_agent == PEER_USER_AGENT
        assert peer.nonce == PEER_NONCE
        assert peer.last_block == PEER_BLOCK_HEIGHT
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
        address = node.address_book.get(KNOWN_TEST_ENDPOINT, NETWORK.REGTEST_PORT)
        assert address is not None
        assert address.sources == {PeerSource.MANUAL}
        assert address.success_count == 1
        assert address.protocol_version == NETWORK.PROTOCOL_VERSION
        assert address.user_agent == PEER_USER_AGENT
        assert address.last_block == PEER_BLOCK_HEIGHT
    finally:
        node.close()


def test_connect_peer_uses_fresh_nonce_for_each_handshake(monkeypatch, tmp_path):
    sockets = [
        _RecordingSocket(incoming=_peer_handshake_bytes()),
        _RecordingSocket(incoming=_peer_handshake_bytes()),
    ]
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


@pytest.mark.parametrize(
    ("network", "magic_bytes", "port"),
    [
        ("mainnet", MAGICBYTES.MAINNET, NETWORK.MAINNET_PORT),
        ("testnet", MAGICBYTES.TESTNET, NETWORK.TESTNET_PORT),
        ("regtest", MAGICBYTES.REGTEST, NETWORK.REGTEST_PORT),
        ("signet", MAGICBYTES.SIGNET, NETWORK.SIGNET_PORT),
    ],
)
def test_connect_peer_receives_version_on_supported_network(
        monkeypatch, tmp_path, network, magic_bytes, port,
):
    fake_socket = _RecordingSocket(incoming=_peer_handshake_bytes(magic_bytes))
    monkeypatch.setattr("src.network.transport.socket.socket", lambda *args, **kwargs: fake_socket)
    node = Node(data_dir=tmp_path, network=network)

    try:
        peer = node.connect_peer(KNOWN_TEST_ENDPOINT)

        assert peer.protocol_version == NETWORK.PROTOCOL_VERSION
        assert peer.user_agent == PEER_USER_AGENT
        assert peer.state is PeerState.READY
        assert peer.port == port
        assert fake_socket.connected_to == (KNOWN_TEST_ENDPOINT, port)
    finally:
        node.close()


@pytest.mark.parametrize(
    "protocol_version",
    [NETWORK.MIN_PROTOCOL_VERSION, NETWORK.PROTOCOL_VERSION],
    ids=["minimum", "current"],
)
def test_connect_peer_accepts_compatible_protocol_versions(
        monkeypatch, tmp_path, protocol_version,
):
    fake_socket = _RecordingSocket(
        incoming=_peer_handshake_bytes(protocol_version=protocol_version),
    )
    monkeypatch.setattr("src.network.transport.socket.socket", lambda *args, **kwargs: fake_socket)
    node = Node(data_dir=tmp_path)

    try:
        peer = node.connect_peer(KNOWN_TEST_ENDPOINT, NETWORK.MAINNET_PORT)

        assert peer.protocol_version == protocol_version
        assert peer.state is PeerState.READY
        assert peer.fail_count == 0
    finally:
        node.close()


def test_connect_peer_allows_standard_messages_before_verack(monkeypatch, tmp_path):
    incoming = _peer_handshake_bytes(
        pre_verack_messages=(WtxidRelay, SendAddrV2),
    )
    fake_socket = _RecordingSocket(incoming=incoming)
    monkeypatch.setattr("src.network.transport.socket.socket", lambda *args, **kwargs: fake_socket)
    node = Node(data_dir=tmp_path)

    try:
        peer = node.connect_peer(KNOWN_TEST_ENDPOINT, NETWORK.MAINNET_PORT)

        assert peer.state is PeerState.READY
        assert len(fake_socket.sent) == 3
        assert isinstance(VerAck.from_bytes(fake_socket.sent[1]), VerAck)
    finally:
        node.close()


def test_connect_peer_rejects_unexpected_message_before_verack(monkeypatch, tmp_path):
    version = _peer_version_bytes()
    ping = Ping(PEER_NONCE)
    incoming = version + ping.to_bytes()
    fake_socket = _RecordingSocket(incoming=incoming)
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
        with pytest.raises(NetworkError, match="Unexpected command before verack"):
            node.connect_peer(KNOWN_TEST_ENDPOINT, NETWORK.MAINNET_PORT)

        assert captured_peer.state is PeerState.DISCONNECTED
        assert captured_peer.fail_count == 1
        assert len(fake_socket.sent) == 2
        assert fake_socket.closed
    finally:
        node.close()


def test_connect_peer_rejects_unknown_command_before_verack(monkeypatch, tmp_path):
    unknown = UnknownMessage("futuremsg", b"payload", MAGICBYTES.MAINNET)
    incoming = _peer_version_bytes() + unknown.to_bytes()
    fake_socket = _RecordingSocket(incoming=incoming)
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
        with pytest.raises(NetworkError, match="Unexpected command before verack: 'futuremsg'"):
            node.connect_peer(KNOWN_TEST_ENDPOINT, NETWORK.MAINNET_PORT)

        assert captured_peer.state is PeerState.DISCONNECTED
        assert captured_peer.fail_count == 1
        assert fake_socket.closed
    finally:
        node.close()


def test_connect_peer_disconnects_if_peer_closes_before_verack(monkeypatch, tmp_path):
    fake_socket = _RecordingSocket(incoming=_peer_version_bytes())
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
        with pytest.raises(ConnectionError, match="closed while receiving"):
            node.connect_peer(KNOWN_TEST_ENDPOINT, NETWORK.MAINNET_PORT)

        assert captured_peer.state is PeerState.DISCONNECTED
        assert captured_peer.fail_count == 1
        assert len(fake_socket.sent) == 2
        assert fake_socket.closed
    finally:
        node.close()


def test_connect_peer_limits_messages_before_verack(monkeypatch, tmp_path):
    negotiation_messages = (WtxidRelay,) * (NETWORK.MAX_PRE_VERACK_MESSAGES + 1)
    incoming = _peer_version_bytes()
    for message_type in negotiation_messages:
        incoming += message_type().to_bytes()
    fake_socket = _RecordingSocket(incoming=incoming)
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
        with pytest.raises(NetworkError, match="exceeded limit"):
            node.connect_peer(KNOWN_TEST_ENDPOINT, NETWORK.MAINNET_PORT)

        assert captured_peer.state is PeerState.DISCONNECTED
        assert captured_peer.fail_count == 1
        assert fake_socket.closed
    finally:
        node.close()


def test_connect_peer_disconnects_on_oversized_pre_verack_message(monkeypatch, tmp_path):
    incoming = _peer_version_bytes() + _oversized_message_header()
    fake_socket = _RecordingSocket(incoming=incoming)
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
        with pytest.raises(NetworkError, match="Invalid size value"):
            node.connect_peer(KNOWN_TEST_ENDPOINT, NETWORK.MAINNET_PORT)

        assert captured_peer.state is PeerState.DISCONNECTED
        assert captured_peer.fail_count == 1
        assert captured_peer.last_fail is not None
        assert fake_socket.incoming == b""
        assert fake_socket.closed
    finally:
        node.close()


def test_connect_peer_rejects_protocol_version_below_minimum(monkeypatch, tmp_path):
    fake_socket = _RecordingSocket(
        incoming=_peer_version_bytes(protocol_version=BELOW_MIN_PROTOCOL_VERSION),
    )
    monkeypatch.setattr("src.network.transport.socket.socket", lambda *args, **kwargs: fake_socket)
    node = Node(data_dir=tmp_path)
    captured_peer = None
    original_connect = node.transport.connect

    def capture_connect(peer):
        nonlocal captured_peer
        captured_peer = peer
        original_connect(peer)

    monkeypatch.setattr(node.transport, "connect", capture_connect)

    expected_error = (
        f"Peer protocol version {BELOW_MIN_PROTOCOL_VERSION} is below minimum supported version "
        f"{NETWORK.MIN_PROTOCOL_VERSION}"
    )

    try:
        with pytest.raises(NetworkError, match=expected_error):
            node.connect_peer(KNOWN_TEST_ENDPOINT, NETWORK.MAINNET_PORT)

        assert captured_peer.protocol_version == BELOW_MIN_PROTOCOL_VERSION
        assert captured_peer.state is PeerState.DISCONNECTED
        assert captured_peer.fail_count == 1
        assert captured_peer.last_fail is not None
        assert len(fake_socket.sent) == 1
        assert fake_socket.closed
    finally:
        node.close()


def test_connect_peer_rejects_unexpected_first_command(monkeypatch, tmp_path):
    ping = Ping(PEER_NONCE)
    ping.magic_bytes = MAGICBYTES.MAINNET
    fake_socket = _RecordingSocket(incoming=ping.to_bytes())
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
        with pytest.raises(NetworkError, match="Unexpected command"):
            node.connect_peer(KNOWN_TEST_ENDPOINT, NETWORK.MAINNET_PORT)

        assert captured_peer.state is PeerState.DISCONNECTED
        assert captured_peer.fail_count == 1
        assert fake_socket.closed
    finally:
        node.close()


@pytest.mark.parametrize(
    "incoming",
    [
        _peer_version_bytes(MAGICBYTES.TESTNET),
        _peer_version_bytes()[:NETWORK.HEADER_LENGTH + 5],
    ],
    ids=["wrong-network-magic", "truncated-payload"],
)
def test_connect_peer_disconnects_on_invalid_version_frame(monkeypatch, tmp_path, incoming):
    fake_socket = _RecordingSocket(incoming=incoming)
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
        with pytest.raises((ConnectionError, NetworkError)):
            node.connect_peer(KNOWN_TEST_ENDPOINT, NETWORK.MAINNET_PORT)

        assert captured_peer.state is PeerState.DISCONNECTED
        assert captured_peer.fail_count == 1
        assert fake_socket.closed
    finally:
        node.close()


def test_connect_peer_disconnects_on_corrupt_version_checksum(monkeypatch, tmp_path):
    incoming = bytearray(_peer_version_bytes())
    checksum_start = NETWORK.HEADER_LENGTH - NETWORK.CHECKSUM_LENGTH
    incoming[checksum_start] ^= 0x01
    fake_socket = _RecordingSocket(incoming=bytes(incoming))
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
        with pytest.raises(NetworkError, match="Failed to validate"):
            node.connect_peer(KNOWN_TEST_ENDPOINT, NETWORK.MAINNET_PORT)

        assert captured_peer.state is PeerState.DISCONNECTED
        assert captured_peer.fail_count == 1
        assert fake_socket.closed
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
