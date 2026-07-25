from __future__ import annotations

import queue
import socket
import threading
from contextlib import contextmanager
from unittest.mock import MagicMock

from src.block.block import Block, BlockHeader
from src.blockchain.blockchain import Blockchain
from src.blockchain.genesis_block import genesis_block
from src.core import MAGICBYTES
from src.network.datatypes.network_data import InvVector
from src.network.datatypes.network_types import InvType, PeerState
from src.network.header_sync import HeaderSyncState
from src.network.messages.ctrl_msg import GetAddr, Ping, Pong
from src.network.messages.data_msg import BlockMessage, GetData, GetHeaders, Headers, Inv
from src.network.peer_address_book import PeerSource
from src.network.transport import Transport
from src.node.node import Node
from src.tx import Tx, TxIn, TxOut

EASY_BITS = bytes.fromhex("207fffff")
SOCKET_TIMEOUT = 3


def _coinbase() -> Tx:
    return Tx(
        inputs=[TxIn(b"\x00" * 32, 0xffffffff, b"\x02\x01\x00", 0xffffffff)],
        outputs=[TxOut(5_000_000_000, b"\x51")],
    )


def _block(node: Node) -> Block:
    return Block(
        version=2,
        prev_block=node.blockchain.tip.block_id,
        timestamp=node.blockchain.tip.timestamp + 1,
        bits=node.blockchain.bits,
        nonce=1,
        txs=[_coinbase()],
    )


def _mine_header(previous_hash: bytes, height: int) -> BlockHeader:
    header = BlockHeader(
        version=4,
        prev_block=previous_hash,
        merkle_root=height.to_bytes(32, "little"),
        timestamp=genesis_block.timestamp + height,
        bits=EASY_BITS,
        nonce=0,
    )
    while not Blockchain._validate_header_pow(header):
        header.nonce += 1
    return header


def _header_chain(count: int) -> list[BlockHeader]:
    headers = []
    previous_hash = genesis_block.block_id
    for height in range(1, count + 1):
        header = _mine_header(previous_hash, height)
        headers.append(header)
        previous_hash = header.block_id
    return headers


@contextmanager
def _connected_regtest_nodes(tmp_path):
    server = Node(
        data_dir=tmp_path / "server",
        network="regtest",
        transport=Transport(timeout=SOCKET_TIMEOUT, magic_bytes=MAGICBYTES.REGTEST),
    )
    client = Node(
        data_dir=tmp_path / "client",
        network="regtest",
        transport=Transport(timeout=SOCKET_TIMEOUT, magic_bytes=MAGICBYTES.REGTEST),
    )
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(SOCKET_TIMEOUT)
    host, port = listener.getsockname()
    accepted = queue.Queue()

    def accept_connection():
        try:
            sock, _address = listener.accept()
            accepted.put(server.accept_peer(sock))
        except BaseException as error:
            accepted.put(error)
        finally:
            listener.close()

    accept_thread = threading.Thread(target=accept_connection, daemon=True)
    accept_thread.start()
    try:
        client_peer = client.connect_peer(host, port)
        server_result = accepted.get(timeout=SOCKET_TIMEOUT)
        if isinstance(server_result, BaseException):
            raise server_result
        accept_thread.join(timeout=SOCKET_TIMEOUT)
        yield server, server_result, client, client_peer
    finally:
        listener.close()
        client.close()
        server.close()
        accept_thread.join(timeout=SOCKET_TIMEOUT)


def _drain_initial_getaddr(server: Node, server_peer) -> None:
    message = server.receive_peer_message(server_peer)
    assert isinstance(message, GetAddr)


def test_two_regtest_nodes_complete_handshake_over_loopback(tmp_path):
    with _connected_regtest_nodes(tmp_path) as (server, server_peer, client, client_peer):
        assert server_peer.state is PeerState.READY
        assert client_peer.state is PeerState.READY
        assert server_peer.protocol_version == client_peer.protocol_version
        assert server.transport.magic_bytes == MAGICBYTES.REGTEST
        assert client.transport.magic_bytes == MAGICBYTES.REGTEST
        assert server_peer in server.ready_peers
        assert client_peer in client.ready_peers
        inbound = server.address_book.get(server_peer.host, server_peer.port)
        assert inbound is not None
        assert PeerSource.INBOUND in inbound.sources


def test_two_regtest_nodes_propagate_block_over_inventory_round_trip(tmp_path):
    with _connected_regtest_nodes(tmp_path) as (source, source_peer, receiver, receiver_peer):
        _drain_initial_getaddr(source, source_peer)
        block = _block(source)
        original_get_block = source.blockchain.get_block
        source.blockchain.get_block = MagicMock(
            side_effect=lambda block_hash: (
                block if block_hash == block.block_id else original_get_block(block_hash)
            )
        )
        receiver.submit_block = MagicMock(return_value=True)

        vector = InvVector(InvType.MSG_BLOCK, block.block_id)
        assert source._announce_inventory(vector) == (source_peer,)

        announcement = receiver.receive_peer_message(receiver_peer)
        assert isinstance(announcement, Inv)
        request = source.receive_peer_message(source_peer)
        assert isinstance(request, GetData)
        delivered = receiver.receive_peer_message(receiver_peer)
        assert isinstance(delivered, BlockMessage)

        receiver.submit_block.assert_called_once_with(block, source_peer=receiver_peer)
        assert len(receiver.inventory_requests) == 0


def test_two_regtest_nodes_exchange_matching_ping_and_pong(tmp_path):
    with _connected_regtest_nodes(tmp_path) as (source, source_peer, receiver, receiver_peer):
        _drain_initial_getaddr(source, source_peer)

        nonce = source.keepalive.ping(source_peer)
        ping = receiver.receive_peer_message(receiver_peer)
        pong = source.receive_peer_message(source_peer)

        assert isinstance(ping, Ping)
        assert ping.nonce == nonce
        assert isinstance(pong, Pong)
        assert pong.nonce == nonce
        assert source.keepalive.pending_nonce(source_peer) is None


def test_header_first_ibd_simulation_against_local_regtest_peer(tmp_path):
    with _connected_regtest_nodes(tmp_path) as (source, source_peer, syncing, syncing_peer):
        _drain_initial_getaddr(source, source_peer)
        headers = _header_chain(5)
        assert source.blockchain.add_headers(headers) == tuple(headers)

        syncing.start_header_sync(syncing_peer)
        request = source.receive_peer_message(source_peer)
        assert isinstance(request, GetHeaders)
        assert request.locator_hashes[0] == genesis_block.block_id

        source.transport.send(source_peer, Headers(headers))
        response = syncing.receive_peer_message(syncing_peer)

        assert isinstance(response, Headers)
        assert syncing.header_sync.state is HeaderSyncState.COMPLETE
        assert syncing.header_sync.headers_received == len(headers)
        assert syncing.blockchain.get_best_header().height == len(headers)
        assert syncing.blockchain.height == 0
