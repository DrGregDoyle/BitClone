from unittest.mock import MagicMock

import pytest

from src.block.block import BlockHeader
from src.blockchain.blockchain import Blockchain
from src.blockchain.genesis_block import genesis_block
from src.config import BitCloneConfig
from src.core import NETWORK, NetworkDataError
from src.network.header_sync import HeaderSyncState
from src.network.messages.data_msg import GetHeaders, Headers
from src.network.peer import Peer
from src.network.datatypes.network_types import PeerState
from src.network.peer_address_book import PeerSource
from src.node.node import Node


EASY_BITS = bytes.fromhex("207fffff")


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


def _header_chain(previous_hash: bytes, start_height: int, count: int) -> list[BlockHeader]:
    headers = []
    for height in range(start_height, start_height + count):
        header = _mine_header(previous_hash, height)
        headers.append(header)
        previous_hash = header.block_id
    return headers


def _ready_peer() -> Peer:
    return Peer("192.0.2.10", NETWORK.MAINNET_PORT, state=PeerState.READY)


def test_block_locator_starts_at_best_header_and_ends_at_genesis(tmp_path):
    chain = Blockchain(db_path=tmp_path / "chain.db")
    headers = _header_chain(chain.get_best_header().block_hash, 1, 25)
    try:
        assert chain.add_headers(headers) == tuple(headers)

        locator = chain.get_block_locator()

        assert locator[0] == headers[-1].block_id
        assert locator[-1] == genesis_block.block_id
        assert locator[:10] == [header.block_id for header in reversed(headers[-10:])]
        assert len(locator) == len(set(locator))
    finally:
        chain.close()


def test_header_sync_loops_on_full_batch_and_completes_on_short_batch(tmp_path):
    node = Node(db_path=tmp_path / "node.db")
    peer = _ready_peer()
    node._ready_peers[peer.key] = peer
    node.transport.send = MagicMock()
    headers = _header_chain(genesis_block.block_id, 1, NETWORK.MAX_HEADERS_RESULTS)
    try:
        first_request = node.start_header_sync(peer)

        assert isinstance(first_request, GetHeaders)
        assert first_request.locator_hashes[0] == genesis_block.block_id
        accepted = node.handle_peer_message(peer, Headers(headers))

        assert accepted == tuple(headers)
        assert node.header_sync.state is HeaderSyncState.SYNCING
        assert node.header_sync.awaiting_headers
        assert node.transport.send.call_count == 2
        next_request = node.transport.send.call_args.args[1]
        assert isinstance(next_request, GetHeaders)
        assert next_request.locator_hashes[0] == headers[-1].block_id

        assert node.handle_peer_message(peer, Headers([])) == ()
        assert node.header_sync.state is HeaderSyncState.COMPLETE
        assert node.blockchain.get_best_header().height == NETWORK.MAX_HEADERS_RESULTS
        assert node.blockchain.height == 0
        assert node.blockchain.tip.block_id == genesis_block.block_id
    finally:
        node.close()


def test_header_sync_rejects_unknown_parent_and_marks_failed(tmp_path):
    node = Node(db_path=tmp_path / "node.db")
    peer = _ready_peer()
    node._ready_peers[peer.key] = peer
    node.transport.send = MagicMock()
    unknown_parent_header = _mine_header(b"\x44" * 32, 1)
    try:
        node.start_header_sync(peer)

        with pytest.raises(NetworkDataError, match="parent is unknown"):
            node.handle_peer_message(peer, Headers([unknown_parent_header]))

        assert node.header_sync.state is HeaderSyncState.FAILED
        assert node.blockchain.get_best_header().height == 0
    finally:
        node.close()


def test_header_sync_rejects_invalid_proof_of_work(tmp_path):
    node = Node(db_path=tmp_path / "node.db")
    peer = _ready_peer()
    node._ready_peers[peer.key] = peer
    node.transport.send = MagicMock()
    invalid = BlockHeader(
        version=4,
        prev_block=genesis_block.block_id,
        merkle_root=b"\x55" * 32,
        timestamp=genesis_block.timestamp + 1,
        bits=bytes.fromhex("03000001"),
        nonce=0,
    )
    try:
        node.start_header_sync(peer)

        with pytest.raises(NetworkDataError, match="proof of work"):
            node.handle_peer_message(peer, Headers([invalid]))
    finally:
        node.close()


def test_header_sync_resumes_from_persisted_best_header(tmp_path):
    db_path = tmp_path / "node.db"
    first = Node(db_path=db_path)
    headers = _header_chain(genesis_block.block_id, 1, 4)
    first.blockchain.add_headers(headers)
    first.close()

    resumed = Node(db_path=db_path)
    peer = _ready_peer()
    resumed._ready_peers[peer.key] = peer
    resumed.transport.send = MagicMock()
    try:
        request = resumed.start_header_sync(peer)

        assert resumed.blockchain.get_best_header().height == 4
        assert resumed.blockchain.height == 0
        assert request.locator_hashes[0] == headers[-1].block_id
    finally:
        resumed.close()


def test_disconnect_makes_incomplete_header_sync_resumable(tmp_path):
    node = Node(db_path=tmp_path / "node.db")
    peer = _ready_peer()
    node._ready_peers[peer.key] = peer
    node.transport.send = MagicMock()
    try:
        node.start_header_sync(peer)
        node.disconnect_peer(peer)

        assert node.header_sync.state is HeaderSyncState.IDLE
        assert not node.header_sync.awaiting_headers
    finally:
        node.close()


def test_synchronous_header_sync_drives_receive_loop_to_completion(tmp_path):
    node = Node(db_path=tmp_path / "node.db")
    peer = _ready_peer()
    node._ready_peers[peer.key] = peer
    headers = _header_chain(genesis_block.block_id, 1, 3)
    node.transport.send = MagicMock()
    node.transport.recv_one = MagicMock(return_value=Headers(headers))
    try:
        assert node.sync_headers(peer) == 3
        assert node.header_sync.state is HeaderSyncState.COMPLETE
        node.transport.recv_one.assert_called_once_with(peer)
    finally:
        node.close()


def test_synchronous_driver_continues_existing_request_without_duplicate(tmp_path):
    node = Node(db_path=tmp_path / "node.db")
    peer = _ready_peer()
    node._ready_peers[peer.key] = peer
    node.transport.send = MagicMock()
    node.transport.recv_one = MagicMock(return_value=Headers([]))
    try:
        node.start_header_sync(peer)
        assert node.sync_headers(peer) == 0

        node.transport.send.assert_called_once()
    finally:
        node.close()


def test_connect_upstream_uses_configured_endpoint_and_starts_header_sync(tmp_path):
    config = BitCloneConfig.from_options(
        data_dir=tmp_path,
        upstream_host="192.168.0.108",
        upstream_port=8333,
    )
    node = Node(config=config)
    peer = _ready_peer()
    node.connect_peer = MagicMock(return_value=peer)
    node.start_header_sync = MagicMock()
    try:
        assert node.connect_upstream() is peer
        node.connect_peer.assert_called_once_with("192.168.0.108", 8333, source=PeerSource.MANUAL)
        node.start_header_sync.assert_called_once_with(peer)
    finally:
        node.close()
