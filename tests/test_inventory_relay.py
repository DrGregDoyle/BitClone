from unittest.mock import MagicMock

import pytest

from src.block.block import Block
from src.core import NETWORK
from src.network.datatypes.network_data import InvVector
from src.network.datatypes.network_types import InvType, PeerState
from src.network.messages.data_msg import BlockMessage, GetData, Inv, NotFound, Txn
from src.network.peer import Peer
from src.node.node import Node
from src.tx import Tx, TxIn, TxOut

SOURCE_HOST = "192.0.2.1"
SECOND_HOST = "192.0.2.2"
KNOWN_TX_HASH = b"\x01" * NETWORK.HASH_LENGTH
UNKNOWN_TX_HASH = b"\x02" * NETWORK.HASH_LENGTH
KNOWN_BLOCK_HASH = b"\x03" * NETWORK.HASH_LENGTH
UNKNOWN_BLOCK_HASH = b"\x04" * NETWORK.HASH_LENGTH


def _ready_peer(host: str) -> Peer:
    return Peer(host, NETWORK.MAINNET_PORT, state=PeerState.READY)


def _tx() -> Tx:
    return Tx(
        inputs=[TxIn(b"\x00" * 32, 0xffffffff, b"\x01\x01", 0xffffffff)],
        outputs=[TxOut(1, b"\x51")],
    )


def test_submit_tx_announces_inventory_to_ready_peers(tmp_path):
    node = Node(db_path=tmp_path / "node.db")
    peers = (_ready_peer(SOURCE_HOST), _ready_peer(SECOND_HOST))
    node._ready_peers = {peer.key: peer for peer in peers}
    node.transport.send = MagicMock()
    node.mempool.add_tx = MagicMock(return_value=True)
    tx = _tx()

    try:
        assert node.submit_tx(tx)

        assert node.transport.send.call_count == 2
        for peer, invocation in zip(peers, node.transport.send.call_args_list):
            assert invocation.args[0] is peer
            message = invocation.args[1]
            assert isinstance(message, Inv)
            assert message.items[0].inv_type is InvType.MSG_TX
            assert message.items[0].obj_hash == tx.txid
    finally:
        node.close()


def test_rejected_tx_is_not_announced(tmp_path):
    node = Node(db_path=tmp_path / "node.db")
    node.mempool.add_tx = MagicMock(return_value=False)
    node.transport.send = MagicMock()

    try:
        assert not node.submit_tx(_tx())
        node.transport.send.assert_not_called()
    finally:
        node.close()


def test_received_tx_is_admitted_and_relayed_without_echoing_source(tmp_path):
    node = Node(db_path=tmp_path / "node.db")
    source = _ready_peer(SOURCE_HOST)
    recipient = _ready_peer(SECOND_HOST)
    node._ready_peers = {peer.key: peer for peer in (source, recipient)}
    node.mempool.add_tx = MagicMock(return_value=True)
    node.transport.send = MagicMock()
    tx = _tx()

    try:
        assert node.handle_peer_message(source, Txn(tx)) == (tx,)

        node.mempool.add_tx.assert_called_once_with(tx)
        node.transport.send.assert_called_once()
        assert node.transport.send.call_args.args[0] is recipient
        announcement = node.transport.send.call_args.args[1]
        assert isinstance(announcement, Inv)
        assert announcement.items == [InvVector(InvType.MSG_TX, tx.txid)]
    finally:
        node.close()


def test_rejected_received_tx_is_ignored_without_disconnect_or_relay(tmp_path):
    node = Node(db_path=tmp_path / "node.db")
    source = _ready_peer(SOURCE_HOST)
    recipient = _ready_peer(SECOND_HOST)
    node._ready_peers = {peer.key: peer for peer in (source, recipient)}
    node.mempool.add_tx = MagicMock(return_value=False)
    node.transport.send = MagicMock()

    try:
        assert node.handle_peer_message(source, Txn(_tx())) == ()

        node.transport.send.assert_not_called()
        assert source.state is PeerState.READY
        assert source in node.ready_peers
    finally:
        node.close()


def test_receive_rejected_tx_keeps_peer_session_ready(tmp_path):
    node = Node(db_path=tmp_path / "node.db")
    source = _ready_peer(SOURCE_HOST)
    node._ready_peers[source.key] = source
    message = Txn(_tx())
    node.transport.recv_one = MagicMock(return_value=message)
    node.transport.send = MagicMock()
    node.mempool.add_tx = MagicMock(return_value=False)

    try:
        assert node.receive_peer_message(source) is message

        assert source.state is PeerState.READY
        assert source in node.ready_peers
        node.transport.send.assert_not_called()
    finally:
        node.close()


def test_inventory_announcement_failure_does_not_undo_accepted_tx(tmp_path):
    node = Node(db_path=tmp_path / "node.db")
    peer = _ready_peer(SOURCE_HOST)
    node._ready_peers[peer.key] = peer
    node.address_book.add_peer(peer)
    node.mempool.add_tx = MagicMock(return_value=True)
    node.transport.send = MagicMock(side_effect=ConnectionError("peer closed"))

    try:
        assert node.submit_tx(_tx())
        assert peer.state is PeerState.DISCONNECTED
        assert peer not in node.ready_peers
        assert node.address_book.get(SOURCE_HOST).fail_count == 1
    finally:
        node.close()


def test_submit_block_announces_inventory_after_acceptance(tmp_path):
    node = Node(db_path=tmp_path / "node.db")
    peer = _ready_peer(SOURCE_HOST)
    node._ready_peers[peer.key] = peer
    node.transport.send = MagicMock()
    node.blockchain.add_block = MagicMock(return_value=True)
    node.mempool.confirm_block = MagicMock()
    block = Block(prev_block=node.blockchain.tip.block_id, bits=node.blockchain.bits, txs=[_tx()])

    try:
        assert node.submit_block(block)

        message = node.transport.send.call_args.args[1]
        assert isinstance(message, Inv)
        assert message.items[0].inv_type is InvType.MSG_BLOCK
        assert message.items[0].obj_hash == block.block_id
    finally:
        node.close()


def test_inv_requests_only_unknown_supported_and_not_inflight_items(tmp_path):
    node = Node(db_path=tmp_path / "node.db")
    first_peer = _ready_peer(SOURCE_HOST)
    second_peer = _ready_peer(SECOND_HOST)
    node._ready_peers = {peer.key: peer for peer in (first_peer, second_peer)}
    node.transport.send = MagicMock()
    node.mempool.mempool[KNOWN_TX_HASH] = MagicMock()
    node.blockchain.get_block = MagicMock(
        side_effect=lambda block_hash: object() if block_hash == KNOWN_BLOCK_HASH else None
    )
    unknown_tx = InvVector(InvType.MSG_TX, UNKNOWN_TX_HASH)
    unknown_block = InvVector(InvType.MSG_BLOCK, UNKNOWN_BLOCK_HASH)
    inventory = Inv([
        InvVector(InvType.MSG_TX, KNOWN_TX_HASH),
        unknown_tx,
        InvVector(InvType.MSG_WITNESS_TX, UNKNOWN_TX_HASH),
        InvVector(InvType.MSG_BLOCK, KNOWN_BLOCK_HASH),
        unknown_block,
        InvVector(InvType.MSG_CMPCT_BLOCK, b"\x05" * NETWORK.HASH_LENGTH),
    ])

    try:
        requested = node.handle_peer_message(first_peer, inventory)

        assert requested == (unknown_tx, unknown_block)
        getdata = node.transport.send.call_args.args[1]
        assert isinstance(getdata, GetData)
        assert getdata.items == [unknown_tx, unknown_block]
        assert len(node.inventory_requests) == 2

        node.transport.send.reset_mock()
        assert node.handle_peer_message(second_peer, inventory) == ()
        node.transport.send.assert_not_called()
    finally:
        node.close()


def test_failed_getdata_send_releases_claimed_inventory(tmp_path):
    node = Node(db_path=tmp_path / "node.db")
    peer = _ready_peer(SOURCE_HOST)
    node._ready_peers[peer.key] = peer
    node.transport.send = MagicMock(side_effect=ConnectionError("peer closed"))
    vector = InvVector(InvType.MSG_TX, UNKNOWN_TX_HASH)

    try:
        with pytest.raises(ConnectionError, match="peer closed"):
            node.handle_peer_message(peer, Inv([vector]))

        assert len(node.inventory_requests) == 0
    finally:
        node.close()


def test_notfound_releases_request_for_another_peer(tmp_path):
    node = Node(db_path=tmp_path / "node.db")
    first_peer = _ready_peer(SOURCE_HOST)
    second_peer = _ready_peer(SECOND_HOST)
    node._ready_peers = {peer.key: peer for peer in (first_peer, second_peer)}
    node.transport.send = MagicMock()
    vector = InvVector(InvType.MSG_TX, UNKNOWN_TX_HASH)

    try:
        assert node.handle_peer_message(first_peer, Inv([vector])) == (vector,)
        node.handle_peer_message(first_peer, NotFound([vector]))
        assert node.handle_peer_message(second_peer, Inv([vector])) == (vector,)
        assert node.transport.send.call_count == 2
    finally:
        node.close()


def test_received_objects_release_matching_inflight_requests(tmp_path):
    node = Node(db_path=tmp_path / "node.db")
    peer = _ready_peer(SOURCE_HOST)
    node._ready_peers[peer.key] = peer
    tx = _tx()
    block = Block(prev_block=node.blockchain.tip.block_id, bits=node.blockchain.bits, txs=[tx])
    tx_vector = InvVector(InvType.MSG_TX, tx.txid)
    block_vector = InvVector(InvType.MSG_BLOCK, block.block_id)
    node.inventory_requests.claim(tx_vector, peer.key)
    node.inventory_requests.claim(block_vector, peer.key)

    try:
        node.handle_peer_message(peer, Txn(tx))
        node.handle_peer_message(peer, BlockMessage(block))

        assert len(node.inventory_requests) == 0
    finally:
        node.close()


def test_getdata_serves_available_objects_and_reports_missing(tmp_path):
    node = Node(db_path=tmp_path / "node.db")
    peer = _ready_peer(SOURCE_HOST)
    node._ready_peers[peer.key] = peer
    tx = _tx()
    block = Block(prev_block=node.blockchain.tip.block_id, bits=node.blockchain.bits, txs=[tx])
    tx_vector = InvVector(InvType.MSG_TX, tx.txid)
    block_vector = InvVector(InvType.MSG_BLOCK, block.block_id)
    missing_vector = InvVector(InvType.MSG_TX, UNKNOWN_TX_HASH)
    node.mempool.get_tx = MagicMock(side_effect=lambda txid: tx if txid == tx.txid else None)
    node.blockchain.get_block = MagicMock(
        side_effect=lambda block_hash: block if block_hash == block.block_id else None
    )
    node.transport.send = MagicMock()

    try:
        served = node.handle_peer_message(
            peer,
            GetData([tx_vector, block_vector, missing_vector]),
        )

        assert served == (tx_vector, block_vector)
        assert isinstance(node.transport.send.call_args_list[0].args[1], Txn)
        assert isinstance(node.transport.send.call_args_list[1].args[1], BlockMessage)
        notfound = node.transport.send.call_args_list[2].args[1]
        assert isinstance(notfound, NotFound)
        assert notfound.items == [missing_vector]
    finally:
        node.close()
