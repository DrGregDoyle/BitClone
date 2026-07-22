import pytest

from src.core import NETWORK
from src.network.datatypes.network_data import InvVector
from src.network.datatypes.network_types import InvType
from src.network.inventory import InflightInventory, inventory_key

PEER_KEY = ("192.0.2.1", NETWORK.MAINNET_PORT)
TX_HASH = b"\x01" * NETWORK.HASH_LENGTH
BLOCK_HASH = b"\x02" * NETWORK.HASH_LENGTH


def test_inventory_key_canonicalizes_wire_variants():
    assert inventory_key(InvVector(InvType.MSG_TX, TX_HASH)) == ("tx", TX_HASH)
    assert inventory_key(InvVector(InvType.MSG_WITNESS_TX, TX_HASH)) == ("tx", TX_HASH)
    assert inventory_key(InvVector(InvType.MSG_BLOCK, BLOCK_HASH)) == ("block", BLOCK_HASH)
    assert inventory_key(InvVector(InvType.MSG_WITNESS_BLOCK, BLOCK_HASH)) == ("block", BLOCK_HASH)
    assert inventory_key(InvVector(InvType.ERROR, TX_HASH)) is None


def test_inflight_inventory_deduplicates_across_peers_and_variants():
    tracker = InflightInventory()
    tx = InvVector(InvType.MSG_TX, TX_HASH)
    witness_tx = InvVector(InvType.MSG_WITNESS_TX, TX_HASH)

    assert tracker.claim(tx, PEER_KEY)
    assert not tracker.claim(witness_tx, ("192.0.2.2", NETWORK.MAINNET_PORT))
    assert tracker.contains(witness_tx)
    assert len(tracker) == 1

    assert tracker.release(witness_tx)
    assert not tracker.contains(tx)


def test_inflight_inventory_expires_requests_after_timeout():
    now = [100.0]
    tracker = InflightInventory(timeout=10, clock=lambda: now[0])
    vector = InvVector(InvType.MSG_BLOCK, BLOCK_HASH)

    assert tracker.claim(vector, PEER_KEY)
    now[0] = 109.99
    assert tracker.contains(vector)
    now[0] = 110

    assert tracker.expire() == 1
    assert not tracker.contains(vector)
    assert tracker.claim(vector, ("192.0.2.2", NETWORK.MAINNET_PORT))


def test_inflight_inventory_releases_disconnected_peers_requests():
    tracker = InflightInventory()
    tracker.claim(InvVector(InvType.MSG_TX, TX_HASH), PEER_KEY)
    tracker.claim(InvVector(InvType.MSG_BLOCK, BLOCK_HASH), PEER_KEY)

    assert tracker.release_peer(PEER_KEY) == 2
    assert len(tracker) == 0


def test_inflight_inventory_rejects_invalid_timeout():
    with pytest.raises(ValueError, match="positive"):
        InflightInventory(timeout=0)
