import pytest

from src.block.block import BlockHeader
from src.core import NETWORK, NetworkDataError, write_compact_size
from src.network.datatypes.network_data import InvVector
from src.network.datatypes.network_types import InvType
from src.network.messages.data_msg import Headers, Inv


def test_protocol_wide_network_limits():
    assert NETWORK.MAX_INVENTORY_ENTRIES == 50_000
    assert NETWORK.MAX_GETBLOCKS_RESULTS == 500
    assert NETWORK.MAX_HEADERS_RESULTS == 2_000
    assert NETWORK.MAX_COMPACT_FILTERS_PER_REQUEST == 1_000
    assert NETWORK.MAX_PAYLOAD_SIZE == 4_000_000


def test_inventory_accepts_maximum_entries():
    item = InvVector(InvType.MSG_TX, bytes(NETWORK.INV_HASH_SIZE))

    message = Inv([item] * NETWORK.MAX_INVENTORY_ENTRIES)

    assert len(message.items) == NETWORK.MAX_INVENTORY_ENTRIES


def test_inventory_rejects_more_than_maximum_entries():
    item = InvVector(InvType.MSG_TX, bytes(NETWORK.INV_HASH_SIZE))

    with pytest.raises(NetworkDataError, match="Inventory list exceeds maximum entries"):
        Inv([item] * (NETWORK.MAX_INVENTORY_ENTRIES + 1))


def test_inventory_payload_rejects_oversized_count_before_reading_items():
    payload = write_compact_size(NETWORK.MAX_INVENTORY_ENTRIES + 1)

    with pytest.raises(NetworkDataError, match="Inventory list exceeds maximum entries"):
        Inv.from_payload(payload)


def test_headers_accepts_maximum_results():
    header = BlockHeader()

    message = Headers([header] * NETWORK.MAX_HEADERS_RESULTS)

    assert len(message.headers) == NETWORK.MAX_HEADERS_RESULTS


def test_headers_reject_more_than_maximum_results():
    header = BlockHeader()

    with pytest.raises(NetworkDataError, match="Headers list exceeds maximum entries"):
        Headers([header] * (NETWORK.MAX_HEADERS_RESULTS + 1))


def test_headers_payload_rejects_oversized_count_before_reading_headers():
    payload = write_compact_size(NETWORK.MAX_HEADERS_RESULTS + 1)

    with pytest.raises(NetworkDataError, match="Headers list exceeds maximum entries"):
        Headers.from_payload(payload)
