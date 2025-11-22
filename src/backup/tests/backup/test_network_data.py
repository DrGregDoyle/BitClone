"""
Tests for the various data structures associated with p2p messaging
"""
from random import randint, choice
from secrets import token_bytes
from time import time as now

import pytest

from src.backup.data import Inventory, InvType, BlockTxRequest, NodeType, NetAddr
from src.backup.data import write_compact_size
from src.backup.tests.backup.randbtc_generators import get_random_invtype


def test_inventory():
    """
    Tests the Inventory Data Structure
    """
    rand_invtype = get_random_invtype()  # Don't include error type
    rand_hash = token_bytes(32)
    rand_inventory = Inventory(rand_invtype, rand_hash)
    recovered_inventory = Inventory.from_bytes(rand_inventory.to_bytes())

    # Verify to_bytes -> from_bytes construction
    assert recovered_inventory.to_bytes() == rand_inventory.to_bytes(), \
        "to_bytes -> from_bytes construction fails for random Inventory"


def test_inventory_int_vs_enum():
    rand_hash = token_bytes(32)
    # using raw int
    inv_int = Inventory(InvType.MSG_TX.value, rand_hash)  # type: ignore
    # using enum
    inv_enum = Inventory(InvType.MSG_TX, rand_hash)
    assert inv_int.to_bytes() == inv_enum.to_bytes()


def test_invtype_invalid_value():
    with pytest.raises(ValueError):
        InvType(999)


def test_blocktx_request():
    rand_hash = token_bytes(32)
    rand_index_num = randint(2, 5)
    rand_index = [write_compact_size(randint(1, 10)) for _ in range(rand_index_num)]

    rand_blocktx_req = BlockTxRequest(rand_hash, rand_index)
    print(f"BLOCKTX REQ: {rand_blocktx_req.to_json()}")


def test_netaddr():
    """
    We make sure a random NetAddr from_bytes -> to_bytes works as expected
    """
    random_nodetype = NodeType(choice([0, 1, 2, 4, 8, 16, 64, 1024]))
    current_time = int(now())

    # Version NetAddr
    version_netaddr = NetAddr(
        timestamp=current_time,
        services=random_nodetype,
        ip_addr="127.0.0.1",
        port=8333,
        is_version=True
    )

    recovered_version_netaddr = NetAddr.from_bytes(version_netaddr.to_bytes(), is_version=True)
    assert recovered_version_netaddr.to_bytes() == version_netaddr.to_bytes(), \
        "NetAddr failed from_bytes -> to_bytes reconstruction"
