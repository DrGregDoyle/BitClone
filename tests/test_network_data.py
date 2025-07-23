"""
Tests for the various data structures associated with p2p messaging
"""

from random import randint
from secrets import token_bytes

import pytest

from src.data import Inventory, InvType, write_compact_size, BlockTxRequest
from tests.randbtc_generators import get_random_invtype


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
