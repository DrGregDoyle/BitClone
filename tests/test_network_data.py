"""
Tests for the various data structures associated with p2p messaging
"""
from secrets import token_bytes

from src.data import Inventory
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
