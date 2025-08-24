"""
Tests for the Transaction classes
"""

from src import Input, Output, WitnessItem, Witness, Transaction
from tests.backup.randbtc_generators import get_random_input, get_random_output, get_random_witness_item, \
    get_random_witness, \
    get_random_tx


def test_tx_input():
    random_input = get_random_input()
    fbrand_input = Input.from_bytes(random_input.to_bytes())

    assert random_input == fbrand_input, f"From bytes method failed for random tx input: {random_input.to_json()}"


def test_tx_output():
    random_output = get_random_output()
    fbrand_output = Output.from_bytes(random_output.to_bytes())

    assert random_output == fbrand_output, f"From bytes method failed for random tx output: {random_output.to_json()}"


def test_witness_item():
    random_witem = get_random_witness_item()
    fbrand_witem = WitnessItem.from_bytes(random_witem.to_bytes())

    assert random_witem == fbrand_witem, f"From bytes method failed for random tx witness item:" \
                                         f" {random_witem.to_json()}"


def test_witness():
    random_witness = get_random_witness()
    fbrand_witness = Witness.from_bytes(random_witness.to_bytes())

    assert random_witness == fbrand_witness, f"From bytes method failed for random tx witness:" \
                                             f" {random_witness.to_json()}"


def test_transaction():
    rand_tx_legacy = get_random_tx(is_segwit=False)
    print(f"RANDOM TX: {rand_tx_legacy.to_json()}")
    print(f"LOCKTIME: {rand_tx_legacy.locktime}")

    # fbrand_segwit = Transaction.from_bytes(rand_tx_segwit.to_bytes())
    fbrand_legacy = Transaction.from_bytes(rand_tx_legacy.to_bytes())
    print(f"RECOVERED TX: {fbrand_legacy.to_json()}")
    print(f"LOCKTIME: {fbrand_legacy.locktime}")
    print(f"DONE")
