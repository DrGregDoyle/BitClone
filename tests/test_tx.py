"""
Tests for the Transaction classes
"""

from src.tx import Input, Output, WitnessItem, Witness, Transaction
from tests.randbtc_generators import get_random_input, get_random_output, get_random_witness_item, get_random_witness, \
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
    rand_tx_segwit = get_random_tx()
    rand_tx_legacy = get_random_tx(is_segwit=False)

    fbrand_segwit = Transaction.from_bytes(rand_tx_segwit.to_bytes())
    fbrand_legacy = Transaction.from_bytes(rand_tx_legacy.to_bytes())

    assert rand_tx_segwit == fbrand_segwit, f"From bytes method failed for random tx segwit:" \
                                            f" {rand_tx_segwit.to_json()}"
    assert rand_tx_legacy == fbrand_legacy, f"From bytes method failed for random tx legacy:" \
                                            f" {rand_tx_legacy.to_json()}"


if __name__ == "__main__":
    test_tx_input()
