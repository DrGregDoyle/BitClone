"""
Tests for the Transaction classes
"""
from secrets import token_bytes, randbits, randbelow

from src.tx import Input, Output, WitnessItem, Witness, Transaction


def test_tx_input():
    _txid = token_bytes(32)  # 32 random bytes
    _vout = randbits(32)  # 4 bytes random  integer
    _scriptsiglen = randbelow(0xfff)  # Length < 4095 bytes
    _scriptsig = token_bytes(_scriptsiglen)
    _sequence = randbits(32)  # 4 bytes random  integer

    _test_input = Input(_txid, _vout, _scriptsig, _sequence)
    _fb_input = Input.from_bytes(_test_input.to_bytes())

    assert _fb_input.to_bytes() == _test_input.to_bytes(), \
        f"Assertion failed. Random Input: {_test_input.to_json()}\nRecovered Input: {_fb_input.to_json()}"


def test_tx_output():
    _amount = randbits(64)  # 8 bytes random integer
    _scriptpubkey = token_bytes(40)  # 40 random bytes

    _test_output = Output(_amount, _scriptpubkey)
    _fb_output = Output.from_bytes(_test_output.to_bytes())

    assert _fb_output.to_bytes() == _test_output.to_bytes(), \
        f"Assertion failed. Random Input: {_test_output.to_json()}\nRecovered Input: {_fb_output.to_json()}"


def test_witness_item():
    _item_length = randbelow(100)  # Generate a witness item of up to 100 bytes
    _item = token_bytes(_item_length)

    _test_witness_item = WitnessItem(_item)
    _fb_witness_item = WitnessItem.from_bytes(_test_witness_item.to_bytes())

    assert _fb_witness_item.to_bytes() == _test_witness_item.to_bytes(), \
        f"Assertion failed. Random WitnessItem: {_test_witness_item.to_json()}\nRecovered WitnessItem: {_fb_witness_item.to_json()}"


def test_witness():
    _num_items = randbelow(5) + 1  # Generate 1 to 5 witness items
    _items = [WitnessItem(token_bytes(randbelow(100))) for _ in range(_num_items)]

    _test_witness = Witness(_items)
    _fb_witness = Witness.from_bytes(_test_witness.to_bytes())

    assert _fb_witness.to_bytes() == _test_witness.to_bytes(), \
        f"Assertion failed. Random Witness: {_test_witness.to_json()}\nRecovered Witness: {_fb_witness.to_json()}"


def test_transaction():
    _version = randbits(32)
    _num_inputs = randbelow(5) + 1
    _num_outputs = randbelow(5) + 1

    # Generate random inputs and outputs
    _inputs = [
        Input(token_bytes(32), randbits(32), token_bytes(randbelow(50)), randbits(32))
        for _ in range(_num_inputs)
    ]
    _outputs = [
        Output(randbits(64), token_bytes(randbelow(50)))
        for _ in range(_num_outputs)
    ]
    _locktime = randbits(32)

    # Legacy Transaction (No Witnesses)
    _no_witness = None
    _test_tx_legacy = Transaction(_inputs, _outputs, _no_witness, _locktime, _version)
    _fb_tx_legacy = Transaction.from_bytes(_test_tx_legacy.to_bytes())

    assert _fb_tx_legacy.to_bytes() == _test_tx_legacy.to_bytes(), \
        f"Legacy Transaction Assertion failed.\nRandom Transaction: {_test_tx_legacy.to_json()}\nRecovered Transaction: {_fb_tx_legacy.to_json()}"

    # SegWit Transaction (With Witnesses)
    _num_witnesses = len(_inputs)  # Each input gets a witness
    _witnesses = [
        Witness([WitnessItem(token_bytes(randbelow(50))) for _ in range(randbelow(3) + 1)])
        for _ in range(_num_witnesses)
    ]

    _test_tx_segwit = Transaction(_inputs, _outputs, _witnesses, _locktime, _version)
    _fb_tx_segwit = Transaction.from_bytes(_test_tx_segwit.to_bytes())

    assert _fb_tx_segwit.to_bytes() == _test_tx_segwit.to_bytes(), \
        f"SegWit Transaction Assertion failed.\nRandom Transaction: {_test_tx_segwit.to_json()}\nRecovered Transaction: {_fb_tx_segwit.to_json()}"


if __name__ == "__main__":
    test_tx_input()
