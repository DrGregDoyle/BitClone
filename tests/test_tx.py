"""
We test the various parts of a BitClone transaction
"""
import os
import sys

import pytest

from src.core import TransactionError
from src.tx import LoadedTx, TxIn, TxOut, UTXO, Witness, Tx
from src.tx.validation import TxValidationContext, validate_loaded_tx

sys.path.append(os.path.dirname(__file__))


def test_txinput(getrand_txinput):
    """
    We test the serialization and class method of TxInput
    """
    random_txinput = getrand_txinput()
    recovered_txinput = TxIn.from_bytes(random_txinput.to_bytes())

    assert recovered_txinput == random_txinput, "Failed to reconstruct TxInput using to_bytes -> from_bytes method"


def test_txoutput(getrand_txoutput):
    """
    We test the serialization and class method of TxOutput
    """
    random_txoutput = getrand_txoutput()
    recovered_txoutput = TxOut.from_bytes(random_txoutput.to_bytes())

    assert recovered_txoutput == random_txoutput, "Failed to reconstruct TxOutput using to_bytes -> from_bytes method"


def test_witness(getrand_witnessfield):
    """
    We test the serialization of the WitnessField class
    """
    random_witness = getrand_witnessfield()
    recovered_witness = Witness.from_bytes(random_witness.to_bytes())

    assert random_witness == recovered_witness, "Failed to reconstruct WitnessField using to_bytes -> from_bytes method"


def test_tx(getrand_tx):
    # Legacy tx first
    random_legacytx = getrand_tx(segwit=False)
    recovered_legacytx = Tx.from_bytes(random_legacytx.to_bytes())

    assert random_legacytx == recovered_legacytx, \
        "Failed to reconstruct Transaction (legacy) using to_bytes -> from_bytes method"

    # Segwit tx
    random_tx = getrand_tx()
    recovered_tx = Tx.from_bytes(random_tx.to_bytes())

    assert random_tx == recovered_tx, "Failed to reconstruct Transaction using to_bytes -> from_bytes method"


def test_loaded_tx_keeps_utxos_aligned_with_inputs():
    outpoint_a = b"\x11" * 32 + (0).to_bytes(4, "little")
    outpoint_b = b"\x22" * 32 + (1).to_bytes(4, "little")
    tx = Tx(
        inputs=[
            TxIn(outpoint_a[:32], outpoint_a[32:], b"", 0xffffffff),
            TxIn(outpoint_b[:32], outpoint_b[32:], b"", 0xffffffff),
        ],
        outputs=[TxOut(1_200, b"\x51")],
    )
    utxos = [
        UTXO(outpoint_a, 1_000, b"\x51", 100),
        UTXO(outpoint_b, 500, b"\x51", 101),
    ]

    loaded_tx = LoadedTx(tx, utxos)

    assert loaded_tx.tx is tx
    assert loaded_tx.utxos == utxos
    assert loaded_tx.input_total == 1_500
    assert loaded_tx.output_total == 1_200
    assert loaded_tx.fee == 300
    assert loaded_tx.utxo_for_input(1) == utxos[1]


def test_loaded_tx_rejects_missing_utxos():
    tx = Tx(
        inputs=[TxIn(b"\x11" * 32, 0, b"", 0xffffffff)],
        outputs=[TxOut(900, b"\x51")],
    )

    with pytest.raises(ValueError, match="one UTXO per input"):
        LoadedTx(tx, [])


def test_loaded_tx_rejects_misaligned_utxos():
    expected_outpoint = b"\x11" * 32 + (0).to_bytes(4, "little")
    wrong_outpoint = b"\x22" * 32 + (0).to_bytes(4, "little")
    tx = Tx(
        inputs=[TxIn(expected_outpoint[:32], expected_outpoint[32:], b"", 0xffffffff)],
        outputs=[TxOut(900, b"\x51")],
    )

    with pytest.raises(ValueError, match="expected"):
        LoadedTx(tx, UTXO(wrong_outpoint, 1_000, b"\x51", 100))


def test_loaded_tx_rejects_negative_fee():
    outpoint = b"\x11" * 32 + (0).to_bytes(4, "little")
    tx = Tx(
        inputs=[TxIn(outpoint[:32], outpoint[32:], b"", 0xffffffff)],
        outputs=[TxOut(1_001, b"\x51")],
    )
    loaded_tx = LoadedTx(tx, UTXO(outpoint, 1_000, b"\x51", 100))

    with pytest.raises(TransactionError, match="Negative fee"):
        _ = loaded_tx.fee


def test_validate_loaded_tx_rejects_duplicate_inputs():
    outpoint = b"\x11" * 32 + (0).to_bytes(4, "little")
    tx = Tx(
        inputs=[
            TxIn(outpoint[:32], outpoint[32:], b"", 0xffffffff),
            TxIn(outpoint[:32], outpoint[32:], b"", 0xffffffff),
        ],
        outputs=[TxOut(900, b"\x51")],
    )
    loaded_tx = LoadedTx(
        tx,
        [
            UTXO(outpoint, 1_000, b"\x51", 100),
            UTXO(outpoint, 1_000, b"\x51", 100),
        ],
    )

    assert not validate_loaded_tx(loaded_tx, TxValidationContext(validate_scripts=False))


def test_validate_loaded_tx_uses_injected_script_validator():
    outpoint = b"\x11" * 32 + (0).to_bytes(4, "little")
    tx = Tx(
        inputs=[TxIn(outpoint[:32], outpoint[32:], b"", 0xffffffff)],
        outputs=[TxOut(900, b"\x51")],
    )
    loaded_tx = LoadedTx(tx, UTXO(outpoint, 1_000, b"\x51", 100))

    assert validate_loaded_tx(
        loaded_tx,
        TxValidationContext(validate_scripts=True, script_validator=lambda candidate: candidate is loaded_tx),
    )
    assert not validate_loaded_tx(
        loaded_tx,
        TxValidationContext(validate_scripts=True, script_validator=lambda candidate: False),
    )
