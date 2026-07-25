"""Selected Bitcoin Core transaction vectors supported by Bitclone validation."""

import json
from pathlib import Path

import pytest

from src.tx.tx import LoadedTx, Tx, UTXO
from src.tx.validation import MAX_MONEY, TxValidationContext, validate_loaded_tx


VECTOR_PATH = Path(__file__).parent / "data" / "bitcoin_core_tx_subset.json"
VECTOR_DATA = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "vector",
    VECTOR_DATA["vectors"],
    ids=lambda vector: f"core-{vector['source_file']}-{vector['source_index']}",
)
def test_bitcoin_core_transaction_structure_vector(vector):
    raw_tx = bytes.fromhex(vector["raw_tx"])
    tx = Tx.from_bytes(raw_tx)
    loaded_tx = LoadedTx(
        tx,
        [
            UTXO(
                outpoint=txin.outpoint,
                amount=MAX_MONEY,
                scriptpubkey=b"\x51",
                block_height=0,
            )
            for txin in tx.inputs
        ],
    )

    actual = validate_loaded_tx(
        loaded_tx,
        TxValidationContext(validate_scripts=False),
    )

    assert actual is vector["expected"]
    assert tx.to_bytes() == raw_tx


def test_bitcoin_core_transaction_vector_sources_are_pinned():
    commit = VECTOR_DATA["source_commit"]
    assert commit == "e34b8d5a7dcd45e4faa3bb5fdeae64bf049037f6"
    assert commit in VECTOR_DATA["valid_source"]
    assert commit in VECTOR_DATA["invalid_source"]
    assert VECTOR_DATA["license"] == "MIT"
