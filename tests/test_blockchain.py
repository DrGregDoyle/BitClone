from pathlib import Path

import pytest

from src.blockchain.blockchain import Blockchain, COINBASE_MATURITY
from src.blockchain.genesis_block import genesis_block
from src.tx.tx import UTXO
from tests.script_vectors import *

TEST_DB_PATH = Path(__file__).parent / "db_files" / "test_blockchain.db"


def _insert_utxos(chain: Blockchain, utxos: list[UTXO]) -> None:
    for utxo in utxos:
        chain.db.add_utxo(utxo)


@pytest.fixture()
def chain():
    """Fresh Blockchain for each test; db connection closed and file deleted on teardown."""
    TEST_DB_PATH.unlink(missing_ok=True)
    blockchain = Blockchain(db_path=TEST_DB_PATH)
    yield blockchain
    blockchain.db.close()  # release the SQLite file handle
    TEST_DB_PATH.unlink(missing_ok=True)


# ------------------------------------------------------------------ #
#  Tests                                                               #
# ------------------------------------------------------------------ #

def test_genesis_block(chain):
    assert chain.tip == genesis_block, "New blockchain does not have genesis block as first block."

    chain.wipe_chain()
    assert chain.tip == genesis_block, (
        "New blockchain after wiping does not have genesis block as first block."
    )

    genesis_coinbase = genesis_block.txs[0]
    outpoint = genesis_coinbase.txid + (0).to_bytes(4, "little")
    utxo = chain.get_utxo(outpoint)

    assert utxo is not None, "Genesis coinbase UTXO not found in UTXO set"
    assert utxo.amount == 5_000_000_000, f"Genesis UTXO amount incorrect: {utxo.amount}"
    assert utxo.is_coinbase, "Genesis UTXO should be marked as coinbase"
    assert utxo.block_height == 0, f"Genesis UTXO block height should be 0, got {utxo.block_height}"


@pytest.mark.parametrize(
    "case_builder",
    [
        build_p2pk_case, build_p2pkh_case, build_p2ms_case,
        # build_p2sh_p2ms_case, build_p2sh_p2wpkh_case,
        # build_p2wpkh_case, build_p2wsh_case,
        build_p2tr_keypath_case, build_p2tr_scriptpath_case,
    ],
)
def test_validate_tx_scripts_matches_known_script_pairs(chain, case_builder):
    case = case_builder()
    _insert_utxos(chain, case.utxos)

    assert chain._validate_tx_scripts(case.tx, case.utxos), (
        f"_validate_tx_scripts failed for known-valid case: {case.name}"
    )


def test_validate_tx_scripts_rejects_modified_scriptsig(chain):
    case = build_p2pkh_case()
    _insert_utxos(chain, case.utxos)

    bad_tx = case.tx.clone()
    bad_script = bytearray(bad_tx.inputs[0].scriptsig)
    bad_script[-1] ^= 0x01
    bad_tx.inputs[0].scriptsig = bytes(bad_script)

    assert not chain._validate_tx_scripts(bad_tx, case.utxos), (
        "Mutated scriptsig unexpectedly passed _validate_tx_scripts"
    )


def test_validate_tx_missing_utxo_fails(chain):
    case = build_p2pkh_case()

    assert not chain._validate_tx(
        tx=case.tx,
        block=genesis_block,
        next_height=chain.height + 1,
        pending_utxos={},
        seen_outpoints=set(),
    ), "Tx with missing UTXO unexpectedly passed validation"


def test_validate_tx_immature_coinbase_fails(chain):
    case = build_p2pkh_case()

    immature_utxo = UTXO(
        outpoint=case.utxos[0].outpoint,
        amount=case.utxos[0].amount,
        scriptpubkey=case.utxos[0].scriptpubkey,
        block_height=chain.height + 1,
        is_coinbase=True,
    )
    chain.db.add_utxo(immature_utxo)

    assert not chain._validate_tx(
        tx=case.tx,
        block=genesis_block,
        next_height=chain.height + COINBASE_MATURITY,
        pending_utxos={},
        seen_outpoints=set(),
    ), "Immature coinbase spend unexpectedly passed validation"


def test_validate_tx_detects_intrablock_double_spend(chain):
    # Need to refactor this using dummy data
    pass


def test_validate_tx_accepts_pending_utxo_from_same_block(chain):
    # Need to refactor this using dummy data
    pass
