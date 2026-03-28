# """
# Tests for the Blockchain and related classes
# """
# from pathlib import Path
#
# from src.blockchain.blockchain import Blockchain
# from src.blockchain.genesis_block import genesis_block
#
# TEST_DB_PATH = Path(__file__).parent / "db_files" / "test_blockchain.db"
#
#
# def test_genesis_block():
#     """
#     We verify that a new Blockchain object is created with the official genesis block as block at index 0
#     """
#     # --- Delete db file
#     TEST_DB_PATH.unlink(missing_ok=True)
#
#     # --- Create new blockchain
#     test_blockchain = Blockchain(db_path=TEST_DB_PATH)
#
#     # --- All new blockchains should have genesis_block as tip
#     assert test_blockchain.tip == genesis_block, "New blockchain does not have genesis block as first block."
#
#     # --- Wipe chain. Should still have genesis block as tip
#     test_blockchain.wipe_chain()
#     assert test_blockchain.tip == genesis_block, ("New blockchain after wiping does not have genesis block as first "
#                                                   "block.")
#
#     # --- Check UTXO set
#     genesis_coinbase = genesis_block.txs[0]
#     outpoint = genesis_coinbase.txid + (0).to_bytes(4, "little")  # txid + vout index
#
#     utxo = test_blockchain.get_utxo(outpoint)
#
#     assert utxo is not None, "Genesis coinbase UTXO not found in UTXO set"
#     assert utxo.amount == 5_000_000_000, f"Genesis UTXO amount incorrect: {utxo.amount}"
#     assert utxo.is_coinbase, "Genesis UTXO should be marked as coinbase"
#     assert utxo.block_height == 0, f"Genesis UTXO block height should be 0, got {utxo.block_height}"
"""
Tests for the Blockchain and blockchain-level script validation.
"""
from pathlib import Path

from src.blockchain.blockchain import Blockchain
from src.blockchain.genesis_block import genesis_block
from src.tx.tx import UTXO

TEST_DB_PATH = Path(__file__).parent / "db_files" / "test_blockchain.db"


def _cleanup_db() -> None:
    TEST_DB_PATH.unlink(missing_ok=True)


def _new_blockchain(script_engine) -> Blockchain:
    _cleanup_db()
    chain = Blockchain(db_path=TEST_DB_PATH)
    chain.script_engine = script_engine
    return chain


def _insert_utxos(chain: Blockchain, utxos: list[UTXO]) -> None:
    for utxo in utxos:
        chain.db.add_utxo(utxo)


def test_genesis_block():
    """
    We verify that a new Blockchain object is created with the official genesis block as block at index 0.
    """
    _cleanup_db()
    test_blockchain = Blockchain(db_path=TEST_DB_PATH)

    assert test_blockchain.tip == genesis_block, "New blockchain does not have genesis block as first block."

    test_blockchain.wipe_chain()
    assert test_blockchain.tip == genesis_block, (
        "New blockchain after wiping does not have genesis block as first block."
    )

    genesis_coinbase = genesis_block.txs[0]
    outpoint = genesis_coinbase.txid + (0).to_bytes(4, "little")
    utxo = test_blockchain.get_utxo(outpoint)

    assert utxo is not None, "Genesis coinbase UTXO not found in UTXO set"
    assert utxo.amount == 5_000_000_000, f"Genesis UTXO amount incorrect: {utxo.amount}"
    assert utxo.is_coinbase, "Genesis UTXO should be marked as coinbase"
    assert utxo.block_height == 0, f"Genesis UTXO block height should be 0, got {utxo.block_height}"

# @pytest.mark.parametrize(
#     "case_builder",
#     [
#         build_p2pk_case,
#         build_p2pkh_case,
#         build_p2ms_case,
#         build_p2sh_p2ms_case,
#         build_p2sh_p2wpkh_case,
#         build_p2wpkh_case,
#         build_p2wsh_case,
#         build_p2tr_keypath_case,
#         build_p2tr_scriptpath_case,
#     ],
# )
# def test_validate_tx_scripts_matches_known_script_pairs(script_engine, case_builder):
#     """
#     Blockchain-level script validation should accept the same known-good spends
#     as the direct script-engine tests.
#     """
#     chain = _new_blockchain(script_engine)
#     case = case_builder()
#     _insert_utxos(chain, case.utxos)
#
#     assert chain._validate_tx_scripts(case.tx, case.utxos), (
#         f"_validate_tx_scripts failed for known-valid case: {case.name}"
#     )
#
#
# def test_validate_tx_scripts_rejects_modified_scriptsig(script_engine):
#     """
#     Mutating a known-good scriptsig should fail blockchain-level validation.
#     """
#     chain = _new_blockchain(script_engine)
#     case = build_p2pkh_case()
#     _insert_utxos(chain, case.utxos)
#
#     bad_tx = case.tx.clone()
#     bad_script = bytearray(bad_tx.inputs[0].scriptsig)
#     bad_script[-1] ^= 0x01
#     bad_tx.inputs[0].scriptsig = bytes(bad_script)
#
#     assert not chain._validate_tx_scripts(bad_tx, case.utxos), (
#         "Mutated scriptsig unexpectedly passed _validate_tx_scripts"
#     )
#
#
# def test_validate_tx_missing_utxo_fails(script_engine):
#     """
#     _validate_tx should reject spends of missing prevouts.
#     """
#     chain = _new_blockchain(script_engine)
#     case = build_p2pkh_case()
#
#     assert not chain._validate_tx(
#         tx=case.tx,
#         block=genesis_block,
#         next_height=chain.height + 1,
#         pending_utxos={},
#         seen_outpoints=set(),
#     ), "Tx with missing UTXO unexpectedly passed validation"
#
#
# def test_validate_tx_immature_coinbase_fails(script_engine):
#     """
#     Spending a coinbase before maturity must fail.
#     """
#     chain = _new_blockchain(script_engine)
#     case = build_p2pkh_case()
#
#     immature_utxo = UTXO(
#         outpoint=case.utxos[0].outpoint,
#         amount=case.utxos[0].amount,
#         scriptpubkey=case.utxos[0].scriptpubkey,
#         block_height=chain.height + 1,
#         is_coinbase=True,
#     )
#     chain.db.add_utxo(immature_utxo)
#
#     assert not chain._validate_tx(
#         tx=case.tx,
#         block=genesis_block,
#         next_height=chain.height + COINBASE_MATURITY,
#         pending_utxos={},
#         seen_outpoints=set(),
#     ), "Immature coinbase spend unexpectedly passed validation"
#
#
# def test_validate_tx_detects_intrablock_double_spend(script_engine):
#     """
#     The second spend of the same outpoint in a block must fail.
#     """
#     chain = _new_blockchain(script_engine)
#     case = build_p2pkh_case()
#     _insert_utxos(chain, case.utxos)
#
#     seen_outpoints = set()
#
#     assert chain._validate_tx(
#         tx=case.tx,
#         block=genesis_block,
#         next_height=chain.height + 1,
#         pending_utxos={},
#         seen_outpoints=seen_outpoints,
#     ), "First spend should have passed"
#
#     assert not chain._validate_tx(
#         tx=case.tx,
#         block=genesis_block,
#         next_height=chain.height + 1,
#         pending_utxos={},
#         seen_outpoints=seen_outpoints,
#     ), "Second spend of same outpoint unexpectedly passed"
#
#
# def test_validate_tx_accepts_pending_utxo_from_same_block(script_engine):
#     """
#     A tx should be allowed to spend an output created earlier in the same block.
#     """
#     chain = _new_blockchain(script_engine)
#     case = build_p2pkh_case()
#
#     pending_utxos = {case.utxos[0].outpoint: case.utxos[0]}
#
#     assert chain._validate_tx(
#         tx=case.tx,
#         block=genesis_block,
#         next_height=chain.height + 1,
#         pending_utxos=pending_utxos,
#         seen_outpoints=set(),
#     ), "Tx spending a pending intra-block UTXO unexpectedly failed"
