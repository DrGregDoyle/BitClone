from pathlib import Path
from types import SimpleNamespace

import pytest

from src.block.block import Block
from src.blockchain.blockchain import Blockchain, COINBASE_MATURITY, MAX_BLOCK_SIGOP_COST, WITNESS_SCALE_FACTOR
from src.blockchain.genesis_block import genesis_block
from src.data import bits_to_target, target_to_bits
from src.tx.tx import LoadedTx, Tx, TxIn, TxOut, UTXO
from tests.script_vectors import *

TEST_DB_PATH = Path(__file__).parent / "db_files" / "test_blockchain.db"


def _insert_utxos(chain: Blockchain, utxos: list[UTXO]) -> None:
    for utxo in utxos:
        chain.db.add_utxo(utxo)


def _dummy_tx(spent_outpoint: bytes, amount: int = 900) -> Tx:
    return Tx(
        inputs=[
            TxIn(
                txid=spent_outpoint[:32],
                vout=spent_outpoint[32:],
                scriptsig=b"",
                sequence=0xffffffff,
            )
        ],
        outputs=[TxOut(amount=amount, scriptpubkey=b"\x51")],
    )


def _coinbase_tx(scriptsig: bytes = b"\x01\x01", amount: int = 0, scriptpubkey: bytes = b"\x51") -> Tx:
    return Tx(
        inputs=[TxIn(b"\x00" * 32, 0xffffffff, scriptsig, 0xffffffff)],
        outputs=[TxOut(amount=amount, scriptpubkey=scriptpubkey)],
    )


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
        build_p2pk_case, build_p2pkh_case, build_p2ms_case, build_p2wsh_case, build_p2tr_keypath_case,
        build_p2sh_p2ms_case,
        build_p2sh_p2wpkh_case,
        build_p2wpkh_case,
        build_p2tr_scriptpath_case,
    ],
)
def test_validate_tx_scripts_matches_known_script_pairs(chain, case_builder):
    case = case_builder()
    _insert_utxos(chain, case.utxos)

    # print(f"SCRIPT VALIDATION: {case.to_json()}")

    assert chain._validate_tx_scripts(case.tx, case.utxos), (
        f"_validate_tx_scripts failed for known-valid case: {case.name}"
    )


def test_validate_tx_scripts_accepts_loaded_tx(chain):
    case = build_p2pkh_case()
    _insert_utxos(chain, case.utxos)

    assert chain._validate_tx_scripts(LoadedTx(case.tx, case.utxos)), (
        "_validate_tx_scripts failed for LoadedTx"
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
    chain._validate_tx_scripts = lambda tx, utxos=None: True

    funding_outpoint = b"\x11" * 32 + (0).to_bytes(4, "little")
    chain.db.add_utxo(
        UTXO(
            outpoint=funding_outpoint,
            amount=1_000,
            scriptpubkey=b"\x51",
            block_height=chain.height,
        )
    )

    tx_a = _dummy_tx(funding_outpoint)
    tx_b = _dummy_tx(funding_outpoint)
    block = Block(prev_block=chain.tip.block_id, txs=[genesis_block.txs[0], tx_a, tx_b])

    assert not chain._validate_block_txs(block), (
        "Block with intra-block double spend unexpectedly passed validation"
    )


def test_validate_tx_accepts_pending_utxo_from_same_block(chain):
    chain._validate_tx_scripts = lambda tx, utxos=None: True

    funding_outpoint = b"\x22" * 32 + (0).to_bytes(4, "little")
    chain.db.add_utxo(
        UTXO(
            outpoint=funding_outpoint,
            amount=1_000,
            scriptpubkey=b"\x51",
            block_height=chain.height,
        )
    )

    parent_tx = _dummy_tx(funding_outpoint, amount=900)
    child_outpoint = parent_tx.txid + (0).to_bytes(4, "little")
    child_tx = _dummy_tx(child_outpoint, amount=800)
    block = Block(prev_block=chain.tip.block_id, txs=[genesis_block.txs[0], parent_tx, child_tx])

    assert chain._validate_block_txs(block), (
        "Tx spending pending UTXO from earlier in same block failed validation"
    )


def test_validate_block_rejects_empty_tx_list(chain):
    block = Block(prev_block=chain.tip.block_id, txs=[_coinbase_tx()])
    block.txs = []

    assert not chain._validate_block(block)


def test_validate_block_rejects_duplicate_txids(chain):
    chain.validate_pow = lambda block: True
    coinbase_tx = _coinbase_tx()
    block = Block(
        prev_block=chain.tip.block_id,
        timestamp=max(chain.tip.timestamp + 1, 1_600_000_000),
        bits=chain.bits,
        txs=[coinbase_tx, coinbase_tx],
    )

    assert not chain._validate_block(block)


@pytest.mark.parametrize("scriptsig", [b"\x51", b"\x51" * 101])
def test_validate_coinbase_rejects_script_size_outside_consensus_limits(chain, scriptsig):
    block = Block(prev_block=chain.tip.block_id, txs=[_coinbase_tx(scriptsig=scriptsig)])

    assert not chain._validate_coinbase(block)


def test_block_sigop_cost_counts_legacy_signature_ops(chain):
    checksigs = (MAX_BLOCK_SIGOP_COST // WITNESS_SCALE_FACTOR) + 1
    block = Block(prev_block=chain.tip.block_id, txs=[_coinbase_tx(scriptpubkey=b"\xac" * checksigs)])

    assert chain._block_sigop_cost(block) == checksigs * WITNESS_SCALE_FACTOR
    assert chain._block_sigop_cost(block) > MAX_BLOCK_SIGOP_COST


def test_count_sigops_skips_pushed_data(chain):
    script = bytes([1, 0xac]) + b"\xac"

    assert chain._count_sigops(script) == 1


def test_validate_block_timestamp_rejects_timestamp_at_mtp(chain):
    block = Block(prev_block=chain.tip.block_id, timestamp=chain.tip.timestamp, bits=chain.bits, txs=[_coinbase_tx()])

    assert not chain._validate_block_timestamp(block, current_time=chain.tip.timestamp)


def test_validate_block_timestamp_rejects_more_than_two_hours_in_future(chain):
    now = 1_700_000_000
    block = Block(prev_block=chain.tip.block_id, timestamp=now + 7201, bits=chain.bits, txs=[_coinbase_tx()])

    assert not chain._validate_block_timestamp(block, current_time=now)


def test_expected_bits_uses_current_bits_between_retargets(chain):
    assert chain._expected_bits_for_height(chain.height + 1) == chain.bits


def test_expected_bits_retargets_at_interval_boundary(chain):
    chain._height = 2015
    chain._target = (1000).to_bytes(32, "big")
    chain._tip = SimpleNamespace(timestamp=Blockchain.TWO_WEEK_SECONDS)
    chain.get_block_at_height = lambda height: SimpleNamespace(timestamp=0)

    assert chain._expected_bits_for_height(2016) == target_to_bits((1000).to_bytes(32, "big"))


def test_retarget_window_constant_uses_seconds():
    assert Blockchain.TWO_WEEK_SECONDS == 14 * 24 * 60 * 60


def test_adjust_target_keeps_target_when_window_takes_two_weeks(chain):
    chain._height = 2016
    chain._target = (1000).to_bytes(32, "big")
    chain._tip = SimpleNamespace(timestamp=Blockchain.TWO_WEEK_SECONDS)
    chain.get_block_at_height = lambda height: SimpleNamespace(timestamp=0)

    chain._adjust_target()

    assert int.from_bytes(chain.target, "big") == 1000


def test_adjust_target_clamps_to_quarter_window(chain):
    chain._height = 2016
    chain._target = (1000).to_bytes(32, "big")
    chain._tip = SimpleNamespace(timestamp=1)
    chain.get_block_at_height = lambda height: SimpleNamespace(timestamp=0)

    chain._adjust_target()

    assert int.from_bytes(chain.target, "big") == 250


def test_adjust_target_clamps_to_four_times_window(chain):
    chain._height = 2016
    chain._target = (1000).to_bytes(32, "big")
    chain._tip = SimpleNamespace(timestamp=Blockchain.TWO_WEEK_SECONDS * 10)
    chain.get_block_at_height = lambda height: SimpleNamespace(timestamp=0)

    chain._adjust_target()

    assert int.from_bytes(chain.target, "big") == 4000


def test_adjust_target_never_exceeds_genesis_target(chain):
    genesis_target = bits_to_target(Blockchain.GENESIS_BLOCK_BITS)
    chain._height = 2016
    chain._target = genesis_target
    chain._tip = SimpleNamespace(timestamp=Blockchain.TWO_WEEK_SECONDS * 4)
    chain.get_block_at_height = lambda height: SimpleNamespace(timestamp=0)

    chain._adjust_target()

    assert chain.target == genesis_target


def test_best_header_can_differ_from_active_tip(chain):
    high_work_header = Block(
        prev_block=chain.tip.block_id,
        bits=b"\x1c\x00\xff\xff",
        txs=[genesis_block.txs[0]],
    )
    chain.db.add_block_index(high_work_header, block_height=chain.height + 1, active=False)

    assert chain.get_best_header().block_hash == high_work_header.block_id
    assert chain.tip == genesis_block


def test_would_reorganize_to_higher_work_inactive_header(chain):
    high_work_header = Block(
        prev_block=chain.tip.block_id,
        bits=b"\x1c\x00\xff\xff",
        txs=[genesis_block.txs[0]],
    )
    chain.db.add_block_index(high_work_header, block_height=chain.height + 1, active=False)

    assert chain.would_reorganize_to(high_work_header.block_id)


def test_reorganize_to_is_not_implemented_until_undo_data_exists(chain):
    high_work_header = Block(
        prev_block=chain.tip.block_id,
        bits=b"\x1c\x00\xff\xff",
        txs=[genesis_block.txs[0]],
    )
    chain.db.add_block_index(high_work_header, block_height=chain.height + 1, active=False)

    with pytest.raises(NotImplementedError):
        chain.reorganize_to(high_work_header.block_id)
