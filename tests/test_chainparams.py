from dataclasses import replace
from types import MappingProxyType

import pytest

from src.block.block import Block
from src.blockchain.blockchain import Blockchain
from src.blockchain.genesis_block import genesis_block
from src.core import (
    CHAIN_PARAMS,
    MAINNET_CHAIN_PARAMS,
    NetworkName,
    ScriptVerifyFlag,
    get_chain_params,
)
from src.tx.tx import LoadedTx, Tx, TxIn, TxOut, UTXO, Witness
from src.tx.validation import validate_tx_scripts
from src.script.sig_ops import _decode_lax_der_signature
from src.data import decode_der_signature, encode_der_signature


def _coinbase(scriptsig: bytes) -> Tx:
    return Tx(
        inputs=[TxIn(b"\x00" * 32, 0xffffffff, scriptsig, 0xffffffff)],
        outputs=[TxOut(0, b"\x51")],
    )


def _spend(scriptpubkey: bytes, witness: list[bytes]) -> tuple[Tx, UTXO]:
    outpoint = b"\x42" * 32 + (0).to_bytes(4, "little")
    tx = Tx(
        inputs=[TxIn(outpoint[:32], outpoint[32:], b"", 0xffffffff)],
        outputs=[TxOut(1, b"\x51")],
        witness=[Witness(witness)],
    )
    return tx, UTXO(outpoint, 2, scriptpubkey, 0)


def test_all_supported_networks_have_canonical_chain_params():
    assert set(CHAIN_PARAMS) == set(NetworkName)
    for network in NetworkName:
        params = get_chain_params(network)
        assert params.network is network
        assert len(params.genesis_hash) == 32
        assert get_chain_params(network.value) is params


@pytest.mark.parametrize(
    ("network", "bip34", "bip65", "bip66", "segwit", "taproot"),
    [
        (NetworkName.MAINNET, 227_931, 388_381, 363_725, 481_824, 709_632),
        (NetworkName.TESTNET, 21_111, 581_885, 330_776, 834_624, 2_011_968),
        (NetworkName.REGTEST, 1, 1, 1, 0, 0),
        (NetworkName.SIGNET, 1, 1, 1, 1, 0),
    ],
)
def test_historical_activation_heights(network, bip34, bip65, bip66, segwit, taproot):
    params = get_chain_params(network)
    assert params.bip34_height == bip34
    assert params.bip65_height == bip65
    assert params.bip66_height == bip66
    assert params.segwit_height == segwit
    assert params.taproot_height == taproot


def test_mainnet_consensus_flags_change_at_exact_activation_boundaries():
    params = MAINNET_CHAIN_PARAMS
    before = params.consensus_script_flags(
        params.bip66_height - 1,
        block_time=params.bip16_activation_time,
    )
    at_bip66 = params.consensus_script_flags(
        params.bip66_height,
        block_time=params.bip16_activation_time,
    )
    at_bip65 = params.consensus_script_flags(
        params.bip65_height,
        block_time=params.bip16_activation_time,
    )
    at_segwit = params.consensus_script_flags(
        params.segwit_height,
        block_time=params.bip16_activation_time,
    )
    at_taproot = params.consensus_script_flags(
        params.taproot_height,
        block_time=params.bip16_activation_time,
    )

    assert before == ScriptVerifyFlag.P2SH
    assert at_bip66 & ScriptVerifyFlag.DERSIG
    assert at_bip65 & ScriptVerifyFlag.CHECKLOCKTIMEVERIFY
    assert at_segwit & ScriptVerifyFlag.WITNESS
    assert at_taproot & ScriptVerifyFlag.TAPROOT


def test_bip16_activation_time_and_historical_exception_are_exact():
    params = MAINNET_CHAIN_PARAMS
    assert not params.consensus_script_flags(
        200_000,
        block_time=params.bip16_activation_time - 1,
    ) & ScriptVerifyFlag.P2SH
    assert params.consensus_script_flags(
        200_000,
        block_time=params.bip16_activation_time,
    ) & ScriptVerifyFlag.P2SH

    exception_hash = next(
        block_hash
        for block_hash, flags in params.script_flag_exceptions.items()
        if flags == ScriptVerifyFlag.NONE
    )
    assert params.consensus_script_flags(
        200_000,
        block_time=params.bip16_activation_time,
        block_hash=exception_hash,
    ) == ScriptVerifyFlag.NONE


def test_standard_flags_are_policy_layer_over_active_consensus_flags():
    params = get_chain_params(NetworkName.TESTNET)
    consensus = params.consensus_script_flags(500_000, block_time=1_600_000_000)
    standard = params.standard_script_flags(500_000, block_time=1_600_000_000)

    assert standard & consensus == consensus
    assert standard & ScriptVerifyFlag.STRICTENC
    assert standard & ScriptVerifyFlag.MINIMALDATA
    assert standard & ScriptVerifyFlag.NULLDUMMY
    assert standard & ScriptVerifyFlag.CLEANSTACK


def test_pre_bip66_lax_der_parser_accepts_redundant_integer_padding():
    strict_signature = encode_der_signature(1, 2)
    strict_r, strict_s = decode_der_signature(strict_signature)
    r_length = strict_signature[3]
    r_end = 4 + r_length
    padded = (
        b"\x30"
        + bytes([strict_signature[1] + 1])
        + b"\x02"
        + bytes([r_length + 1])
        + b"\x00"
        + strict_signature[4:r_end]
        + strict_signature[r_end:]
    )

    with pytest.raises(ValueError):
        decode_der_signature(padded)
    assert _decode_lax_der_signature(padded) == (strict_r, strict_s)


def test_mainnet_bip34_coinbase_height_is_not_enforced_before_activation(tmp_path):
    chain = Blockchain(db_path=tmp_path / "chain.db", network=NetworkName.MAINNET)
    try:
        block = Block(prev_block=chain.tip.block_id, txs=[_coinbase(b"\x02\x01\x00")])
        assert chain._validate_coinbase(block, block_height=MAINNET_CHAIN_PARAMS.bip34_height - 1)
        assert not chain._validate_coinbase(block, block_height=MAINNET_CHAIN_PARAMS.bip34_height)
    finally:
        chain.close()


def test_pre_activation_witness_program_is_anyone_can_spend():
    tx, utxo = _spend(b"\x00\x14" + b"\x11" * 20, witness=[])
    loaded = LoadedTx(tx, [utxo])

    assert validate_tx_scripts(loaded, flags=ScriptVerifyFlag.P2SH)


def test_bip30_rejects_unspent_overwrite_and_allows_exact_exception(tmp_path):
    candidate = Block(
        prev_block=genesis_block.block_id,
        txs=[_coinbase(b"\x01\x01")],
    )
    exception_params = replace(
        MAINNET_CHAIN_PARAMS,
        bip30_exceptions=MappingProxyType({1: candidate.block_id}),
    )
    chain = Blockchain(
        db_path=tmp_path / "chain.db",
        chain_params=exception_params,
    )
    try:
        outpoint = candidate.txs[0].txid + (0).to_bytes(4, "little")
        chain.db.add_utxo(UTXO(outpoint, 1, b"\x51", 0, True))

        assert not chain._validate_bip30(candidate, 2)
        assert chain._validate_bip30(candidate, 1)
    finally:
        chain.close()
