"""Block-level consensus regressions for Sprint 6 Story 6.3."""

from types import SimpleNamespace

import pytest

from src.block.block import Block
from src.blockchain.blockchain import (
    Blockchain,
    WITNESS_COMMITMENT_HEADER,
)
from src.core import NetworkName, TX
from src.cryptography import hash256
from src.data import bits_to_target, MerkleTree
from src.tx.tx import Tx, TxIn, TxOut, UTXO, Witness


def _height_script(height: int) -> bytes:
    encoded = height.to_bytes((height.bit_length() + 7) // 8 or 1, "little")
    if encoded[-1] & 0x80:
        encoded += b"\x00"
    return bytes([len(encoded)]) + encoded


def _coinbase(height: int, amount: int = 0) -> Tx:
    return Tx(
        inputs=[
            TxIn(
                b"\x00" * 32,
                0xffffffff,
                _height_script(height),
                0xffffffff,
            )
        ],
        outputs=[TxOut(amount, b"\x51")],
    )


@pytest.fixture()
def chain(tmp_path):
    blockchain = Blockchain(
        db_path=tmp_path / "chain.db",
        network=NetworkName.REGTEST,
    )
    yield blockchain
    blockchain.close()


def _candidate(chain: Blockchain, txs: list[Tx]) -> Block:
    return Block(
        prev_block=chain.tip.block_id,
        timestamp=chain.tip.timestamp + 1,
        bits=chain.bits,
        txs=txs,
    )


def test_full_block_validation_rejects_header_merkle_mismatch(chain, monkeypatch):
    block = _candidate(chain, [_coinbase(1)])
    block.merkle_tree.merkle_root = b"\xff" * 32
    monkeypatch.setattr(chain, "validate_pow", lambda candidate: True)

    assert not chain._validate_block(block)


def test_proof_of_work_accepts_hash_exactly_equal_to_target():
    bits = bytes.fromhex("1d00ffff")
    target = int.from_bytes(bits_to_target(bits), "big")
    candidate = SimpleNamespace(
        bits=bits,
        block_id=target.to_bytes(32, "little"),
    )

    assert Blockchain.validate_pow(candidate)


def test_proof_of_work_rejects_hash_one_above_target():
    bits = bytes.fromhex("1d00ffff")
    target = int.from_bytes(bits_to_target(bits), "big")
    candidate = SimpleNamespace(
        bits=bits,
        block_id=(target + 1).to_bytes(32, "little"),
    )

    assert not Blockchain.validate_pow(candidate)


def test_coinbase_rejects_reward_one_satoshi_over_subsidy(chain):
    block = _candidate(chain, [_coinbase(1, chain.block_subsidy + 1)])

    assert not chain._validate_coinbase(block, block_height=1)


def test_coinbase_accepts_subsidy_plus_fees_but_not_more(chain):
    funding_outpoint = b"\x11" * 32 + (0).to_bytes(TX.VOUT, "little")
    chain.db.add_utxo(UTXO(funding_outpoint, 1_000, b"\x51", 0))
    spend = Tx(
        inputs=[TxIn(funding_outpoint[:32], funding_outpoint[32:], b"", 0xffffffff)],
        outputs=[TxOut(900, b"\x51")],
    )
    exact = _candidate(chain, [_coinbase(1, chain.block_subsidy + 100), spend])
    excessive = _candidate(chain, [_coinbase(1, chain.block_subsidy + 101), spend])

    assert chain._validate_coinbase(exact, block_height=1)
    assert not chain._validate_coinbase(excessive, block_height=1)


def test_witness_commitment_is_checked_when_only_coinbase_has_witness(chain):
    reserved_value = b"\x22" * 32
    coinbase = _coinbase(1)
    coinbase.witness = [Witness([reserved_value])]
    block = _candidate(chain, [coinbase])
    witness_root = MerkleTree([b"\x00" * TX.TXID]).merkle_root
    commitment = hash256(witness_root + reserved_value)
    coinbase.outputs.append(TxOut(0, WITNESS_COMMITMENT_HEADER + commitment))

    assert chain._validate_witness_commitment(block, block_height=1)

    coinbase.outputs[-1] = TxOut(
        0,
        WITNESS_COMMITMENT_HEADER + b"\xff" * 32,
    )
    assert not chain._validate_witness_commitment(block, block_height=1)


def test_witness_data_without_commitment_is_rejected(chain):
    coinbase = _coinbase(1)
    coinbase.witness = [Witness([b"\x00" * 32])]
    block = _candidate(chain, [coinbase])

    assert not chain._validate_witness_commitment(block, block_height=1)
