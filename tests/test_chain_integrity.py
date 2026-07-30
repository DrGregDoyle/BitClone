"""Atomic chain-state, orphan-block, and checkpoint regression tests."""
from dataclasses import replace
from types import MappingProxyType

import pytest

from src.block.block import Block
from src.blockchain.blockchain import Blockchain
from src.blockchain.genesis_block import genesis_block
from src.blockchain.orphan_pool import OrphanBlockPool
from src.core import NetworkDataError, NetworkName
from src.tx import Tx, TxIn, TxOut


def _coinbase(marker: int) -> Tx:
    return Tx(
        inputs=[
            TxIn(
                b"\x00" * 32,
                0xffffffff,
                b"\x02" + marker.to_bytes(2, "little"),
                0xffffffff,
            )
        ],
        outputs=[TxOut(0, b"\x51")],
    )


def _block(parent: Block, marker: int, transactions: tuple[Tx, ...] = ()) -> Block:
    return Block(
        version=4,
        prev_block=parent.block_id,
        timestamp=parent.timestamp + 1,
        bits=parent.bits,
        nonce=marker,
        txs=[_coinbase(marker), *transactions],
    )


def _file_sizes(blocks_dir) -> dict[str, int]:
    return {
        path.name: path.stat().st_size
        for path in blocks_dir.glob("blk*.dat")
    }


@pytest.mark.parametrize("storage_mode", ["archival", "pruned"])
def test_tip_connection_rolls_back_database_and_block_file_on_fault(
        tmp_path,
        monkeypatch,
        storage_mode,
):
    blocks_dir = tmp_path / "blocks"
    chain = Blockchain(
        db_path=tmp_path / "chain.db",
        blocks_dir=blocks_dir,
        network=NetworkName.REGTEST,
        storage_mode=storage_mode,
        prune_keep_blocks=2,
    )
    chain._validate_block = lambda block: True
    candidate = _block(chain.tip, 1)
    original_tip = chain.tip.block_id
    original_utxos = chain.utxo_count()
    original_files = _file_sizes(blocks_dir)

    def fail_after_utxo_write(spent_outpoints, created_utxos, conn):
        conn.execute("DELETE FROM utxos")
        raise RuntimeError("injected chainstate failure")

    monkeypatch.setattr(chain.db, "_apply_utxo_delta", fail_after_utxo_write)
    try:
        assert not chain.add_block(candidate)
        assert chain.tip.block_id == original_tip
        assert chain.height == 0
        assert chain.utxo_count() == original_utxos
        assert chain.db.get_block_index(candidate.block_id) is None
        assert not chain.db.has_block_body(candidate.block_id)
        assert _file_sizes(blocks_dir) == original_files
    finally:
        chain.close()


def test_reorganization_is_one_transaction_when_candidate_activation_faults(tmp_path, monkeypatch):
    chain = Blockchain(
        db_path=tmp_path / "chain.db",
        network=NetworkName.REGTEST,
    )
    chain._validate_block = lambda block: True
    chain._validate_side_block_candidate = lambda *args: True
    active_one = _block(chain.tip, 11)
    active_two = _block(active_one, 12)
    assert chain.add_block(active_one)
    assert chain.add_block(active_two)

    side_one = _block(genesis_block, 21)
    side_two = _block(side_one, 22)
    side_three = _block(side_two, 23)
    assert chain.add_block(side_one)
    assert chain.add_block(side_two)

    original_activate = chain.db.activate_chain_block
    activations = 0

    def fail_second_activation(*args, **kwargs):
        nonlocal activations
        activations += 1
        if activations == 2:
            kwargs["conn"].execute("DELETE FROM utxos")
            raise RuntimeError("injected reorganization failure")
        return original_activate(*args, **kwargs)

    monkeypatch.setattr(chain.db, "activate_chain_block", fail_second_activation)
    try:
        assert not chain.add_block(side_three)
        assert chain.tip.block_id == active_two.block_id
        assert chain.height == 2
        assert chain.get_block_at_height(1).block_id == active_one.block_id
        assert chain.get_block_at_height(2).block_id == active_two.block_id
        assert chain.db.get_block_index(active_one.block_id).active
        assert chain.db.get_block_index(active_two.block_id).active
        assert not chain.db.get_block_index(side_one.block_id).active
        assert chain.utxo_count() == 3
    finally:
        chain.close()


def test_startup_reconciles_uncommitted_archival_file_tail(tmp_path):
    db_path = tmp_path / "chain.db"
    blocks_dir = tmp_path / "blocks"
    chain = Blockchain(
        db_path=db_path,
        blocks_dir=blocks_dir,
        network=NetworkName.REGTEST,
    )
    committed_sizes = _file_sizes(blocks_dir)
    chain.db.block_store.write_block(b"\x44" * 32, b"uncommitted body")
    assert _file_sizes(blocks_dir) != committed_sizes
    chain.close()

    recovered = Blockchain(
        db_path=db_path,
        blocks_dir=blocks_dir,
        network=NetworkName.REGTEST,
    )
    try:
        assert _file_sizes(blocks_dir) == committed_sizes
        assert recovered.tip.block_id == genesis_block.block_id
    finally:
        recovered.close()


def test_orphan_child_connects_automatically_after_parent_arrives(tmp_path):
    chain = Blockchain(
        db_path=tmp_path / "chain.db",
        network=NetworkName.REGTEST,
    )
    chain._validate_block = lambda block: True
    chain._validate_orphan_candidate = lambda block: True
    parent = _block(chain.tip, 31)
    child = _block(parent, 32)
    try:
        assert not chain.add_block(child)
        assert len(chain.orphans) == 1
        assert chain.db.get_block_index(child.block_id) is None

        assert chain.add_block(parent)
        assert len(chain.orphans) == 0
        assert chain.tip.block_id == child.block_id
        assert chain.height == 2
    finally:
        chain.close()


def test_orphan_pool_evicts_oldest_block_at_capacity():
    pool = OrphanBlockPool(max_blocks=2)
    first = _block(genesis_block, 41)
    second = _block(genesis_block, 42)
    third = _block(genesis_block, 43)

    assert pool.add(first, added_at=1)
    assert pool.add(second, added_at=2)
    assert pool.add(third, added_at=3)

    assert len(pool) == 2
    assert first.block_id not in pool
    assert second.block_id in pool
    assert third.block_id in pool


def test_checkpoint_rejects_conflicting_block_and_header(tmp_path):
    chain = Blockchain(
        db_path=tmp_path / "chain.db",
        network=NetworkName.REGTEST,
    )
    accepted = _block(chain.tip, 51)
    conflicting = _block(chain.tip, 52)
    chain.chain_params = replace(
        chain.chain_params,
        checkpoints=MappingProxyType({1: accepted.block_id}),
    )
    chain._validate_block = lambda block: True
    chain._validate_header_pow = lambda header: True
    try:
        assert not chain.add_block(conflicting)
        with pytest.raises(NetworkDataError, match="checkpoint"):
            chain.add_headers([conflicting.get_header()])

        assert chain.add_block(accepted)
        assert chain.tip.block_id == accepted.block_id
    finally:
        chain.close()


def test_mainnet_checkpoint_map_contains_known_good_historical_blocks():
    from src.core import get_chain_params

    checkpoints = get_chain_params(NetworkName.MAINNET).checkpoints

    assert checkpoints[0] == genesis_block.block_id
    assert 91_842 in checkpoints
    assert 91_880 in checkpoints
    assert 227_931 in checkpoints
    assert 481_824 in checkpoints
    assert 692_261 in checkpoints
    with pytest.raises(TypeError):
        checkpoints[1] = b"\x00" * 32
