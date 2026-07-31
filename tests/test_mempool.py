"""
Tests for MemPool.add_tx() - Vibecaded by Claude

Each test is self-contained: it spins up a fresh in-memory SQLite database,
seeds it with whatever UTXOs the test needs, builds a transaction that spends
them, then calls add_tx() and asserts the expected outcome.

Run with:
    python -m pytest tests/test_mempool.py -v
or directly:
    python tests/test_mempool.py
"""
import os
import unittest
from random import randint
from unittest.mock import MagicMock, patch

from src.core import TX
from src.mempool.mempool import MemPool, MemPoolTx
from src.mempool.orphan_pool import OrphanTransactionPool
from src.mempool.policy import AdmissionCategory
from src.script import P2SH_Key, P2WPKH_Key
from src.tx import TxIn, TxOut, Tx, UTXO


# ---------------------------------------------------------------------------
# Helpers / factories
# ---------------------------------------------------------------------------

ANYONE_CAN_SPEND_REDEEM_SCRIPT = b'\x51'
ANYONE_CAN_SPEND_SCRIPTSIG = b'\x01\x51'
ANYONE_CAN_SPEND_SCRIPTPUBKEY = P2SH_Key.from_data(ANYONE_CAN_SPEND_REDEEM_SCRIPT).script

def make_txid() -> bytes:
    """Return 32 random bytes to use as a fake previous txid."""
    return os.urandom(32)


def make_utxo(txid: bytes, vout: int = 0, amount: int = 100_000,
              scriptpubkey: bytes = ANYONE_CAN_SPEND_SCRIPTPUBKEY) -> UTXO:
    """
    Build a UTXO. The default is P2SH-wrapped OP_1 (anyone-can-spend), so it
    exercises a recognized script template without requiring a signature.
    """
    outpoint = txid + vout.to_bytes(TX.VOUT, "little")
    return UTXO(outpoint=outpoint, amount=amount, scriptpubkey=scriptpubkey, block_height=randint(1, 1_000_000))


def make_spending_tx(utxos: list[UTXO], output_amount: int,
                     sequence: int = 0xffffffff) -> Tx:
    """
    Build an unsigned transaction that spends every UTXO in the list and
    sends output_amount sats to a P2SH-wrapped OP_1 anyone-can-spend output.

    The fee is implicitly:  sum(utxo.amount) - output_amount
    """
    inputs = [
        TxIn(
            txid=u.outpoint[:32],
            vout=u.outpoint[32:],
            scriptsig=ANYONE_CAN_SPEND_SCRIPTSIG,
            sequence=sequence,
        )
        for u in utxos
    ]
    outputs = [TxOut(amount=output_amount, scriptpubkey=ANYONE_CAN_SPEND_SCRIPTPUBKEY)]
    return Tx(inputs=inputs, outputs=outputs)


def make_mempool_with_utxos(utxos: list[UTXO]) -> MemPool:
    """
    Return a MemPool whose database is pre-seeded with the given UTXOs.
    The database itself is replaced with a lightweight mock so the tests have
    no filesystem dependency.
    """
    mp = MemPool.__new__(MemPool)  # skip __init__ so we control everything
    mp.max_size = MemPool.MAX_SIZE
    mp.max_time = MemPool.MAX_TIME
    mp.min_fee = MemPool.MIN_FEE
    mp.max_block_weight = MemPool.MAX_BLOCK_WEIGHT
    mp.max_ancestor_count = MemPool.MAX_ANCESTOR_COUNT
    mp.max_ancestor_vbytes = MemPool.MAX_ANCESTOR_VBYTES
    mp.max_descendant_count = MemPool.MAX_DESCENDANT_COUNT
    mp.max_descendant_vbytes = MemPool.MAX_DESCENDANT_VBYTES
    mp.max_replacement_evictions = MemPool.MAX_REPLACEMENT_EVICTIONS
    mp.mempool = {}
    mp.total_vbytes = 0
    mp.spent_outpoints = set()
    mp.spends = {}
    mp.orphans = OrphanTransactionPool()
    mp.rolling_min_fee = 0.0
    mp.rolling_fee_updated_at = 0
    # Build a dict of outpoint -> UTXO so the mock db can serve lookups
    utxo_map = {u.outpoint: u for u in utxos}

    mock_db = MagicMock()
    mock_db.get_utxo.side_effect = lambda outpoint: utxo_map.get(outpoint)
    mp.btcdb = mock_db

    return mp


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestAddTxHappyPath(unittest.TestCase):

    def test_mempool_record_normalizes_bytes_and_owns_metadata_lists(self):
        tx = make_spending_tx([make_utxo(make_txid())], output_amount=90_000)

        with patch("src.mempool.mempool.time.time", side_effect=[10.9, 11.2]):
            first = MemPoolTx(tx.to_bytes(), fee=10_000)
            second = MemPoolTx(tx, fee=10_000)

        self.assertIsInstance(first.tx, Tx)
        self.assertEqual(first.tx.to_bytes(), tx.to_bytes())
        self.assertIsNot(first.ancestors, second.ancestors)
        self.assertIsNot(first.descendants, second.descendants)
        self.assertEqual(first.arrival_time, 10)
        self.assertEqual(second.arrival_time, 11)

    def test_mempool_record_retains_mutable_identity_semantics(self):
        tx = make_spending_tx([make_utxo(make_txid())], output_amount=90_000)
        first = MemPoolTx(tx, fee=10_000)
        second = MemPoolTx(tx, fee=10_000)

        first.ancestors.append(second)
        second.descendants.append(first)

        self.assertIs(first.ancestors[0], second)
        self.assertNotEqual(first, second)
        self.assertIs(MemPoolTx.__eq__, object.__eq__)
        self.assertIs(MemPoolTx.__hash__, object.__hash__)
        self.assertIs(MemPoolTx.__repr__, object.__repr__)

    def test_short_p2sh_redeem_script_is_not_misclassified_as_p2wpkh(self):
        self.assertFalse(P2WPKH_Key.matches(ANYONE_CAN_SPEND_REDEEM_SCRIPT))

    def test_valid_single_input_tx_is_accepted(self):
        """A well-formed tx with a known UTXO and positive fee is accepted."""
        txid = make_txid()
        utxo = make_utxo(txid, amount=100_000)
        mp = make_mempool_with_utxos([utxo])

        tx = make_spending_tx([utxo], output_amount=90_000)  # 10 000 sat fee
        raw_tx = tx.to_bytes()

        result = mp.add_tx(raw_tx)

        self.assertTrue(result)
        self.assertIn(tx.txid, mp.mempool)

    def test_valid_multi_input_tx_is_accepted(self):
        """A tx spending two UTXOs is accepted and has both inputs recorded."""
        txid_a = make_txid()
        txid_b = make_txid()
        utxo_a = make_utxo(txid_a, vout=0, amount=50_000)
        utxo_b = make_utxo(txid_b, vout=1, amount=50_000)
        mp = make_mempool_with_utxos([utxo_a, utxo_b])

        tx = make_spending_tx([utxo_a, utxo_b], output_amount=95_000)  # 5 000 sat fee
        result = mp.add_tx(tx.to_bytes())

        self.assertTrue(result)
        self.assertEqual(len(mp.mempool), 1)

    def test_mempooltx_fee_is_calculated_correctly(self):
        """The MemPoolTx stored in the pool carries the correct fee."""
        txid = make_txid()
        utxo = make_utxo(txid, amount=200_000)
        mp = make_mempool_with_utxos([utxo])

        tx = make_spending_tx([utxo], output_amount=175_000)  # 25 000 sat fee
        mp.add_tx(tx.to_bytes())

        stored: MemPoolTx = mp.mempool[tx.txid]
        self.assertEqual(stored.fee, 25_000)

    def test_ancestor_is_detected_when_input_references_mempool_tx(self):
        """
        When a tx input references a txid already in the mempool, that txid
        should appear in the new MemPoolTx's ancestors list.
        """
        # First tx goes into the mempool
        txid_a = make_txid()
        utxo_a = make_utxo(txid_a, amount=100_000)
        mp = make_mempool_with_utxos([utxo_a])

        parent_tx = make_spending_tx([utxo_a], output_amount=90_000)
        mp.add_tx(parent_tx.to_bytes())

        # Second tx spends the output of the first tx
        # Its UTXO must also be in the mock db (simulates an unconfirmed output)
        child_utxo = make_utxo(parent_tx.txid, vout=0, amount=90_000)
        mp.btcdb.get_utxo.side_effect = lambda op: (
            child_utxo if op == child_utxo.outpoint[:32] + (0).to_bytes(4, 'little') else None
        )

        child_tx = make_spending_tx([child_utxo], output_amount=80_000)
        mp.add_tx(child_tx.to_bytes())

        child_mempool_tx: MemPoolTx = mp.mempool[child_tx.txid]
        self.assertEqual(len(child_mempool_tx.ancestors), 1)
        self.assertIs(child_mempool_tx.ancestors[0], mp.mempool[parent_tx.txid])

    def test_unconfirmed_parent_output_is_resolved_without_database_entry(self):
        utxo = make_utxo(make_txid(), amount=100_000)
        mp = make_mempool_with_utxos([utxo])
        parent = make_spending_tx([utxo], output_amount=90_000)
        child_input = make_utxo(parent.txid, amount=90_000)
        child = make_spending_tx([child_input], output_amount=80_000)

        self.assertTrue(mp.add_tx(parent))
        self.assertTrue(mp.add_tx(child))
        self.assertEqual(mp.mempool[child.txid].fee, 10_000)

    def test_ancestors_and_descendants_are_transitive(self):
        utxo = make_utxo(make_txid(), amount=100_000)
        mp = make_mempool_with_utxos([utxo])
        parent = make_spending_tx([utxo], output_amount=90_000)
        child = make_spending_tx(
            [make_utxo(parent.txid, amount=90_000)],
            output_amount=80_000,
        )
        grandchild = make_spending_tx(
            [make_utxo(child.txid, amount=80_000)],
            output_amount=70_000,
        )

        self.assertTrue(mp.add_tx(parent))
        self.assertTrue(mp.add_tx(child))
        self.assertTrue(mp.add_tx(grandchild))

        self.assertEqual(
            [entry.tx.txid for entry in mp.mempool[grandchild.txid].ancestors],
            [parent.txid, child.txid],
        )
        self.assertEqual(
            {entry.tx.txid for entry in mp.mempool[parent.txid].descendants},
            {child.txid, grandchild.txid},
        )


class TestMempoolDependencies(unittest.TestCase):

    def test_ancestor_count_limit_includes_candidate(self):
        utxo = make_utxo(make_txid(), amount=100_000)
        mp = make_mempool_with_utxos([utxo])
        mp.max_ancestor_count = 2
        parent = make_spending_tx([utxo], output_amount=90_000)
        child = make_spending_tx(
            [make_utxo(parent.txid, amount=90_000)],
            output_amount=80_000,
        )
        grandchild = make_spending_tx(
            [make_utxo(child.txid, amount=80_000)],
            output_amount=70_000,
        )

        self.assertTrue(mp.add_tx(parent))
        self.assertTrue(mp.add_tx(child))
        self.assertFalse(mp.add_tx(grandchild))
        self.assertNotIn(grandchild.txid, mp)

    def test_descendant_count_limit_rejects_second_branch(self):
        utxo = make_utxo(make_txid(), amount=200_000)
        mp = make_mempool_with_utxos([utxo])
        mp.max_descendant_count = 2
        parent = Tx(
            inputs=[
                TxIn(
                    txid=utxo.outpoint[:32],
                    vout=utxo.outpoint[32:],
                    scriptsig=ANYONE_CAN_SPEND_SCRIPTSIG,
                    sequence=0xffffffff,
                )
            ],
            outputs=[
                TxOut(90_000, ANYONE_CAN_SPEND_SCRIPTPUBKEY),
                TxOut(90_000, ANYONE_CAN_SPEND_SCRIPTPUBKEY),
            ],
        )
        first_child = make_spending_tx(
            [make_utxo(parent.txid, vout=0, amount=90_000)],
            output_amount=80_000,
        )
        second_child = make_spending_tx(
            [make_utxo(parent.txid, vout=1, amount=90_000)],
            output_amount=80_000,
        )

        self.assertTrue(mp.add_tx(parent))
        self.assertTrue(mp.add_tx(first_child))
        self.assertFalse(mp.add_tx(second_child))
        self.assertNotIn(second_child.txid, mp)

    def test_template_selects_high_fee_package_in_dependency_order(self):
        parent_utxo = make_utxo(make_txid(), amount=100_000)
        independent_utxo = make_utxo(make_txid(), amount=100_000)
        mp = make_mempool_with_utxos([parent_utxo, independent_utxo])
        parent = make_spending_tx([parent_utxo], output_amount=99_900)
        child = make_spending_tx(
            [make_utxo(parent.txid, amount=99_900)],
            output_amount=90_000,
        )
        independent = make_spending_tx([independent_utxo], output_amount=99_000)

        self.assertTrue(mp.add_tx(parent))
        self.assertTrue(mp.add_tx(child))
        self.assertTrue(mp.add_tx(independent))
        mp.max_block_weight = parent.wu + child.wu

        template = mp.get_block_template()

        self.assertEqual([tx.txid for tx in template], [parent.txid, child.txid])

    def test_orphan_is_promoted_when_parent_arrives(self):
        utxo = make_utxo(make_txid(), amount=100_000)
        mp = make_mempool_with_utxos([utxo])
        parent = make_spending_tx([utxo], output_amount=90_000)
        child = make_spending_tx(
            [make_utxo(parent.txid, amount=90_000)],
            output_amount=80_000,
        )

        self.assertFalse(mp.add_tx(child))
        self.assertIn(child.txid, mp.orphans)
        self.assertTrue(mp.add_tx(parent))

        self.assertNotIn(child.txid, mp.orphans)
        self.assertIn(child.txid, mp)

    def test_orphan_is_promoted_when_parent_is_confirmed(self):
        mp = make_mempool_with_utxos([])
        parent_txid = make_txid()
        parent_output = make_utxo(parent_txid, amount=90_000)
        child = make_spending_tx([parent_output], output_amount=80_000)

        self.assertFalse(mp.add_tx(child))
        self.assertIn(child.txid, mp.orphans)
        mp.btcdb.get_utxo.side_effect = (
            lambda outpoint: parent_output if outpoint == parent_output.outpoint else None
        )

        mp.confirm_block([parent_txid])

        self.assertNotIn(child.txid, mp.orphans)
        self.assertIn(child.txid, mp)

    def test_orphan_pool_evicts_oldest_entry_at_count_limit(self):
        pool = OrphanTransactionPool(max_count=1)
        first = make_spending_tx(
            [make_utxo(make_txid(), amount=100_000)],
            output_amount=90_000,
        )
        second = make_spending_tx(
            [make_utxo(make_txid(), amount=100_000)],
            output_amount=90_000,
        )

        self.assertTrue(pool.add(first, {first.inputs[0].txid}))
        self.assertTrue(pool.add(second, {second.inputs[0].txid}))

        self.assertNotIn(first.txid, pool)
        self.assertIn(second.txid, pool)


class TestReplacementPolicy(unittest.TestCase):

    def test_signaled_transaction_can_be_replaced_for_higher_fee(self):
        utxo = make_utxo(make_txid(), amount=100_000)
        mp = make_mempool_with_utxos([utxo])
        original = make_spending_tx(
            [utxo],
            output_amount=90_000,
            sequence=0xfffffffd,
        )
        replacement = make_spending_tx(
            [utxo],
            output_amount=89_000,
            sequence=0xfffffffd,
        )

        self.assertTrue(mp.add_tx(original))
        result = mp.accept_tx(replacement)

        self.assertTrue(result.accepted)
        self.assertEqual(result.category, AdmissionCategory.ACCEPTED)
        self.assertEqual(result.replaced_txids, (original.txid,))
        self.assertNotIn(original.txid, mp)
        self.assertIn(replacement.txid, mp)

    def test_non_signaled_conflict_cannot_be_replaced(self):
        utxo = make_utxo(make_txid(), amount=100_000)
        mp = make_mempool_with_utxos([utxo])
        original = make_spending_tx([utxo], output_amount=90_000)
        replacement = make_spending_tx(
            [utxo],
            output_amount=80_000,
            sequence=0xfffffffd,
        )

        self.assertTrue(mp.add_tx(original))
        result = mp.accept_tx(replacement)

        self.assertFalse(result.accepted)
        self.assertEqual(result.category, AdmissionCategory.POLICY)
        self.assertIn("does not signal", result.reason)
        self.assertIn(original.txid, mp)

    def test_replacement_removes_conflict_descendants_and_covers_their_fees(self):
        utxo = make_utxo(make_txid(), amount=100_000)
        mp = make_mempool_with_utxos([utxo])
        original = make_spending_tx(
            [utxo],
            output_amount=99_000,
            sequence=0xfffffffd,
        )
        child = make_spending_tx(
            [make_utxo(original.txid, amount=99_000)],
            output_amount=98_000,
        )
        insufficient = make_spending_tx(
            [utxo],
            output_amount=98_000,
            sequence=0xfffffffd,
        )
        replacement = make_spending_tx(
            [utxo],
            output_amount=97_000,
            sequence=0xfffffffd,
        )

        self.assertTrue(mp.add_tx(original))
        self.assertTrue(mp.add_tx(child))
        rejected = mp.accept_tx(insufficient)
        accepted = mp.accept_tx(replacement)

        self.assertFalse(rejected.accepted)
        self.assertIn("incremental relay fee", rejected.reason)
        self.assertTrue(accepted.accepted)
        self.assertEqual(set(accepted.replaced_txids), {original.txid, child.txid})
        self.assertNotIn(original.txid, mp)
        self.assertNotIn(child.txid, mp)

    def test_replacement_cannot_add_a_new_unconfirmed_input(self):
        conflict_utxo = make_utxo(make_txid(), amount=100_000)
        parent_a_utxo = make_utxo(make_txid(), amount=100_000)
        parent_b_utxo = make_utxo(make_txid(), amount=100_000)
        mp = make_mempool_with_utxos([conflict_utxo, parent_a_utxo, parent_b_utxo])
        parent_a = make_spending_tx([parent_a_utxo], output_amount=90_000)
        parent_b = make_spending_tx([parent_b_utxo], output_amount=90_000)
        original = make_spending_tx(
            [conflict_utxo, make_utxo(parent_a.txid, amount=90_000)],
            output_amount=180_000,
            sequence=0xfffffffd,
        )
        replacement = make_spending_tx(
            [conflict_utxo, make_utxo(parent_b.txid, amount=90_000)],
            output_amount=170_000,
            sequence=0xfffffffd,
        )

        self.assertTrue(mp.add_tx(parent_a))
        self.assertTrue(mp.add_tx(parent_b))
        self.assertTrue(mp.add_tx(original))
        result = mp.accept_tx(replacement)

        self.assertFalse(result.accepted)
        self.assertIn("new unconfirmed input", result.reason)
        self.assertIn(original.txid, mp)

    def test_inherited_rbf_signal_allows_descendant_replacement(self):
        root_utxo = make_utxo(make_txid(), amount=100_000)
        mp = make_mempool_with_utxos([root_utxo])
        signaling_parent = make_spending_tx(
            [root_utxo],
            output_amount=90_000,
            sequence=0xfffffffd,
        )
        original = make_spending_tx(
            [make_utxo(signaling_parent.txid, amount=90_000)],
            output_amount=89_000,
        )
        replacement = make_spending_tx(
            [make_utxo(signaling_parent.txid, amount=90_000)],
            output_amount=88_000,
        )

        self.assertTrue(mp.add_tx(signaling_parent))
        self.assertTrue(mp.add_tx(original))
        result = mp.accept_tx(replacement)

        self.assertTrue(result.accepted)
        self.assertNotIn(original.txid, mp)
        self.assertIn(signaling_parent.txid, mp)

    def test_replacement_eviction_set_is_bounded(self):
        utxo = make_utxo(make_txid(), amount=100_000)
        mp = make_mempool_with_utxos([utxo])
        mp.max_replacement_evictions = 1
        original = make_spending_tx(
            [utxo],
            output_amount=99_000,
            sequence=0xfffffffd,
        )
        child = make_spending_tx(
            [make_utxo(original.txid, amount=99_000)],
            output_amount=98_000,
        )
        replacement = make_spending_tx(
            [utxo],
            output_amount=90_000,
            sequence=0xfffffffd,
        )

        self.assertTrue(mp.add_tx(original))
        self.assertTrue(mp.add_tx(child))
        result = mp.accept_tx(replacement)

        self.assertFalse(result.accepted)
        self.assertIn("would evict 2", result.reason)


class TestMempoolPressurePolicy(unittest.TestCase):

    def test_full_mempool_evicts_lowest_feerate_transaction(self):
        low_utxo = make_utxo(make_txid(), amount=100_000)
        high_utxo = make_utxo(make_txid(), amount=100_000)
        mp = make_mempool_with_utxos([low_utxo, high_utxo])
        low_fee = make_spending_tx([low_utxo], output_amount=99_000)
        high_fee = make_spending_tx([high_utxo], output_amount=90_000)
        mp.max_size = high_fee.vbytes

        self.assertTrue(mp.add_tx(low_fee))
        self.assertTrue(mp.add_tx(high_fee))

        self.assertNotIn(low_fee.txid, mp)
        self.assertIn(high_fee.txid, mp)
        self.assertLessEqual(mp.total_vbytes, mp.max_size)

    def test_eviction_raises_rolling_minimum_relay_fee(self):
        low_utxo = make_utxo(make_txid(), amount=100_000)
        high_utxo = make_utxo(make_txid(), amount=100_000)
        later_utxo = make_utxo(make_txid(), amount=100_000)
        mp = make_mempool_with_utxos([low_utxo, high_utxo, later_utxo])
        low_fee = make_spending_tx([low_utxo], output_amount=99_000)
        high_fee = make_spending_tx([high_utxo], output_amount=90_000)
        later_low_fee = make_spending_tx([later_utxo], output_amount=99_000)
        mp.max_size = high_fee.vbytes

        self.assertTrue(mp.add_tx(low_fee))
        self.assertTrue(mp.add_tx(high_fee))
        result = mp.accept_tx(later_low_fee)

        self.assertGreater(mp.get_min_relay_feerate(), mp.min_fee)
        self.assertFalse(result.accepted)
        self.assertIn("fee too low", result.reason)

    def test_rolling_minimum_fee_decays_by_half_life(self):
        mp = make_mempool_with_utxos([])
        mp.rolling_min_fee = 8.0
        mp.rolling_fee_updated_at = 1_000

        self.assertEqual(
            mp.get_min_relay_feerate(1_000 + MemPool.ROLLING_FEE_HALFLIFE),
            4.0,
        )


class TestAdmissionCategories(unittest.TestCase):

    def test_consensus_invalid_transaction_has_distinct_category(self):
        utxo = make_utxo(make_txid(), amount=100_000)
        mp = make_mempool_with_utxos([utxo])
        tx = make_spending_tx([utxo], output_amount=90_000)
        tx.inputs[0].scriptsig = b'\x01\x00'

        result = mp.accept_tx(tx)

        self.assertFalse(result.accepted)
        self.assertEqual(result.category, AdmissionCategory.CONSENSUS_INVALID)

    def test_consensus_valid_nonstandard_output_has_distinct_category(self):
        utxo = make_utxo(make_txid(), amount=100_000)
        mp = make_mempool_with_utxos([utxo])
        tx = Tx(
            inputs=[
                TxIn(
                    txid=utxo.outpoint[:32],
                    vout=utxo.outpoint[32:],
                    scriptsig=ANYONE_CAN_SPEND_SCRIPTSIG,
                    sequence=0xffffffff,
                )
            ],
            outputs=[TxOut(amount=90_000, scriptpubkey=b"\x51")],
        )

        result = mp.accept_tx(tx)

        self.assertFalse(result.accepted)
        self.assertEqual(result.category, AdmissionCategory.NONSTANDARD)
        self.assertIn("non-standard output", result.reason)


class TestAddTxRejectionCases(unittest.TestCase):

    def test_script_validation_is_enabled(self):
        """Mempool admission must execute scripts for every candidate tx."""
        utxo = make_utxo(make_txid(), amount=100_000)
        mp = make_mempool_with_utxos([utxo])
        tx = make_spending_tx([utxo], output_amount=90_000)

        with patch("src.mempool.mempool.validate_loaded_tx", return_value=True) as validate:
            self.assertTrue(mp.add_tx(tx))

        context = validate.call_args.args[1]
        self.assertTrue(context.validate_scripts)

    def test_script_validation_error_rejects_transaction(self):
        """Malformed scripts are ignored instead of escaping peer admission."""
        utxo = make_utxo(make_txid(), amount=100_000)
        mp = make_mempool_with_utxos([utxo])
        tx = make_spending_tx([utxo], output_amount=90_000)

        with patch(
                "src.mempool.mempool.validate_loaded_tx",
                side_effect=ValueError("malformed script"),
        ):
            result = mp.add_tx(tx)

        self.assertFalse(result)
        self.assertNotIn(tx.txid, mp.mempool)

    def test_invalid_redeem_script_is_rejected(self):
        """A scriptSig that does not satisfy its spent output is rejected."""
        utxo = make_utxo(make_txid(), amount=100_000)
        mp = make_mempool_with_utxos([utxo])
        tx = make_spending_tx([utxo], output_amount=90_000)
        tx.inputs[0].scriptsig = b'\x01\x00'

        self.assertFalse(mp.add_tx(tx))
        self.assertNotIn(tx.txid, mp.mempool)

    def test_duplicate_tx_is_rejected(self):
        """The same tx submitted twice should be rejected the second time."""
        txid = make_txid()
        utxo = make_utxo(txid, amount=100_000)
        mp = make_mempool_with_utxos([utxo])

        tx = make_spending_tx([utxo], output_amount=90_000)
        raw_tx = tx.to_bytes()

        first = mp.add_tx(raw_tx)
        second = mp.add_tx(raw_tx)

        self.assertTrue(first)
        self.assertFalse(second)
        self.assertEqual(len(mp.mempool), 1)

    def test_tx_with_unknown_utxo_is_rejected(self):
        """
        A tx whose input references an outpoint not in the UTXO set should
        raise ReadError (from _get_utxos) and therefore be rejected.
        """
        mp = make_mempool_with_utxos([])  # empty UTXO set

        phantom_utxo = make_utxo(make_txid(), amount=100_000)
        tx = make_spending_tx([phantom_utxo], output_amount=90_000)

        result = mp.add_tx(tx.to_bytes())
        self.assertFalse(result)

    def test_tx_with_outputs_exceeding_inputs_is_rejected(self):
        """A tx where outputs > inputs (negative fee) must be rejected."""
        txid = make_txid()
        utxo = make_utxo(txid, amount=50_000)
        mp = make_mempool_with_utxos([utxo])

        # Trying to spend more than the input provides
        tx = make_spending_tx([utxo], output_amount=60_000)
        result = mp.add_tx(tx.to_bytes())

        self.assertFalse(result)

    def test_tx_below_minimum_feerate_is_rejected(self):
        """A positive fee below the configured sat/vbyte floor is rejected."""
        utxo = make_utxo(make_txid(), amount=100_000)
        mp = make_mempool_with_utxos([utxo])
        tx = make_spending_tx([utxo], output_amount=99_999)

        self.assertGreater(tx.vbytes, 1)
        self.assertFalse(mp.add_tx(tx))

    def test_coinbase_tx_is_rejected(self):
        """
        A coinbase tx (txid = 0x00*32, vout = 0xffffffff) must not enter the
        mempool — they are only valid inside a block.
        """
        mp = make_mempool_with_utxos([])

        coinbase_input = TxIn(
            txid=b'\x00' * 32,
            vout=0xffffffff,
            scriptsig=b'\x03\x01\x00\x00',  # block height push
            sequence=0xffffffff,
        )
        coinbase_output = TxOut(amount=625_000_000, scriptpubkey=b'\x51')
        coinbase_tx = Tx(inputs=[coinbase_input], outputs=[coinbase_output])

        result = mp.add_tx(coinbase_tx.to_bytes())
        self.assertFalse(result)

    def test_malformed_bytes_are_rejected(self):
        """
        Completely invalid bytes should be caught at deserialisation and
        return False rather than raising an uncaught exception.
        """
        mp = make_mempool_with_utxos([])
        result = mp.add_tx(b'\xde\xad\xbe\xef')
        self.assertFalse(result)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
