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
    mp.mempool = {}
    mp.total_vbytes = 0
    mp.spent_outpoints = set()
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
