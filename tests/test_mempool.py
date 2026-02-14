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
from unittest.mock import MagicMock

from src.mempool.mempool import MemPool, MemPoolTx
from src.tx import TxIn, TxOut, Transaction, UTXO


# ---------------------------------------------------------------------------
# Helpers / factories
# ---------------------------------------------------------------------------

def make_txid() -> bytes:
    """Return 32 random bytes to use as a fake previous txid."""
    return os.urandom(32)


def make_utxo(txid: bytes, vout: int = 0, amount: int = 100_000,
              scriptpubkey: bytes = b'\x51') -> UTXO:
    """
    Build a UTXO.  scriptpubkey defaults to OP_1 (anyone-can-spend) so the
    script engine won't reject it while script validation is still a stub.
    """
    return UTXO(txid=txid, vout=vout, amount=amount, scriptpubkey=scriptpubkey)


def make_spending_tx(utxos: list[UTXO], output_amount: int,
                     sequence: int = 0xffffffff) -> Transaction:
    """
    Build an unsigned transaction that spends every UTXO in the list and
    sends output_amount sats to an OP_1 anyone-can-spend output.

    The fee is implicitly:  sum(utxo.amount) - output_amount
    """
    inputs = [
        TxIn(
            txid=u.txid,
            vout=u.vout,
            scriptsig=b'',  # unsigned — mempool doesn't verify scripts yet
            sequence=sequence,
        )
        for u in utxos
    ]
    outputs = [TxOut(amount=output_amount, scriptpubkey=b'\x51')]
    return Transaction(inputs=inputs, outputs=outputs)


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
    mp.script_engine = MagicMock()  # script validation is a stub in mempool

    # Build a dict of outpoint -> UTXO so the mock db can serve lookups
    utxo_map = {u.txid + u.vout.to_bytes(4, 'little'): u for u in utxos}

    mock_db = MagicMock()
    mock_db.get_utxo.side_effect = lambda outpoint: utxo_map.get(outpoint)
    mp.btcdb = mock_db

    return mp


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestAddTxHappyPath(unittest.TestCase):

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
            child_utxo if op == child_utxo.txid + (0).to_bytes(4, 'little') else None
        )

        child_tx = make_spending_tx([child_utxo], output_amount=80_000)
        mp.add_tx(child_tx.to_bytes())

        child_mempool_tx: MemPoolTx = mp.mempool[child_tx.txid]
        self.assertEqual(len(child_mempool_tx.ancestors), 1)
        self.assertIs(child_mempool_tx.ancestors[0], mp.mempool[parent_tx.txid])


class TestAddTxRejectionCases(unittest.TestCase):

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
        coinbase_tx = Transaction(inputs=[coinbase_input], outputs=[coinbase_output])

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
