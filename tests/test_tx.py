"""
A file for testing Transaction and its related classes. Both decoding and encoding
"""
from src.cipher import decode_outpoint, decode_utxo
from tests.utility import random_outpoint, random_utxo


def test_outpoint():
    _t = random_outpoint()
    t1 = decode_outpoint(_t.bytes)
    t2 = decode_outpoint(_t.hex)

    assert t1.bytes == _t.bytes
    assert t2.bytes == _t.bytes


def test_utxo():
    _u = random_utxo()
    u1 = decode_utxo(_u.bytes)
    u2 = decode_utxo(_u.hex)

    assert u1.bytes == _u.bytes
    assert u2.bytes == _u.bytes
# def test_witness_item():
#     _wi = random_witness_item()
#     wi1 = decode_witness_item(_wi.bytes)
#     wi2 = decode_witness_item(_wi.hex)
#
#     assert wi1.bytes == _wi.bytes
#     assert wi2.bytes == _wi.bytes
#
#
# def test_witness():
#     item_num = randint(1, 10)
#     _w = random_witness(item_num)
#     w1 = decode_witness(_w.bytes)
#     w2 = decode_witness(_w.hex)
#
#     assert w1.bytes == _w.bytes
#     assert w2.bytes == _w.bytes
#
#
# def test_txinput():
#     _ti = random_txinput()
#     tx1 = decode_input(_ti.bytes)
#     tx2 = decode_input(_ti.hex)
#
#     assert tx1.bytes == _ti.bytes
#     assert tx2.bytes == _ti.bytes
#
#
# def test_txoutput():
#     _to = random_txoutput()
#     tx1 = decode_output(_to.bytes)
#     tx2 = decode_output(_to.hex)
#
#     assert tx1.bytes == _to.bytes
#     assert tx2.bytes == _to.bytes

# def test_tx():
#     # Random nums
#     input_num1 = randint(1, 10)
#     input_num2 = randint(1, 10)
#     output_num1 = randint(1, 10)
#     output_num2 = randint(1, 10)
#
#     # Legacy
#     _tx = random_tx(input_num=input_num1, output_num=output_num1, segwit=False)
#     tx1 = decode_transaction(_tx.bytes)
#     tx2 = decode_transaction(_tx.hex)
#
#     assert tx1.bytes == _tx.bytes
#     assert tx2.bytes == _tx.bytes
#     assert _tx.txid == _tx.wtxid
#
#     # Segwit
#     _txs = random_tx(input_num=input_num2, output_num=output_num2, segwit=True)
#     tx3 = decode_transaction(_txs.bytes)
#     tx4 = decode_transaction(_txs.hex)
#
#     assert tx3.bytes == _txs.bytes
#     assert tx4.bytes == _txs.bytes
#     assert _txs.txid != _txs.wtxid
