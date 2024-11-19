"""
Tests to verify encoding/decoding
"""
from secrets import randbits

from src.cipher import decompress_public_key, decode_compact_size, decode_endian, decode_outpoint, decode_utxo, \
    decode_witness_item, decode_witness, decode_input, decode_output
from src.wallet import Wallet

from src.library.primitive import CompactSize, Endian
from tests.backup.utility import random_outpoint, random_utxo, random_witness_item, random_witness, random_txinput, \
    random_txoutput


def test_compressed_public_key():
    test_wallet = Wallet()
    recovered_point = decompress_public_key(test_wallet.compressed_public_key)
    assert recovered_point == test_wallet.public_key_point


def test_compact_size():
    num1 = CompactSize(0xfc)
    num2 = CompactSize(0xfd)
    num3 = CompactSize(0xffff)
    num4 = CompactSize(0xffffffff)
    num5 = CompactSize(0xffffffffffffffff)

    assert num1.hex == "fc"
    assert num2.hex == "fdfd00"
    assert num3.hex == "fdffff"
    assert num4.hex == "feffffffff"
    assert num5.hex == "ffffffffffffffffff"
    assert decode_compact_size(num1.hex) == (num1.num, 2)
    assert decode_compact_size(num2.hex) == (num2.num, 6)
    assert decode_compact_size(num3.hex) == (num3.num, 6)
    assert decode_compact_size(num4.hex) == (num4.num, 10)
    assert decode_compact_size(num5.hex) == (num5.num, 18)


def test_endian():
    bit_size = 128
    rand_num = randbits(bit_size)
    test_endian = Endian(rand_num, bit_size // 8)
    de1 = decode_endian(test_endian.hex)
    de2 = decode_endian(test_endian.bytes)

    assert de1 == rand_num
    assert de2 == rand_num


def test_outpoint():
    _outpt = random_outpoint()
    do1 = decode_outpoint(_outpt.hex)
    do2 = decode_outpoint(_outpt.bytes)

    assert do1.tx_id.hex == _outpt.tx_id.hex
    assert do1.v_out.num == _outpt.v_out.num
    assert do2.tx_id.hex == _outpt.tx_id.hex
    assert do2.v_out.num == _outpt.v_out.num


def test_utxo():
    _utxo = random_utxo()
    du1 = decode_utxo(_utxo.hex)
    du2 = decode_utxo(_utxo.bytes)

    assert du1.bytes == _utxo.bytes
    assert du2.bytes == _utxo.bytes


def test_witness_item():
    wi = random_witness_item()
    dwi1 = decode_witness_item(wi.hex)
    dwi2 = decode_witness_item(wi.bytes)
    assert dwi1.bytes == wi.bytes
    assert dwi2.bytes == wi.bytes


def test_witness():
    w = random_witness()
    w1 = decode_witness(w.bytes)
    w2 = decode_witness(w.hex)
    assert w1.bytes == w.bytes
    assert w2.bytes == w.bytes


def test_txinput():
    i = random_txinput()
    i1 = decode_input(i.bytes)
    i2 = decode_input(i.hex)
    assert i1.bytes == i.bytes
    assert i2.bytes == i.bytes


def test_txoutput():
    t = random_txoutput()
    t1 = decode_output(t.bytes)
    t2 = decode_output(t.hex)

    assert t1.bytes == t.bytes
    assert t2.bytes == t.bytes


def test_tx():
    """
    We instead use known txs from Bitcoin instead of randomly generated ones.
    """
    pass
