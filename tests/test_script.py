"""
Tests for BTC Script
"""
from random import randint
from secrets import token_bytes

import pytest

from src.script import ScriptEngine, BTCNum


@pytest.fixture
def engine():
    return ScriptEngine()


def test_op_false(engine):
    op_false_hex = "00"
    op_false_val = engine.eval_script_from_hex(op_false_hex)
    assert not op_false_val, f"Expected false script but received {op_false_val}"


def test_op_pushbytes(engine):
    rand_num = randint(0x01, 0x4b)
    rand_bytes = token_bytes(rand_num)
    op_pushbytes_hex = hex(rand_num)[2:].zfill(2) + rand_bytes.hex()
    engine.eval_script_from_hex(op_pushbytes_hex)
    assert engine.stack.top == rand_bytes, "OP_PUSHBYTES failed for random data"


@pytest.mark.parametrize("op_pushdata_hex, expected", [
    ("4c04deadbeef", "deadbeef"),
    ("4d0400deadbeef", "deadbeef"),
    ("4e04000000deadbeef", "deadbeef"),
])
def test_op_pushdata(engine, op_pushdata_hex, expected):
    engine.eval_script_from_hex(op_pushdata_hex)
    assert engine.stack.top.hex() == expected


def test_op_1negate(engine):
    op_1negate_hex = "4f"
    engine.eval_script_from_hex(op_1negate_hex)
    assert engine.stack.top == b'\x81'


def test_op_num(engine):
    rand_num2 = randint(1, 16)
    op_num_hex = hex(80 + rand_num2)[2:]
    engine.eval_script_from_hex(op_num_hex)
    assert engine.stack.top == BTCNum(rand_num2).bytes


def test_op_nop(engine):
    op_nop_hex = "61"
    engine.eval_script_from_hex(op_nop_hex)
    assert engine.stack.height == 0


def test_op_toaltstack(engine):
    op_toaltstack_hex = "516b"
    engine.eval_script_from_hex(op_toaltstack_hex)
    assert engine.altstack.top == b'\x01'


def test_op_fromaltstack(engine):
    op_fromaltstack_hex = "516b6c"
    engine.eval_script_from_hex(op_fromaltstack_hex)
    assert engine.stack.top == b'\x01'


def test_op_ifdup(engine):
    op_ifdup_hex = "5173"
    engine.eval_script_from_hex(op_ifdup_hex)
    assert engine.stack.stack[0] == engine.stack.stack[1]


def test_op_depth(engine):
    op_depth_hex = "51525374"
    engine.eval_script_from_hex(op_depth_hex)
    assert engine.stack.stack[0] == bytes.fromhex("03")
    assert engine.stack.stack[1] == bytes.fromhex("03")
    assert engine.stack.stack[2] == bytes.fromhex("02")
    assert engine.stack.stack[3] == bytes.fromhex("01")
    assert engine.stack.height == 4


def test_op_drop(engine):
    rand_bytes8 = token_bytes(8)
    op_drop_hex = "5208" + rand_bytes8.hex() + "75"
    engine.eval_script_from_hex(op_drop_hex)
    assert engine.stack.top == bytes.fromhex("02")


def test_op_dup(engine):
    op_dup_hex = "515276"
    engine.eval_script_from_hex(op_dup_hex)
    assert engine.stack.height == 3
    assert engine.stack.stack[0] == bytes.fromhex("02")
    assert engine.stack.stack[1] == bytes.fromhex("02")
    assert engine.stack.stack[2] == bytes.fromhex("01")
