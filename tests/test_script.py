"""
Tests for BTC Script
"""
from random import randint
from secrets import token_bytes

import pytest

from src.library.Script.script import ScriptEngine, BTCNum


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


def test_op_nip(engine):
    op_nip_hex = "51525377"
    engine.eval_script_from_hex(op_nip_hex)
    assert engine.stack.height == 2
    assert engine.stack.stack[0] == bytes.fromhex("03")
    assert engine.stack.stack[1] == bytes.fromhex("01")


def test_op_over(engine):
    op_over_hex = "515278"
    engine.eval_script_from_hex(op_over_hex)
    assert engine.stack.height == 3
    assert engine.stack.stack[0] == bytes.fromhex("01")
    assert engine.stack.stack[1] == bytes.fromhex("02")
    assert engine.stack.stack[2] == bytes.fromhex("01")


def test_op_pick1(engine):
    op_pick_hex = "51525354555279"
    engine.eval_script_from_hex(op_pick_hex)
    assert engine.stack.height == 6
    assert engine.stack.stack[0] == bytes.fromhex("03")
    assert engine.stack.stack[1] == bytes.fromhex("05")
    assert engine.stack.stack[2] == bytes.fromhex("04")
    assert engine.stack.stack[3] == bytes.fromhex("03")
    assert engine.stack.stack[4] == bytes.fromhex("02")
    assert engine.stack.stack[5] == bytes.fromhex("01")


def test_op_pick2(engine):
    op_pick_hex = "5758595a5379"
    engine.eval_script_from_hex(op_pick_hex)
    assert engine.stack.height == 5
    assert engine.stack.stack[0] == bytes.fromhex("07")
    assert engine.stack.stack[1] == bytes.fromhex("0a")
    assert engine.stack.stack[2] == bytes.fromhex("09")
    assert engine.stack.stack[3] == bytes.fromhex("08")
    assert engine.stack.stack[4] == bytes.fromhex("07")


def test_op_roll1(engine):
    op_roll_hex = "5152535455527a"
    engine.eval_script_from_hex(op_roll_hex)
    assert engine.stack.height == 5
    assert engine.stack.stack[0] == bytes.fromhex("03")
    assert engine.stack.stack[1] == bytes.fromhex("05")
    assert engine.stack.stack[2] == bytes.fromhex("04")
    assert engine.stack.stack[3] == bytes.fromhex("02")
    assert engine.stack.stack[4] == bytes.fromhex("01")


def test_op_rot(engine):
    op_roll_hex = "5152537b"
    engine.eval_script_from_hex(op_roll_hex)
    assert engine.stack.height == 3
    assert engine.stack.stack[0] == bytes.fromhex("01")
    assert engine.stack.stack[1] == bytes.fromhex("03")
    assert engine.stack.stack[2] == bytes.fromhex("02")


def test_op_swap(engine):
    op_swap_hex = "5152537c"
    engine.eval_script_from_hex(op_swap_hex)
    assert engine.stack.height == 3
    assert engine.stack.stack[0] == bytes.fromhex("02")
    assert engine.stack.stack[1] == bytes.fromhex("03")
    assert engine.stack.stack[2] == bytes.fromhex("01")


def test_op_tuck1(engine):
    op_tuck_hex = "5152537d"
    engine.eval_script_from_hex(op_tuck_hex)
    assert engine.stack.height == 4
    assert engine.stack.stack[0] == bytes.fromhex("03")
    assert engine.stack.stack[1] == bytes.fromhex("02")
    assert engine.stack.stack[2] == bytes.fromhex("03")
    assert engine.stack.stack[3] == bytes.fromhex("01")


def test_op_tuck2(engine):
    op_tuck_hex = "5152535a5b7d"
    engine.eval_script_from_hex(op_tuck_hex)
    assert engine.stack.height == 6
    assert engine.stack.stack[0] == bytes.fromhex("0b")
    assert engine.stack.stack[1] == bytes.fromhex("0a")
    assert engine.stack.stack[2] == bytes.fromhex("0b")
    assert engine.stack.stack[3] == bytes.fromhex("03")
    assert engine.stack.stack[4] == bytes.fromhex("02")
    assert engine.stack.stack[5] == bytes.fromhex("01")


def test_op_2drop(engine):
    op_2drop_hex = "51526d"
    engine.eval_script_from_hex(op_2drop_hex)
    assert engine.stack.height == 0


def test_op_2dup(engine):
    op_2dup_hex = "51526e"
    engine.eval_script_from_hex(op_2dup_hex)
    assert engine.stack.height == 4
    assert engine.stack.stack[0] == bytes.fromhex("02")
    assert engine.stack.stack[1] == bytes.fromhex("01")
    assert engine.stack.stack[2] == bytes.fromhex("02")
    assert engine.stack.stack[3] == bytes.fromhex("01")


def test_op_3dup(engine):
    op_3dup_hex = "5152536f"
    engine.eval_script_from_hex(op_3dup_hex)
    assert engine.stack.height == 6
    assert engine.stack.stack[0] == bytes.fromhex("03")
    assert engine.stack.stack[1] == bytes.fromhex("02")
    assert engine.stack.stack[2] == bytes.fromhex("01")
    assert engine.stack.stack[3] == bytes.fromhex("03")
    assert engine.stack.stack[4] == bytes.fromhex("02")
    assert engine.stack.stack[5] == bytes.fromhex("01")


def test_op_2over(engine):
    op_2over_hex = "51525354555670"
    engine.eval_script_from_hex(op_2over_hex)
    assert engine.stack.height == 8
    assert engine.stack.stack[0] == bytes.fromhex("04")
    assert engine.stack.stack[1] == bytes.fromhex("03")
    assert engine.stack.stack[2] == bytes.fromhex("06")
    assert engine.stack.stack[3] == bytes.fromhex("05")
    assert engine.stack.stack[4] == bytes.fromhex("04")
    assert engine.stack.stack[5] == bytes.fromhex("03")
    assert engine.stack.stack[6] == bytes.fromhex("02")
    assert engine.stack.stack[7] == bytes.fromhex("01")


def test_op_2rot(engine):
    op_2rot_hex = "51525354555671"
    engine.eval_script_from_hex(op_2rot_hex)
    assert engine.stack.height == 6
    assert engine.stack.stack[0] == bytes.fromhex("02")
    assert engine.stack.stack[1] == bytes.fromhex("01")
    assert engine.stack.stack[2] == bytes.fromhex("06")
    assert engine.stack.stack[3] == bytes.fromhex("05")
    assert engine.stack.stack[4] == bytes.fromhex("04")
    assert engine.stack.stack[5] == bytes.fromhex("03")


def test_op_2swap(engine):
    op_2swap_hex = "51525354555672"
    engine.eval_script_from_hex(op_2swap_hex)
    assert engine.stack.height == 6
    assert engine.stack.stack[0] == bytes.fromhex("04")
    assert engine.stack.stack[1] == bytes.fromhex("03")
    assert engine.stack.stack[2] == bytes.fromhex("06")
    assert engine.stack.stack[3] == bytes.fromhex("05")
    assert engine.stack.stack[4] == bytes.fromhex("02")
    assert engine.stack.stack[5] == bytes.fromhex("01")


def test_op_size1(engine):
    op_2swap_hex = "0082"
    engine.eval_script_from_hex(op_2swap_hex)
    assert engine.stack.height == 2
    assert engine.stack.stack[0] == b''
    assert engine.stack.stack[1] == b''


def test_op_size2(engine):
    op_2swap_hex = "5a82"
    engine.eval_script_from_hex(op_2swap_hex)
    assert engine.stack.height == 2
    assert engine.stack.stack[0] == bytes.fromhex("01")
    assert engine.stack.stack[1] == bytes.fromhex("0a")


def test_op_size3(engine):
    op_2swap_hex = "03a4b5c682"
    engine.eval_script_from_hex(op_2swap_hex)
    assert engine.stack.height == 2
    assert engine.stack.stack[0] == bytes.fromhex("03")
    assert engine.stack.stack[1] == bytes.fromhex("a4b5c6")


def test_op_equal(engine):
    op_equal_hex = "515187"
    engine.eval_script_from_hex(op_equal_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("01")


def test_op_equal_verify(engine):
    op_equal_verify_hex = "515187"
    assert engine.eval_script_from_hex(op_equal_verify_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("01")


def test_op_1add(engine):
    op_1add_hex = "528b"
    assert engine.eval_script_from_hex(op_1add_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("03")


def test_op_1sub(engine):
    op_1add_hex = "528c"
    assert engine.eval_script_from_hex(op_1add_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("01")


def test_op_negate(engine):
    op_negate_hex = "528f"
    assert engine.eval_script_from_hex(op_negate_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("82")


def test_op_abs1(engine):
    op_abs_hex = "528f90"
    assert engine.eval_script_from_hex(op_abs_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("02")


def test_op_abs2(engine):
    op_abs_hex = "4f90"
    assert engine.eval_script_from_hex(op_abs_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("01")


def test_op_not1(engine):
    op_not_hex = "0091"
    assert engine.eval_script_from_hex(op_not_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("01")


def test_op_not2(engine):
    op_not_hex = "5191"
    engine.eval_script_from_hex(op_not_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == b''


def test_op_0notequal1(engine):
    op_not_hex = "5192"
    engine.eval_script_from_hex(op_not_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("01")


def test_op_0notequal2(engine):
    op_not_hex = "0092"
    engine.eval_script_from_hex(op_not_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == b''


def test_op_add(engine):
    op_add_hex = "515193"
    engine.eval_script_from_hex(op_add_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("02")


def test_op_add2(engine):
    op_add_hex = "5253935487"
    engine.eval_script_from_hex(op_add_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == b''


def test_op_sub(engine):
    op_add_hex = "555394"
    engine.eval_script_from_hex(op_add_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("02")


def test_booland(engine):
    op_booland_hex = "51519a"
    assert engine.eval_script_from_hex(op_booland_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("01")


def test_booland2(engine):
    op_booland2_hex = "51009a"
    engine.eval_script_from_hex(op_booland2_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == b''


def test_booland3(engine):
    op_booland3_hex = "00009a"
    engine.eval_script_from_hex(op_booland3_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == b''


def test_booland4(engine):
    op_booland4_hex = "02a4b6559a"
    assert engine.eval_script_from_hex(op_booland4_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("01")


def test_boolor(engine):
    op_boolor_hex = "51519b"
    assert engine.eval_script_from_hex(op_boolor_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("01")


def test_boolor2(engine):
    op_boolor2_hex = "51009b"
    assert engine.eval_script_from_hex(op_boolor2_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("01")


def test_boolor3(engine):
    op_boolor3_hex = "00009b"
    engine.eval_script_from_hex(op_boolor3_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == b''  # bytes.fromhex("00")


def test_boolor4(engine):
    op_boolor4_hex = "02a4b6559b"
    assert engine.eval_script_from_hex(op_boolor4_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("01")


def test_numeq1(engine):
    op_numeq1_hex = "52529c"
    assert engine.eval_script_from_hex(op_numeq1_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("01")


def test_numeq2(engine):
    op_numeq2_hex = "52539c"
    engine.eval_script_from_hex(op_numeq2_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == b''  # bytes.fromhex("01")


def test_numeq3(engine):
    op_numeq3_hex = "0100009c"
    assert engine.eval_script_from_hex(op_numeq3_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("01")


def test_op_return(engine):
    op_return_hex = "51526a5353"
    engine.eval_script_from_hex(op_return_hex)
    assert engine.stack.height == 2
    assert engine.stack.stack[0] == bytes.fromhex("02")
    assert engine.stack.stack[1] == bytes.fromhex("01")


def test_numeq_verify1(engine):
    numeq_verify_hex1 = "51519d"
    engine.eval_script_from_hex(numeq_verify_hex1)
    assert engine.stack.height == 0


def test_numeq_verify2(engine):
    numeq_verify_hex1 = "51529d5151"
    engine.eval_script_from_hex(numeq_verify_hex1)
    assert engine.stack.height == 0


def test_numneq1(engine):
    numneq_hex1 = "51529e"  # Numbers not equal, pushes true to stack
    engine.eval_script_from_hex(numneq_hex1)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("01")


def test_numneq2(engine):
    numneq_hex1 = "51519e"  # Numbers equal, pushes false to stack
    engine.eval_script_from_hex(numneq_hex1)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == b''  # bytes.fromhex("01")


def test_lt1(engine):
    lt_hex1 = "52519f"
    engine.eval_script_from_hex(lt_hex1)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("01")


def test_lt2(engine):
    lt_hex2 = "51529f"
    engine.eval_script_from_hex(lt_hex2)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == b''  # bytes.fromhex("01")


def test_gt1(engine):
    gt_hex1 = "5152a0"
    engine.eval_script_from_hex(gt_hex1)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("01")


def test_gt2(engine):
    gt_hex2 = "5251a0"
    engine.eval_script_from_hex(gt_hex2)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == b''  # bytes.fromhex("01")


def test_leq1(engine):
    lt_hex1 = "5151a15251a1"
    engine.eval_script_from_hex(lt_hex1)
    assert engine.stack.height == 2
    assert engine.stack.stack[0] == bytes.fromhex("01")
    assert engine.stack.stack[0] == bytes.fromhex("01")


def test_leq2(engine):
    lt_hex1 = "5152a1"
    engine.eval_script_from_hex(lt_hex1)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == b''  # bytes.fromhex("01")


def test_geq1(engine):
    lt_hex1 = "5151a15152a2"
    engine.eval_script_from_hex(lt_hex1)
    assert engine.stack.height == 2
    assert engine.stack.stack[0] == bytes.fromhex("01")
    assert engine.stack.stack[0] == bytes.fromhex("01")


def test_geq2(engine):
    lt_hex1 = "5251a2"
    engine.eval_script_from_hex(lt_hex1)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == b''  # bytes.fromhex("01")


def test_min(engine):
    min_hex = "5358a3"
    engine.eval_script_from_hex(min_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("03")


def test_max(engine):
    min_hex = "5358a4"
    engine.eval_script_from_hex(min_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("08")


def test_within1(engine):
    within_hex1 = "525153a5"
    engine.eval_script_from_hex(within_hex1)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("01")


def test_ripemd160(engine):
    """
    Known ripemd160 hash of b'' = 9c1185a5c5e9fc54612808977ee8f548b2258d31
    """
    ripemd160_hex = "00a6"
    engine.eval_script_from_hex(ripemd160_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("9c1185a5c5e9fc54612808977ee8f548b2258d31")


def test_sha1(engine):
    """
    Known sha1 hash of b'' = da39a3ee5e6b4b0d3255bfef95601890afd80709
    """
    sha1_hex = "00a7"
    engine.eval_script_from_hex(sha1_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("da39a3ee5e6b4b0d3255bfef95601890afd80709")


def test_sha256(engine):
    """
    Known sha256 hash of b'' = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    """
    sha256_hex = "00a8"
    engine.eval_script_from_hex(sha256_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")


def test_hash160(engine):
    """
    Known hash160 hash of b'' = b472a266d0bd89c13706a4132ccfb16f7c3b9fcb
    """
    hash160_hex = "00a9"
    engine.eval_script_from_hex(hash160_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb")


def test_hash256(engine):
    """
    Known hash256 hash of b'' = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
    """
    hash256_hex = "00aa"
    engine.eval_script_from_hex(hash256_hex)
    assert engine.stack.height == 1
    assert engine.stack.stack[0] == bytes.fromhex("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456")
