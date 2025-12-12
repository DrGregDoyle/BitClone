"""
We test that all opcodes perform what's expected
"""

from secrets import token_bytes, randbelow

import pytest

from src.script.script_engine import ScriptEngine
from src.script.stack import BitNum


@pytest.fixture
def engine():
    return ScriptEngine()


def _pop_all(stack):
    """Pop all items from a BitStack, returning them top-first."""
    items = []
    while stack.height:
        items.append(stack.pop())
    return items


# OP_0, OP_FALSE
def test_op_false(engine):
    test_script = bytes.fromhex("00")
    valid_stack = engine.validate_script(test_script)
    assert not valid_stack, "OP_FALSE script validated to True"


def test_op_pushbytes(engine):
    opcode = max(1, randbelow(76))  # No zero data
    random_data = token_bytes(opcode)
    test_script = opcode.to_bytes(1, "big") + random_data
    engine.execute_script(test_script)
    assert engine.stack.top == random_data, "OP_PUSHBYTES failed for random data"


@pytest.mark.parametrize("op_pushdata_hex, expected", [
    ("4c04deadbeef", "deadbeef"),
    ("4d0400deadbeef", "deadbeef"),
    ("4e04000000deadbeef", "deadbeef"),
])
def test_op_pushdata(engine, op_pushdata_hex, expected):
    engine.execute_script(bytes.fromhex(op_pushdata_hex))
    assert engine.stack.top.hex() == expected


def test_op_1negate(engine):
    op_1negate_hex = "4f"
    engine.execute_script(bytes.fromhex(op_1negate_hex))
    assert engine.stack.top == b"\x81"


def test_op_num(engine):
    rand_num2 = 1 + randbelow(16)
    opcode = 0x50 + rand_num2  # OP_1 .. OP_16
    engine.execute_script(bytes([opcode]))
    assert engine.stack.top == BitNum(rand_num2).to_bytes()


def test_op_nop(engine):
    op_nop_hex = "61"
    engine.execute_script(bytes.fromhex(op_nop_hex))
    assert engine.stack.height == 0


def test_op_toaltstack(engine):
    op_toaltstack_hex = "516b"
    engine.execute_script(bytes.fromhex(op_toaltstack_hex))
    assert engine.alt_stack.top == bytes.fromhex("01")


def test_op_fromaltstack(engine):
    op_fromaltstack_hex = "516b6c"
    engine.execute_script(bytes.fromhex(op_fromaltstack_hex))
    assert engine.stack.top == bytes.fromhex("01")


def test_op_ifdup(engine):
    op_ifdup_hex = "5173"
    engine.execute_script(bytes.fromhex(op_ifdup_hex))
    assert engine.stack.height == 2
    items = _pop_all(engine.stack)
    assert items[0] == items[1]


def test_op_depth(engine):
    op_depth_hex = "51525374"
    engine.execute_script(bytes.fromhex(op_depth_hex))
    items = _pop_all(engine.stack)
    assert items == [
        bytes.fromhex("03"),
        bytes.fromhex("03"),
        bytes.fromhex("02"),
        bytes.fromhex("01"),
    ]


def test_op_drop(engine):
    rand_bytes8 = token_bytes(8)
    op_drop_hex = "5208" + rand_bytes8.hex() + "75"
    engine.execute_script(bytes.fromhex(op_drop_hex))
    assert engine.stack.top == bytes.fromhex("02")


def test_op_dup(engine):
    op_dup_hex = "515276"
    engine.execute_script(bytes.fromhex(op_dup_hex))
    items = _pop_all(engine.stack)
    assert items == [
        bytes.fromhex("02"),
        bytes.fromhex("02"),
        bytes.fromhex("01"),
    ]


def test_op_nip(engine):
    op_nip_hex = "51525377"
    engine.execute_script(bytes.fromhex(op_nip_hex))
    items = _pop_all(engine.stack)
    assert items == [
        bytes.fromhex("03"),
        bytes.fromhex("01"),
    ]
    assert len(items) == 2


def test_op_over(engine):
    op_over_hex = "515278"
    engine.execute_script(bytes.fromhex(op_over_hex))
    items = _pop_all(engine.stack)
    assert items == [
        bytes.fromhex("01"),
        bytes.fromhex("02"),
        bytes.fromhex("01"),
    ]


def test_op_pick1(engine):
    op_pick_hex = "51525354555279"
    engine.execute_script(bytes.fromhex(op_pick_hex))
    items = _pop_all(engine.stack)
    assert items == [
        bytes.fromhex("03"),
        bytes.fromhex("05"),
        bytes.fromhex("04"),
        bytes.fromhex("03"),
        bytes.fromhex("02"),
        bytes.fromhex("01"),
    ]


def test_op_pick2(engine):
    op_pick_hex = "5758595a5379"
    engine.execute_script(bytes.fromhex(op_pick_hex))
    items = _pop_all(engine.stack)
    assert items == [
        bytes.fromhex("07"),
        bytes.fromhex("0a"),
        bytes.fromhex("09"),
        bytes.fromhex("08"),
        bytes.fromhex("07"),
    ]


def test_op_roll1(engine):
    op_roll_hex = "5152535455527a"
    engine.execute_script(bytes.fromhex(op_roll_hex))
    items = _pop_all(engine.stack)
    assert items == [
        bytes.fromhex("03"),
        bytes.fromhex("05"),
        bytes.fromhex("04"),
        bytes.fromhex("02"),
        bytes.fromhex("01"),
    ]
    assert len(items) == 5


def test_op_rot(engine):
    op_rot_hex = "5152537b"
    engine.execute_script(bytes.fromhex(op_rot_hex))
    items = _pop_all(engine.stack)
    assert items == [
        bytes.fromhex("01"),
        bytes.fromhex("03"),
        bytes.fromhex("02"),
    ]


def test_op_swap(engine):
    op_swap_hex = "5152537c"
    engine.execute_script(bytes.fromhex(op_swap_hex))
    items = _pop_all(engine.stack)
    assert items == [
        bytes.fromhex("02"),
        bytes.fromhex("03"),
        bytes.fromhex("01"),
    ]


def test_op_tuck1(engine):
    op_tuck_hex = "5152537d"
    engine.execute_script(bytes.fromhex(op_tuck_hex))
    items = _pop_all(engine.stack)
    assert items == [
        bytes.fromhex("03"),
        bytes.fromhex("02"),
        bytes.fromhex("03"),
        bytes.fromhex("01"),
    ]


def test_op_tuck2(engine):
    op_tuck_hex = "5152535a5b7d"
    engine.execute_script(bytes.fromhex(op_tuck_hex))
    items = _pop_all(engine.stack)
    assert items == [
        bytes.fromhex("0b"),
        bytes.fromhex("0a"),
        bytes.fromhex("0b"),
        bytes.fromhex("03"),
        bytes.fromhex("02"),
        bytes.fromhex("01"),
    ]


def test_op_2drop(engine):
    op_2drop_hex = "51526d"
    engine.execute_script(bytes.fromhex(op_2drop_hex))
    assert engine.stack.height == 0


def test_op_2dup(engine):
    op_2dup_hex = "51526e"
    engine.execute_script(bytes.fromhex(op_2dup_hex))
    items = _pop_all(engine.stack)
    assert items == [
        bytes.fromhex("02"),
        bytes.fromhex("01"),
        bytes.fromhex("02"),
        bytes.fromhex("01"),
    ]


def test_op_3dup(engine):
    op_3dup_hex = "5152536f"
    engine.execute_script(bytes.fromhex(op_3dup_hex))
    items = _pop_all(engine.stack)
    assert items == [
        bytes.fromhex("03"),
        bytes.fromhex("02"),
        bytes.fromhex("01"),
        bytes.fromhex("03"),
        bytes.fromhex("02"),
        bytes.fromhex("01"),
    ]


def test_op_2over(engine):
    op_2over_hex = "51525354555670"
    engine.execute_script(bytes.fromhex(op_2over_hex))
    items = _pop_all(engine.stack)
    assert items == [
        bytes.fromhex("04"),
        bytes.fromhex("03"),
        bytes.fromhex("06"),
        bytes.fromhex("05"),
        bytes.fromhex("04"),
        bytes.fromhex("03"),
        bytes.fromhex("02"),
        bytes.fromhex("01"),
    ]


def test_op_2rot(engine):
    op_2rot_hex = "51525354555671"
    engine.execute_script(bytes.fromhex(op_2rot_hex))
    items = _pop_all(engine.stack)
    assert items == [
        bytes.fromhex("02"),
        bytes.fromhex("01"),
        bytes.fromhex("06"),
        bytes.fromhex("05"),
        bytes.fromhex("04"),
        bytes.fromhex("03"),
    ]


def test_op_2swap(engine):
    op_2swap_hex = "51525354555672"
    engine.execute_script(bytes.fromhex(op_2swap_hex))
    items = _pop_all(engine.stack)
    assert items == [
        bytes.fromhex("04"),
        bytes.fromhex("03"),
        bytes.fromhex("06"),
        bytes.fromhex("05"),
        bytes.fromhex("02"),
        bytes.fromhex("01"),
    ]


def test_op_size1(engine):
    op_size_hex = "0082"
    engine.execute_script(bytes.fromhex(op_size_hex))
    items = _pop_all(engine.stack)
    assert items == [b"", b""]
    assert len(items) == 2


def test_op_size2(engine):
    op_size_hex = "5a82"
    engine.execute_script(bytes.fromhex(op_size_hex))
    items = _pop_all(engine.stack)
    assert items == [
        bytes.fromhex("01"),
        bytes.fromhex("0a"),
    ]


def test_op_size3(engine):
    op_size_hex = "03a4b5c682"
    engine.execute_script(bytes.fromhex(op_size_hex))
    items = _pop_all(engine.stack)
    assert items == [
        bytes.fromhex("03"),
        bytes.fromhex("a4b5c6"),
    ]


def test_op_equal(engine):
    op_equal_hex = "515187"
    engine.execute_script(bytes.fromhex(op_equal_hex))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("01")]


def test_op_equal_verify(engine):
    op_equal_verify_hex = "515187"
    engine.execute_script(bytes.fromhex(op_equal_verify_hex))
    items = _pop_all(engine.stack)
    # Expect same stack result as OP_EQUAL for this engine
    assert items == [bytes.fromhex("01")]


def test_op_1add(engine):
    op_1add_hex = "528b"
    engine.execute_script(bytes.fromhex(op_1add_hex))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("03")]


def test_op_1sub(engine):
    op_1sub_hex = "528c"
    engine.execute_script(bytes.fromhex(op_1sub_hex))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("01")]


def test_op_negate(engine):
    op_negate_hex = "528f"
    engine.execute_script(bytes.fromhex(op_negate_hex))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("82")]


def test_op_abs1(engine):
    op_abs_hex = "528f90"
    engine.execute_script(bytes.fromhex(op_abs_hex))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("02")]


def test_op_abs2(engine):
    op_abs_hex = "4f90"
    engine.execute_script(bytes.fromhex(op_abs_hex))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("01")]


def test_op_not1(engine):
    op_not_hex = "0091"
    engine.execute_script(bytes.fromhex(op_not_hex))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("01")]


def test_op_not2(engine):
    op_not_hex = "5191"
    engine.execute_script(bytes.fromhex(op_not_hex))
    items = _pop_all(engine.stack)
    assert items == [b""]


def test_op_0notequal1(engine):
    op_not_hex = "5192"
    engine.execute_script(bytes.fromhex(op_not_hex))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("01")]


def test_op_0notequal2(engine):
    op_not_hex = "0092"
    engine.execute_script(bytes.fromhex(op_not_hex))
    items = _pop_all(engine.stack)
    assert items == [b""]


def test_op_add(engine):
    op_add_hex = "515193"
    engine.execute_script(bytes.fromhex(op_add_hex))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("02")]


def test_op_add2(engine):
    op_add_hex = "5253935487"
    engine.execute_script(bytes.fromhex(op_add_hex))
    items = _pop_all(engine.stack)
    assert items == [b""]


def test_op_sub(engine):
    op_sub_hex = "555394"
    engine.execute_script(bytes.fromhex(op_sub_hex))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("02")]


def test_booland(engine):
    op_booland_hex = "51519a"
    engine.execute_script(bytes.fromhex(op_booland_hex))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("01")]


def test_booland2(engine):
    op_booland2_hex = "51009a"
    engine.execute_script(bytes.fromhex(op_booland2_hex))
    items = _pop_all(engine.stack)
    assert items == [b""]


def test_booland3(engine):
    op_booland3_hex = "00009a"
    engine.execute_script(bytes.fromhex(op_booland3_hex))
    items = _pop_all(engine.stack)
    assert items == [b""]


def test_booland4(engine):
    op_booland4_hex = "02a4b6559a"
    engine.execute_script(bytes.fromhex(op_booland4_hex))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("01")]


def test_boolor(engine):
    op_boolor_hex = "51519b"
    engine.execute_script(bytes.fromhex(op_boolor_hex))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("01")]


def test_boolor2(engine):
    op_boolor2_hex = "51009b"
    engine.execute_script(bytes.fromhex(op_boolor2_hex))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("01")]


def test_boolor3(engine):
    op_boolor3_hex = "00009b"
    engine.execute_script(bytes.fromhex(op_boolor3_hex))
    items = _pop_all(engine.stack)
    assert items == [b""]


def test_boolor4(engine):
    op_boolor4_hex = "02a4b6559b"
    engine.execute_script(bytes.fromhex(op_boolor4_hex))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("01")]


def test_numeq1(engine):
    op_numeq1_hex = "52529c"
    engine.execute_script(bytes.fromhex(op_numeq1_hex))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("01")]


def test_numeq2(engine):
    op_numeq2_hex = "52539c"
    engine.execute_script(bytes.fromhex(op_numeq2_hex))
    items = _pop_all(engine.stack)
    assert items == [b""]


def test_numeq3(engine):
    op_numeq3_hex = "0100009c"
    engine.execute_script(bytes.fromhex(op_numeq3_hex))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("01")]


def test_op_return(engine):
    op_return_hex = "51526a5353"
    engine.execute_script(bytes.fromhex(op_return_hex))
    items = _pop_all(engine.stack)
    # Script is marked invalid internally, but opcodes after OP_RETURN still ran
    assert items == [
        bytes.fromhex("02"),
        bytes.fromhex("01"),
    ]


def test_op_verify1(engine):
    test_script = bytes.fromhex("5169")
    engine.execute_script(test_script)
    assert engine.stack.height == 0


def test_op_verify2(engine):
    test_script = bytes.fromhex("515169")
    assert engine.validate_script(test_script)


def test_op_verify3(engine):
    """
    Stack = b''
    OP_VERIFY should pop it and fail the script
    """
    test_script = bytes.fromhex("0069")
    assert not engine.validate_script(test_script)


def test_numeq_verify1(engine):
    numeq_verify_hex1 = "51519d"
    engine.execute_script(bytes.fromhex(numeq_verify_hex1))
    assert engine.stack.height == 0


def test_numeq_verify2(engine):
    numeq_verify_hex1 = "51529d5151"
    engine.execute_script(bytes.fromhex(numeq_verify_hex1))
    assert engine.stack.height == 0


def test_numneq1(engine):
    numneq_hex1 = "51529e"
    engine.execute_script(bytes.fromhex(numneq_hex1))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("01")]


def test_numneq2(engine):
    numneq_hex1 = "51519e"
    engine.execute_script(bytes.fromhex(numneq_hex1))
    items = _pop_all(engine.stack)
    assert items == [b""]


def test_lt1(engine):
    """
    OP_LESSTHAN: Pop the top two items, True if the 2nd element is less than the top, otherwise False
    """
    lt_hex1 = "51529f"
    engine.execute_script(bytes.fromhex(lt_hex1))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("01")]


def test_lt2(engine):
    lt_hex2 = "52519f"
    engine.execute_script(bytes.fromhex(lt_hex2))
    items = _pop_all(engine.stack)
    assert items == [b""]


def test_gt1(engine):
    """
    OP_GREATERTHAN | Pop the top tuo items; True if the 2nd element is greater than the top, false otherwise
    """
    gt_hex1 = "5251a0"
    engine.execute_script(bytes.fromhex(gt_hex1))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("01")]


def test_gt2(engine):
    gt_hex2 = "5152a0"
    engine.execute_script(bytes.fromhex(gt_hex2))
    items = _pop_all(engine.stack)
    assert items == [b""]


def test_leq1(engine):
    leq_hex1 = "5151a15152a1"
    engine.execute_script(bytes.fromhex(leq_hex1))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("01"), bytes.fromhex("01")]


def test_leq2(engine):
    leq_hex2 = "5251a1"
    engine.execute_script(bytes.fromhex(leq_hex2))
    items = _pop_all(engine.stack)
    assert items == [b""]


def test_geq1(engine):
    geq_hex1 = "5151a15251a2"
    engine.execute_script(bytes.fromhex(geq_hex1))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("01"), bytes.fromhex("01")]


def test_geq2(engine):
    geq_hex2 = "5152a2"
    engine.execute_script(bytes.fromhex(geq_hex2))
    items = _pop_all(engine.stack)
    assert items == [b""]


def test_min(engine):
    min_hex = "5358a3"
    engine.execute_script(bytes.fromhex(min_hex))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("03")]


def test_max(engine):
    max_hex = "5358a4"
    engine.execute_script(bytes.fromhex(max_hex))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("08")]


def test_within1(engine):
    within_hex1 = "525153a5"
    engine.execute_script(bytes.fromhex(within_hex1))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("01")]


def test_ripemd160(engine):
    """
    Known ripemd160 hash of b'' = 9c1185a5c5e9fc54612808977ee8f548b2258d31
    """
    ripemd160_hex = "00a6"
    engine.execute_script(bytes.fromhex(ripemd160_hex))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("9c1185a5c5e9fc54612808977ee8f548b2258d31")]


def test_sha1(engine):
    """
    Known sha1 hash of b'' = da39a3ee5e6b4b0d3255bfef95601890afd80709
    """
    sha1_hex = "00a7"
    engine.execute_script(bytes.fromhex(sha1_hex))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("da39a3ee5e6b4b0d3255bfef95601890afd80709")]


def test_sha256(engine):
    """
    Known sha256 hash of b'' = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    """
    sha256_hex = "00a8"
    engine.execute_script(bytes.fromhex(sha256_hex))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]


def test_hash160(engine):
    """
    Known hash160 hash of b'' = b472a266d0bd89c13706a4132ccfb16f7c3b9fcb
    """
    hash160_hex = "00a9"
    engine.execute_script(bytes.fromhex(hash160_hex))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb")]


def test_hash256(engine):
    """
    Known hash256 hash of b'' = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
    """
    hash256_hex = "00aa"
    engine.execute_script(bytes.fromhex(hash256_hex))
    items = _pop_all(engine.stack)
    assert items == [bytes.fromhex("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456")]
