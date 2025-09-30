"""
Numerical Operations for BitCoin script
    0x82 -- 0xa5
    0x82 | OP_SIZE
    0x87 | OP_EQUAL
    0x88 | OP_EQUALVERIFY
    0x8b | OP_1ADD
    0x8c | OP_1SUB
    0x8f | OP_NEGATE
    0x90 | OP_ABS
    0x91 | OP_NOT
    0x92 | OP_0NOTEQUAL
    0x93 | OP_ADD
    0x94 | OP_SUB
    0x9a | OP_BOOLAND
    0x9b | OP_BOOLOR
    0x9c | OP_NUMEQUAL
    0x9d | OP_NUMEQUALVERIFY
    0x9e | OP_NUMNOTEQUAL
    0x9f | OP_LESSTHAN
    0xa0 | OP_GREATERTHAN
    0xa1 | OP_LESSTHANOREQUAL
    0xa2 | OP_GREATERTHANOREQUAL
    0xa3 | OP_MIN
    0xa4 | OP_MAX
    0xa5 | OP_WITHIN
"""

from src.core import BitStackError
from src.script import BitStack, BitNum

__all__ = ["op_size", "op_equal", "op_equalverify", "op_1add", "op_1sub", "op_negate", "op_abs", "op_not",
           "op_0notequal", "op_add", "op_sub", "op_booland", "op_boolor", "op_numequal", "op_numequalverify",
           "op_numnotequal", "op_lessthan", "op_greaterthan", "op_lessthanorequal", "op_greaterthanorequal", "op_min",
           "op_max", "op_within"]


def op_size(main_stack: BitStack):
    """
    OP_SIZE | 0x82
    Pushes the byte length of the top element without popping it
    """
    top = main_stack.top
    size = len(top) if top != b'' else 0
    main_stack.push(BitNum(size))


def op_equal(main_stack: BitStack):
    """
    OP_EQUAL | 0x87
    Returns 1 if the inputs are exactly equal, 0 otherwise
    """
    a = main_stack.pop()
    b = main_stack.pop()
    main_stack.pushbool(a == b)


def op_equalverify(main_stack: BitStack):
    """
    OP_EQUALVERIFY | 0x88
    Same as OP_EQUAL, but fails script if not equal
    """
    op_equal(main_stack)
    top = main_stack.pop()
    if top == b'':
        raise BitStackError("OP_EQUALVERIFY failed")


def op_1add(main_stack: BitStack):
    """
    OP_1ADD | 0x8b
    Add 1 to the top item on the stack.
    """
    num = main_stack.popnum()  # int
    main_stack.push(BitNum(num + 1))


def op_1sub(main_stack: BitStack):
    """
    OP_1SUB | 0x8c
    1 is subtracted from the input.
    """
    num = main_stack.popnum()  # int
    main_stack.push(BitNum(num - 1))


def op_negate(main_stack: BitStack):
    """
    OP_NEGATE | 0x8f
    The sign of the input is flipped.
    """
    num = main_stack.popnum()  # int
    main_stack.push(BitNum(-num))


def op_abs(main_stack: BitStack):
    """
    OP_ABS |  0x90
    The input is made positive.
    """
    num = main_stack.popnum()  # int
    main_stack.push(BitNum(abs(num)))


def op_not(main_stack: BitStack):
    """
    OP_NOT | 0x91
    Pop the top item and push 1 if it is zero; otherwise, push 0
    """
    num = main_stack.popnum()  # int
    main_stack.pushbool(num == 0)


def op_0notequal(main_stack: BitStack):
    """
    OP_0NOTEQUAL | 0x92
    Returns 0 if the input is 0. 1 otherwise.
    """
    num = main_stack.popnum()  # int
    main_stack.pushbool(num != 0)


def op_add(main_stack: BitStack):
    """
    OP_ADD |  0x93
    a is added to b.
    """
    a = main_stack.popnum()
    b = main_stack.popnum()
    main_stack.push(BitNum(a + b))


def op_sub(main_stack: BitStack):
    """
    OP_SUB |  0x94
    Pop two stack items and push the second minus the top
    """
    a = main_stack.popnum()
    b = main_stack.popnum()
    main_stack.push(BitNum(b - a))


def op_booland(main_stack: BitStack):
    """
    OP_BOOLAND | 0x9a
    If both a and b are not 0, the output is 1. Otherwise, 0.
    """
    a = main_stack.popnum()
    b = main_stack.popnum()
    main_stack.pushbool(a != 0 and b != 0)


def op_boolor(main_stack: BitStack):
    """
    OP_BOOLOR |  0x9b
    If a or b is not 0, the output is 1. Otherwise, 0.
    """
    a = main_stack.popnum()
    b = main_stack.popnum()
    main_stack.pushbool(a != 0 or b != 0)


def op_numequal(main_stack: BitStack):
    """
    OP_NUMEQUAL | 0x9c
    Returns 1 if the numbers are equal, 0 otherwise.
    """
    a = main_stack.popnum()
    b = main_stack.popnum()
    main_stack.pushbool(a == b)


def op_numequalverify(main_stack: BitStack):
    """
    OP_NUMEQUALVERIFY | 0x9d
    Same as OP_NUMEQUAL, but runs OP_VERIFY afterward.
    """
    op_numequal(main_stack)
    top = main_stack.pop()
    if top == b'':
        raise BitStackError("OP_NUMEQUALVERIFY failed verification")


def op_numnotequal(main_stack: BitStack):
    """
    OP_NUMNOTEQUAL | 0x9e
    Returns 1 if the numbers are not equal, 0 otherwise.
    """
    a = main_stack.popnum()
    b = main_stack.popnum()
    main_stack.pushbool(a != b)


def op_lessthan(main_stack: BitStack):
    """
    OP_LESSTHAN | 0x9f
    Returns 1 if b is less than a, 0 otherwise. (bottom < top)
    """
    a = main_stack.popnum()
    b = main_stack.popnum()
    main_stack.pushbool(a > b)


def op_greaterthan(main_stack: BitStack):
    """
    OP_GREATERTHAN | 0xa0
    Returns 1 if b is greater than a, 0 otherwise. (bottom > top)
    """
    a = main_stack.popnum()
    b = main_stack.popnum()
    main_stack.pushbool(a < b)


def op_lessthanorequal(main_stack: BitStack):
    """
    OP_LESSTHANOREQUAL | 0xa1
    Returns 1 if b is less than or equal to a, 0 otherwise.  (bottom <= top)
    """
    a = main_stack.popnum()
    b = main_stack.popnum()
    main_stack.pushbool(a >= b)


def op_greaterthanorequal(main_stack: BitStack):
    """
    OP_GREATERTHANOREQUAL | 0xa2
    Returns 1 if b is greater than or equal to a, 0 otherwise. (bottom >= top)
    """
    a = main_stack.popnum()
    b = main_stack.popnum()
    main_stack.pushbool(a <= b)


def op_min(main_stack: BitStack):
    """
    OP_MIN | 0xa3
    Returns the smallest of a and b.
    """
    a = main_stack.popnum()
    b = main_stack.popnum()
    main_stack.push(BitNum(min(a, b)))


def op_max(main_stack: BitStack):
    """
    OP_MAX | 0xa4
    Returns the largest of a and b.
    """
    a = main_stack.popnum()
    b = main_stack.popnum()
    main_stack.push(BitNum(max(a, b)))


def op_within(main_stack: BitStack):
    """
    OP_WITHIN | 0xa5
    Returns 1 if x is within the specified range (left-inclusive), 0 otherwise.
    """
    _max = main_stack.popnum()
    _min = main_stack.popnum()
    num = main_stack.popnum()
    main_stack.pushbool(_min <= num < _max)


# --- Testing --- #
if __name__ == "__main__":
    test_stack = BitStack([BitNum(3), BitNum(2), BitNum(1), BitNum(0)])
    print(f"TEST STACK: {test_stack.to_json()}")
    op_greaterthan(test_stack)
    print(f"AFTER OPS: {test_stack.to_json()}")
    op_min(test_stack)
    print(f"AFTER OPS: {test_stack.to_json()}")
    op_max(test_stack)
    print(f"AFTER OPS: {test_stack.to_json()}")
