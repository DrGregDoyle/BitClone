"""
Numerical Operations for BitCoin script
    0x8b -- 0xa5
"""

from src.script import BitStack, BitNum


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
    if num == 0:
        main_stack.push(b'\x01')  # Push 1 | OP_TRUE
    else:
        main_stack.push(b'')  # Push 0


# --- Testing --- #
if __name__ == "__main__":
    test_stack = BitStack([BitNum(3), BitNum(2), BitNum(1), BitNum(0)])
    print(f"TEST STACK: {test_stack.to_json()}")
    op_not(test_stack)
    print(f"AFTER OPS: {test_stack.to_json()}")
    op_not(test_stack)
    print(f"AFTER OPS: {test_stack.to_json()}")
