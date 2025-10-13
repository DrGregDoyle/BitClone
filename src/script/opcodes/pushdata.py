"""
Basic Push operations for BitCoin, including True/False
    0x00 -- 0x60
"""
from src.script.stack import BitStack, BitNum

__all__ = ["op_false", "op_true"]


def op_false(main_stack: BitStack):
    """
    OP_0, OP_FALSE, OP_PUSHBYTES_0 | 0x00
    Push empty byte array to stack
    """
    main_stack.pushbool(False)


def op_true(main_stack: BitStack):
    """
    OP_1, OP_TRUE | 0x51
    Push 1 to the stack
    """
    main_stack.pushbool(True)


# --- TESTING ---
if __name__ == "__main__":
    test_stack = BitStack(items=[
        BitNum(5), BitNum(4), BitNum(3), BitNum(2), BitNum(1), BitNum(0)
    ])
    print(f"TEST STACK: {test_stack.to_json()}")
    op_one(test_stack)
    print(f"TEST STACK: {test_stack.to_json()}")
