"""
The functions for all True/False opcodes: e.g, OP_0, OP_FALSE, OP_1, OP_TRUE
    0x00, 0x4f, 0x51, 0x61
    0x00: OP_FALSE
    0x4f: OP_1NEGATE
    0x51: OP_TRUE

"""
from src.script.stack import BitStack, BitNum

__all__ = ["op_false", "op_true", "op_1negate"]


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


def op_1negate(main_stack: BitStack):
    """
    OP_1NEGATE | 0x4f
    Push -1 to the stack
    """
    main_stack.push(BitNum(-1))


# --- TESTING ---
if __name__ == "__main__":
    test_stack = BitStack(items=[
        BitNum(5), BitNum(4), BitNum(3), BitNum(2), BitNum(1), BitNum(0)
    ])
    print(f"TEST STACK: {test_stack.to_json()}")
