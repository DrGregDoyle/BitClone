"""
Opcodes for verification (i.e., will return True/False)

    0x69 | OP_VERIFY
    0x6a | OP_RETURN

"""
from src.script.stack import BitStack

__all__ = ["op_verify", "op_equalverify", "op_numequalverify"]


def op_verify(main_stack: BitStack) -> bool:
    """
    OP_VERIFY | 0x69
    Pop the stack. Return False if the element is 0 or '', True otherwise
    """
    top = main_stack.pop()
    if top in [b'', 0, b'\x00']:
        return False
    return True


def op_equalverify(main_stack: BitStack) -> bool:
    """
    OP_EQUALVERIFY | 0x88
    Same as OP_EQUAL, but fails script if not equal
    """
    # OP_EQUAL
    a = main_stack.pop()
    b = main_stack.pop()
    main_stack.pushbool(a == b)
    # OP_VERIFY
    return op_verify(main_stack)


def op_numequalverify(main_stack: BitStack) -> bool:
    """
    OP_NUMEQUALVERIFY | 0x9d
    Same as OP_NUMEQUAL, but runs OP_VERIFY afterward.
    """
    # OP_NUMEQUAL
    a = main_stack.popnum()
    b = main_stack.popnum()
    main_stack.pushbool(a == b)
    # OP_VERIFY
    return op_verify(main_stack)
