"""
Basic Stack Operation OpCodes
    0x6b -- 0x7d
    0x6b | OP_TOALTSTACK
    0x6c | OP_FROMALTSTACK
    0x6d | OP_2DROP
    0x6e | OP_2DUP
    0x6f | OP_3DUP
    0x70 | OP_2OVER
    0x71 | OP_2ROT
    0x72 | OP_2SWAP
    0x73 | OP_IFDUP
    0x74 | OP_DEPTH
    0x75 | OP_DROP
    0x76 | OP_DUP
    0x77 | OP_NIP
    0x78 | OP_OVER
    0x79 | OP_PICK
    0x7a | OP_ROLL
    0x7b | OP_ROT
    0x7c | OP_SWAP
    0x7d | OP_TUCK
"""
from src.core import BitStackError
from src.script.stack import BitStack, BitNum

__all__ = ["op_toaltstack", "op_fromaltstack", "op_2drop", "op_2dup", "op_3dup", "op_2over", "op_2rot", "op_2swap",
           "op_ifdup", "op_depth", "op_drop", "op_dup", "op_nip", "op_over", "op_pick", "op_roll", "op_rot",
           "op_swap", "op_tuck"]


def op_toaltstack(main_stack: BitStack, alt_stack: BitStack):
    """
    OP_TOALTSTACK | 0x6b
    Puts the input onto the top of the alt stack. Removes it from the main stack.
    """
    alt_stack.push(main_stack.pop())


def op_fromaltstack(main_stack: BitStack, alt_stack: BitStack):
    """
    OP_FROMALTSTACK | 0x6c
    Puts the input onto the top of the main stack. Removes it from the alt stack.
    """
    main_stack.push(alt_stack.pop())


def op_2drop(main_stack: BitStack):
    """
    OP_2DROP | 0x6d
    Removes the top two stack items.
    """
    main_stack.pop()
    main_stack.pop()


def op_2dup(main_stack: BitStack):
    """
    OP_2DUP | 0x6e
    Duplicates the top two stack items.
    """
    item_list = main_stack.popitems(2)  # [top, first]
    main_stack.pushlist(item_list + item_list)


def op_3dup(main_stack: BitStack):
    """
    OP_3DUP | 0x6f
    Duplicates the top three stack items.
    """
    items = main_stack.popitems(3)
    main_stack.pushlist(items + items)


def op_2over(main_stack: BitStack):
    """
    OP_2OVER | 0x70
    Duplicate the 3rd and 4th items in the stack
    """
    items = main_stack.popitems(4)  # top [0, 1, 2, 3] bottom
    items = items[2:] + items  # top [ 2, 3, 0, 1, 2, 3]
    main_stack.pushlist(items)


def op_2rot(main_stack: BitStack):
    """
    OP_2ROT | 0x71
    Move the 5th and 6th items to the top
    """
    items = main_stack.popitems(6)  # items = [top, 1, 2, 3, 4, 5]
    items = items[4:] + items[:4]  # items = [5, 6, top, 1, 2, 3]
    main_stack.pushlist(items)


def op_2swap(main_stack: BitStack):
    """
    OP_2SWAP | 0x72
    Swap the top two pairs of items
    """
    items = main_stack.popitems(4)  # items = [top, 1, 2, 3]
    items = items[2:] + items[:2]  # items = [2, 3, top, 1]
    main_stack.pushlist(items)


def op_ifdup(main_stack: BitStack):
    """
    OP_IFDUP |  0x73
    Duplicates the top item on the stick iff it's non-zero
    """
    if main_stack.top != b'':
        main_stack.push(main_stack.top)


def op_depth(main_stack: BitStack):
    """
    OP_DEPTH | 0x74
    Puts the number of stack items onto the stack (including 0 for empty stack)
    """
    main_stack.push(BitNum(main_stack.height))


def op_drop(main_stack: BitStack):
    """
    OP_DROP | 0x75
    Removes the top stack item.
    """
    main_stack.pop()


def op_dup(main_stack: BitStack):
    """
    OP_DUP | 0x76
    Duplicates the top stack item. Fail on empty stack
    """
    if main_stack.is_empty:
        raise BitStackError("Cannot duplicate empty stack")
    main_stack.push(main_stack.top)


def op_nip(main_stack: BitStack):
    """
    OP_NIP | 0x77
    Removes the second-to-top stack item
    """
    [top, _] = main_stack.popitems(2)
    main_stack.push(top)


def op_over(main_stack: BitStack):
    """
    OP_OVER | 0x78
    Copies the second-to-top stack item to the top.
    """
    [top, second] = main_stack.popitems(2)
    main_stack.pushlist([second, top, second])


def op_pick(main_stack: BitStack):
    """
    OP_PICK | 0x79
    The item n back in the stack is copied to the top. n is assumed to be on top of stack
    """
    n = main_stack.popnum()

    # Check height
    if main_stack.height <= n:
        raise BitStackError("Cannot pick at a distance greater than the height")

    item = main_stack.stack[n]
    main_stack.push(item)


def op_roll(main_stack: BitStack):
    """
    OP_ROLL | 0x7a
    The item n back in the stack is moved to the top.
    """
    n = main_stack.popnum()

    # Check height
    if main_stack.height < n + 1:
        raise BitStackError("Cannot roll at a distance greater than the height")

    items = main_stack.popitems(n + 1)  # Add 1 for indexing
    items = items[-1:] + items[:-1]
    main_stack.pushlist(items)


def op_rot(main_stack: BitStack):
    """
    OP_ROT | 0x7b
    The 3rd item down the stack is moved to the top.
    """
    [first, second, third] = main_stack.popitems(3)
    main_stack.pushlist([third, first, second])


def op_swap(main_stack: BitStack):
    """
    OP_SWAP | 0x7c
    The top two items on the stack are swapped.
    """
    main_stack.pushitems(main_stack.popitems(2))  # Push items pushes [top, second] so that top is pushed first


def op_tuck(main_stack: BitStack):
    """
    OP_TUCK | 0x7d
    The item at the top of the stack is copied and inserted before the second-to-top item.
    """
    [top, first] = main_stack.popitems(2)  # [top, first]
    main_stack.pushlist([top, first, top])


# --- TESTING ---#
if __name__ == "__main__":
    test_stack = BitStack([BitNum(6), BitNum(5), BitNum(4), BitNum(3), BitNum(2), BitNum(1)])
    empty_stack = BitStack()
    print(f"TEST STACK: {test_stack.to_json()}")
    print(f"TEST STACK TOP: {test_stack.top}")
    print(f"TEST STACK BOTTOM: {test_stack.bottom}")
    op_tuck(test_stack)
    print(f"AFTER OPS")
    print(f"TEST STACK: {test_stack.to_json()}")
    print(f"TEST STACK TOP: {test_stack.top}")
    print(f"TEST STACK BOTTOM: {test_stack.bottom}")
    # op_over(test_stack)
    # print(f"AFTER OPS")
    # print(f"TEST STACK: {test_stack.to_json()}")
    # print(f"TEST STACK TOP: {test_stack.top}")
    # print(f"TEST STACK BOTTOM: {test_stack.bottom}")
    # op_swap(test_stack)
    # print(f"AFTER OPS")
    # print(f"TEST STACK: {test_stack.to_json()}")
    # print(f"TEST STACK TOP: {test_stack.top}")
    # print(f"TEST STACK BOTTOM: {test_stack.bottom}")
