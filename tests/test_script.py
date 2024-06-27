"""
A file for testing the ScriptEngine
"""

from collections import deque
from random import randint

from src.script import ScriptEngine


def random_hex_byte():
    """Returns a 2-character (1-byte) hex string"""
    random_num = randint(0, 255)
    return format(random_num, "02x")


def hex_byte(num: int):
    return format(num, "02x")


def test_pushdata():
    # Config
    test_engine = ScriptEngine()

    # OP_0 - Push an empty bytestring
    script1 = "00"
    test_engine.parse_script(script1)
    assert test_engine.main_stack.top == None

    # OP_1 -- OP_75 - Pushbytes
    random_byte_length = randint(1, 75)
    random_hex_string = "".join([random_hex_byte() for _ in range(random_byte_length)])
    script2 = hex_byte(random_byte_length) + random_hex_string
    test_engine.parse_script(script2)
    assert test_engine.main_stack.top == random_hex_string

    # OP_1NEGATE
    script3 = "4f"
    test_engine.parse_script(script3)
    assert test_engine.main_stack.top == -1

    # OP_RESERVED
    script4 = "50"
    reserved = False
    try:
        test_engine.parse_script(script4)
    except ValueError:
        reserved = True
    assert reserved

    # OP_1 -- OP_16
    for x in range(1, 17):
        temp_script = hex_byte(80 + x)
        test_engine.parse_script(temp_script)
        assert test_engine.main_stack.top == x


def test_stack_operators():
    # Config
    test_engine = ScriptEngine()

    # OP_TOALTSTACK
    script1 = "51526b"
    test_engine.parse_script(script1)
    assert test_engine.main_stack.top == 1
    assert test_engine.alt_stack.top == 2

    # OP_FROMALTSTACK
    script2 = "5152536b6b6c"
    test_engine.parse_script(script2)
    assert test_engine.main_stack.top == 2
    assert test_engine.alt_stack.top == 3

    # OP_2DROP
    script3 = "5152536d"
    test_engine.parse_script(script3)
    assert test_engine.main_stack.top == 1

    # OP_3DUP
    script4 = "555253546e"
    test_engine.parse_script(script4)
    assert test_engine.main_stack.top == 4

    # OP_2OVER
    script5 = "5152535470"
    test_engine.parse_script(script5)
    test_stack1 = deque([2, 1, 4, 3, 2, 1])
    assert all([test_engine.main_stack.stack[i] == test_stack1[i] for i in range(len(test_stack1))])

    # OP_2ROT
    script6 = "51525354555671"
    test_engine.parse_script(script6)
    test_stack2 = deque([2, 1, 6, 5, 4, 3])
    assert all([test_engine.main_stack.stack[i] == test_stack2[i] for i in range(len(test_stack2))])

    # OP_2SWAP
    script7 = "5152535472"
    test_engine.parse_script(script7)
    test_stack3 = deque([2, 1, 4, 3])
    assert all([test_engine.main_stack.stack[i] == test_stack3[i] for i in range(len(test_stack3))])

    # OP_IFDUP
    # TODO: Need subtract 1 to get 0 value
    script8a = "515273"
    test_engine.parse_script(script8a)
    assert test_engine.main_stack.top == 2
    assert test_engine.main_stack.stack[1] == 2

    # OP_DEPTH
    script9 = "74"
    stack_depth = len(test_engine.main_stack.stack)
    test_engine.parse_script(script9)
    assert test_engine.main_stack.top == stack_depth

    # OP_DROP
    script10 = "5175"
    test_engine.parse_script(script10)
    assert test_engine.main_stack.top == stack_depth

    # OP_DUP
    script11 = "54555676"
    test_engine.parse_script(script11)
    test_stack4 = deque([6, 6, 5, 4])
    assert all([test_engine.main_stack.stack[i] == test_stack4[i] for i in range(len(test_stack4))])

    # OP_NIP
    # CLEAR MAIN STACK
    test_engine.main_stack.clear_stack()
    assert test_engine.main_stack.height == 0
    script12 = "515277"
    test_engine.parse_script(script12)
    assert test_engine.main_stack.top == 2
    assert test_engine.main_stack.height == 1

    # OP_OVER
    