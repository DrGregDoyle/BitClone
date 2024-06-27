"""
A file for testing the ScriptEngine
"""

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
