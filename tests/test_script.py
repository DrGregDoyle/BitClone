"""
A file for testing the ScriptEngine
"""

from random import randint

from src.script import ScriptEngine, Stack


def random_hex_byte():
    """Returns a 2-character (1-byte) hex string"""
    random_num = randint(0, 255)
    return format(random_num, "02x")


def hex_byte(num: int):
    return format(num, "02x")


def assert_stacks(d1: Stack, d2: Stack) -> bool:
    check1 = [(len(d1.stack) == len(d2.stack))]
    check2 = [d1.stack[i] == d2.stack[i] for i in range(len(d1.stack))]
    check1.extend(check2)
    # return all([d1.stack[i] == d2.stack[i] for i in range(len(d1.stack))])
    return all(check1)


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
    test_stack = Stack()
    test_alt_stack = Stack()
    script = ""

    def run_engine():
        test_engine.parse_script(script)

    def assert_stacks():
        assert len(test_stack.stack) == test_engine.main_stack.height
        assert all(
            [test_stack.stack[i] == test_engine.main_stack.stack[i] for i in range(test_engine.main_stack.height)])

    def assert_alt_stacks():
        assert len(test_alt_stack.stack) == test_engine.alt_stack.height
        assert all(
            [test_alt_stack.stack[i] == test_engine.alt_stack.stack[i] for i in range(test_engine.alt_stack.height)])

    # OP_TOALTSTACK
    script = "51526b"  # Push 1, Push 2, OP_
    run_engine()  # main stack = [1], alt stack = [2]
    test_stack.push(1)  # test stack = [1]
    test_alt_stack.push(2)  # test_alt stack = [2]
    assert_stacks()
    assert_alt_stacks()

    # OP_FROMALTSTACK -
    script = "6c"
    run_engine()  # main stack = [2, 1], alt stack = []
    test_stack.push(2)  # test stack = [2, 1]
    test_alt_stack.pop()  # test_alt stack = []
    assert_stacks()
    assert_alt_stacks()

    # OP_2DROP
    script = "6d"
    run_engine()  # main stack = []
    test_stack.pop()
    test_stack.pop()
    assert_stacks()

    # OP_2DUP
    script = "51526e"  # Push 1, Push 2, OP_
    run_engine()  # main stack = [2, 1, 2, 1]
    test_stack = Stack([2, 1, 2, 1])
    assert_stacks()

    # OP_3DUP
    script = "6f"
    run_engine()  # main stack = [2, 1, 2, 2, 1, 2, 1]
    test_stack = Stack([2, 1, 2, 2, 1, 2, 1])
    assert_stacks()

    # OP_2OVER
    script = "70"
    run_engine()  # main stack = [2, 2, 2, 1, 2, 2, 1, 2, 1]
    test_stack = Stack([2, 2, 2, 1, 2, 2, 1, 2, 1])
    assert_stacks()

    # OP_2ROT
    script = "71"
    run_engine()  # main stack = [2, 2, 2, 2, 2, 1, 1, 2, 1]
    test_stack = Stack([2, 2, 2, 2, 2, 1, 1, 2, 1])
    assert_stacks()

    # OP_2SWAP
    script = "6d6d6d535472"  # Drop 2, Drop 2, Drop 2, Push 3, Push 4, OP_ | main stack = [4, 3, 1, 2, 1]
    run_engine()  # main stack = [1, 2, 4, 3, 1]
    test_stack = Stack([1, 2, 4, 3, 1])
    assert_stacks()

    # OP_IFDUP
    # TODO: Need subtract 1 to get 0 value
    script = "73"
    run_engine()  # main stack = [1, 1, 2, 4, 3, 1]
    test_stack.push(1)
    assert_stacks()

    # OP_DEPTH
    script = "74"
    run_engine()  # main stack = [6, 1, 1, 2, 4, 3 ,1]
    test_stack.push(6)
    assert_stacks()

    # OP_DROP
    script = "757575"  # Drop, Drop, Drop
    run_engine()  # main stack = [2, 4, 3, 1]
    test_stack = Stack([2, 4, 3, 1])
    assert_stacks()

    # OP_DUP
    script = "76"
    run_engine()  # main stack = [2, 2, 4, 3, 1]
    test_stack.push(2)
    assert_stacks()

    # OP_NIP
    script = "7577"  # Drop, OP_
    run_engine()  # main stack = [2, 3, 1]
    test_stack = Stack([2, 3, 1])
    assert_stacks()

    # OP_OVER
    script = "78"
    run_engine()  # main stack = [3, 2, 3, 1]
    test_stack.push(3)
    assert_stacks()

    # OP_PICK
    script = "79" + hex_byte(3)  # Select the bottom-most element
    run_engine()  # main stack = [1, 3, 2, 3, 1]
    test_stack.push(1)
    assert_stacks()

    # OP_ROLL
    script = "7a" + hex_byte(3)  # Select the second to last element
    run_engine()  # main stack = [3, 1, 3, 2, 1]
    test_stack = Stack([3, 1, 3, 2, 1])
    assert_stacks()

    # OP_ROT
    script = "7b"
    run_engine()  # main stack = [3, 3, 1, 2, 1]
    test_stack = Stack([3, 3, 1, 2, 1])
    assert_stacks()

    # OP_SWAP
    script = "757c"  # Drop, OP_
    run_engine()  # main stack = [1, 3, 2, 1]
    test_stack = Stack([1, 3, 2, 1])
    assert_stacks()

    # OP_TUCK
    script = "7d"
    run_engine()  # main stack = [1, 3, 1, 2, 1]
    test_stack = Stack([1, 3, 1, 2, 1])
    assert_stacks()


def test_strings():
    # Config
    test_engine = ScriptEngine()

    # OP_SIZE
    script = "08ffeeddccbbaa998882"  # Push 8 bytes of data, <data>, OP_
    test_engine.parse_script(script)
    test_stack = Stack([16, "ffeeddccbbaa9988"])
    assert assert_stacks(test_stack, test_engine.main_stack)


def test_bitwise_operators():
    # Config
    engine = ScriptEngine()
    script = ""

    def run_engine():
        engine.parse_script(script)

    # OP_EQUAL True/False
    script = "515287515187"  # Push 1, Push 2, OP_, Push 1, Push 1, OP_ -> main_stack = [True, False]
    run_engine()
    test_stack = Stack([True, False])
    assert assert_stacks(test_stack, engine.main_stack)

    # OP_EQUALVERIFY
    script = "51518788"  # Push 1, Push 1, OP_EQUAL, OP_EQUALVERIFY -> main_stack = [False]
    run_engine()
    test_stack = Stack([False])
    assert assert_stacks(test_stack, engine.main_stack)


def test_numeric():
    # Config
    engine = ScriptEngine()
    script = ""
    test_stack = Stack()

    def run_engine():
        engine.parse_script(script)

    def assert_stacks():
        assert test_stack.height == engine.main_stack.height
        assert all([test_stack.stack[i] == engine.main_stack.stack[i] for i in range(test_stack.height)])

    # OP_1ADD
    script = "518b"
    run_engine()  # Main stack = [2]
    test_stack.push(2)
    assert_stacks()

    # OP_1SUB
    script = "8c"
    run_engine()  # Main stack = [1]
    test_stack = Stack([1])
    assert_stacks()

    # OP_NEGATE
    script = "8f"
    run_engine()  # Main stack = [-1]
    test_stack = Stack([-1])
    assert_stacks()

    # OP_ABS
    script = "90"
    run_engine()  # Main stack = [1]
    test_stack = Stack([1])
    assert_stacks()

    # OP_NOT
    script = "91"
    run_engine()  # Main stack = [0]
    test_stack = Stack([0])
    assert_stacks()

    # OP_0NOTEQUAL
    script = "925192"  # OP_, Push 1, OP_
    run_engine()  # Main stack = [1, 0]
    test_stack = Stack([1, 0])
    assert_stacks()

    # OP_ADD
    script = "5293"  # Push 2, OP_
    run_engine()  # Main stack = [3, 1, 0]
    test_stack = Stack([3, 0])
    assert_stacks()

    # OP_SUB
    script = "94"
    run_engine()  # Main stack = [3]
    test_stack = Stack([3])
    assert_stacks()

    # OP_BOOLAND
    script = "519a"
    run_engine()  # Main stack = [1]
    test_stack = Stack([1])
    assert_stacks()

    # OP_BOOLOR
    script = "518c9b"  # Push 1, SUB1, OP_ | main stack = [0, 1]
    run_engine()  # Main stack = [1]
    assert_stacks()

    # OP_NUMEQUAL
    script = "529c"  # Push 2, OP_
    run_engine()  # Main stack = [0]
    test_stack = Stack([0])
    assert_stacks()

    # OP_NUMEQUALVERIFY
    script = "518c9d"  # Push 1, SUB1, OP_ | main stack = [0, 0]
    run_engine()  # Main stack = []
    test_stack = Stack()
    assert_stacks()

    # OP_NUMNOTEQUAL
    script = "51529e"  # Push 1, Push 2, OP_
    run_engine()  # Main stack = [1]
    test_stack = Stack([1])
    assert_stacks()

    # OP_LESSTHAN
    script = "529f"  # Push 1, OP_
    run_engine()  # Main stack = [0]
    test_stack = Stack([0])
    assert_stacks()

    # OP_GREATERTHAN
    script = "53a0"  # Push 3, OP_
    run_engine()  # Main stack = [1]
    test_stack = Stack([1])
    assert_stacks()

    # OP_LESSTHANOREQUAL
    script = "5554a1"  # Push 5, Push 4, OP_
    run_engine()  # Main stack = [1, 1]
    test_stack = Stack([1, 1])
    assert_stacks()

    # OP_GREATERTHANOREQUAL
    script = "a2"
    run_engine()  # Main stack = [1]
    test_stack = Stack([1])
    assert_stacks()

    # OP_MIN
    script = "52a3"  # Push 2, OP_
    run_engine()  # Main stack = [1]
    assert_stacks()

    # OP_MAX
    script = "52a4"  # Push 2, OP_
    run_engine()  # Main stack = [2]
    test_stack = Stack([2])
    assert_stacks()

    # OP_WITHIN
    script = "5151a5"  # Push 1, Push 1, OP_
    run_engine()  # Main stack = [1]
    test_stack = Stack([1])
    assert_stacks()
