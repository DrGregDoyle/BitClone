"""
All cryptographic op-codes
    0xa6 -- 0xba
    0xa6 | OP_RIPEMD160
    0xa7 | OP_SHA1
    0xa8 | OP_SHA256
    0xa9 | OP_HASH160
    0xaa | OP_HASH256
    0xab | OP_CODESEPARATOR
    0xac | OP_CHECKSIG
    0xad | OP_CHECKSIGVERIFY
    0xae | OP_CHECKMULTISIG
    0xaf | OP_CHECKMULTISIGVERIFY
    0xba | OP_CHECKSIGADD
"""
from src.cryptography import ripemd160, sha1, sha256, hash160, hash256
from src.script.stack import BitStack

__all__ = ["op_sha256", "op_hash160", "op_hash256", "op_ripemd160", "op_sha1"]


def op_ripemd160(main_stack: BitStack):
    """
    OP_RIPEMD160 | 0xa6
    The input is hashed using RIPEMD-160.
    """
    data = main_stack.pop()
    main_stack.push(ripemd160(data))


def op_sha1(main_stack: BitStack):
    """
    OP_SHA1 |  0xa7
    The input is hashed using SHA-1.
    """
    data = main_stack.pop()
    main_stack.push(sha1(data))


def op_sha256(main_stack: BitStack):
    """
    OP_SHA256 | 0xa8
    The input is hashed using SHA-256.
    """
    data = main_stack.pop()
    main_stack.push(sha256(data))


def op_hash160(main_stack: BitStack):
    """
    OP_HASH160 | 0xa9
    The input is hashed twice: first with SHA-256 and then with RIPEMD-160.
    """
    data = main_stack.pop()
    main_stack.push(hash160(data))


def op_hash256(main_stack: BitStack):
    """
    OP_HASH256 | 0xaa
    The input is hashed two times with SHA-256.
    """
    data = main_stack.pop()
    main_stack.push(hash256(data))


# --- TESTING --- #
if __name__ == "__main__":
    test_stack = BitStack([b'\x03', b'\x02', b'\x01'])
    print(f"TEST STACK: {test_stack.to_json()}")
    op_ripemd160(test_stack)
    print(f"STACK AFTER OPS: {test_stack.to_json()}")
