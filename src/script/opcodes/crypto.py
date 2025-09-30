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
from src.script.context import ExecutionContext
from src.script.stack import BitStack


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


def op_codeseparator(main_stack: BitStack):
    """
    OP_CODESEPARATOR |  0xab
    All the signature checking words will only match signatures to the data after the most recently-executed
    OP_CODESEPARATOR.
    """
    pass


def op_checksig(main_stack: BitStack, ctx: ExecutionContext):
    """
    OP_CHECKSIG | 0xac
    The entire transaction's outputs, inputs, and script (from the most recently-executed OP_CODESEPARATOR to the
    end) are hashed. The signature used by OP_CHECKSIG must be a valid signature for this
    hash and public key.

    NOTE: If tapscript = true we use Schnorr signatures instead of ECDSA
    """
    pass


def op_checksigverify(main_stack: BitStack):
    """
    OP_CHECKSIGVERIFY | 0xad
    Same as OP_CHECKSIG, but OP_VERIFY is executed afterward.
    """
    pass


def op_checkmultisig(main_stack: BitStack):
    """
    OP_CHECKMULTISIG | 0xae
    Compares the first signature against each public key until it finds an ECDSA match. Starting with the
    subsequent public key, it compares the second signature against each remaining public key until it finds an
    ECDSA match. The process is repeated until all signatures have been checked or not enough public keys remain
    to produce a successful result.

    NOTE: If tapscript = True, this OP_CODE is disabled
    """
    pass


def op_checkmultisigverify(main_stack: BitStack):
    """
    OP_CHECKMULTISIGVERIFY |  0xaf
    Same as OP_CHECKMULTISIG, but OP_VERIFY is executed afterward.

    NOTE: If tapscript = True, this OP_CODE is disabled
    """
    pass


def op_checksigadd(main_stack: BitStack):
    """
    OP_CHECKSIGADD | 0xba
    Three values are popped from the stack. The integer n is incremented by one and returned to the stack if the
    signature is valid for the public key and transaction. The integer n is returned to the stack unchanged if the
    signature is the empty vector (OP_0). In any other case, the script is invalid. This opcode is only available in
    tapscript.[2]
    """
    pass


# --- TESTING --- #
if __name__ == "__main__":
    test_stack = BitStack([b'\x03', b'\x02', b'\x01'])
    print(f"TEST STACK: {test_stack.to_json()}")
    op_ripemd160(test_stack)
    print(f"STACK AFTER OPS: {test_stack.to_json()}")
