"""
Opcode mapping - maps opcode bytes to their implementation functions
"""

from src.script.opcodes.bools import *
from src.script.opcodes.crypto import *
from src.script.opcodes.numeric import *
from src.script.opcodes.stackops import *
from src.script.opcodes.verify import *

__all__ = ["OPCODE_MAP"]
# Build the opcode map
OPCODE_MAP = {
    # Bools
    0x00: op_false,
    0x4f: op_1negate,
    0x51: op_true,

    # Verify
    0x69: op_verify,
    0x88: op_equalverify,
    0x9d: op_numequalverify,

    # StackOps
    0x6b: op_toaltstack,
    0x6c: op_fromaltstack,
    0x6d: op_2drop,
    0x6e: op_2dup,
    0x6f: op_3dup,
    0x70: op_2over,
    0x71: op_2rot,
    0x72: op_2swap,
    0x73: op_ifdup,
    0x74: op_depth,
    0x75: op_drop,
    0x76: op_dup,
    0x77: op_nip,
    0x78: op_over,
    0x79: op_pick,
    0x7a: op_roll,
    0x7b: op_rot,
    0x7c: op_swap,
    0x7d: op_tuck,

    # Crypto
    0xa6: op_ripemd160,
    0xa7: op_sha1,
    0xa8: op_sha256,
    0xa9: op_hash160,
    0xaa: op_hash256,
    # Handled in the ScriptEngine class
    # 0xab: op_codeseparator,
    # 0xac: op_checksig,  # Takes context
    # 0xad: op_checksigverify,
    # 0xae: op_checkmultisig
    # 0xaf: op_checkmultisigverify
    # 0xba: op_checksigadd

    # Numeric
    0x82: op_size,
    0x87: op_equal,
    0x8b: op_1add,
    0x8c: op_1sub,
    0x8f: op_negate,
    0x90: op_abs,
    0x91: op_not,
    0x92: op_0notequal,
    0x93: op_add,
    0x94: op_sub,
    0x9a: op_booland,
    0x9b: op_boolor,
    0x9c: op_numequal,
    0x9e: op_numnotequal,
    0x9f: op_lessthan,
    0xa0: op_greaterthan,
    0xa1: op_lessthanorequal,
    0xa2: op_greaterthanorequal,
    0xa3: op_min,
    0xa4: op_max,
    0xa5: op_within
}
