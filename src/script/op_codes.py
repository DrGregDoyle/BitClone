OPCODES = {
    # push value
    0x00: "OP_0",  # == OP_FALSE
    0x4c: "OP_PUSHDATA1",
    0x4d: "OP_PUSHDATA2",
    0x4e: "OP_PUSHDATA4",
    0x4f: "OP_1NEGATE",
    0x50: "OP_RESERVED",
    0x51: "OP_1",  # == OP_TRUE
    0x52: "OP_2",
    0x53: "OP_3",
    0x54: "OP_4",
    0x55: "OP_5",
    0x56: "OP_6",
    0x57: "OP_7",
    0x58: "OP_8",
    0x59: "OP_9",
    0x5a: "OP_10",
    0x5b: "OP_11",
    0x5c: "OP_12",
    0x5d: "OP_13",
    0x5e: "OP_14",
    0x5f: "OP_15",
    0x60: "OP_16",

    # control
    0x61: "OP_NOP",
    0x62: "OP_VER",
    0x63: "OP_IF",
    0x64: "OP_NOTIF",
    0x65: "OP_VERIF",
    0x66: "OP_VERNOTIF",
    0x67: "OP_ELSE",
    0x68: "OP_ENDIF",
    0x69: "OP_VERIFY",
    0x6a: "OP_RETURN",

    # stack ops
    0x6b: "OP_TOALTSTACK",
    0x6c: "OP_FROMALTSTACK",
    0x6d: "OP_2DROP",
    0x6e: "OP_2DUP",
    0x6f: "OP_3DUP",
    0x70: "OP_2OVER",
    0x71: "OP_2ROT",
    0x72: "OP_2SWAP",
    0x73: "OP_IFDUP",
    0x74: "OP_DEPTH",
    0x75: "OP_DROP",
    0x76: "OP_DUP",
    0x77: "OP_NIP",
    0x78: "OP_OVER",
    0x79: "OP_PICK",
    0x7a: "OP_ROLL",
    0x7b: "OP_ROT",
    0x7c: "OP_SWAP",
    0x7d: "OP_TUCK",

    # splice ops
    0x7e: "OP_CAT",
    0x7f: "OP_SUBSTR",
    0x80: "OP_LEFT",
    0x81: "OP_RIGHT",
    0x82: "OP_SIZE",

    # bit logic
    0x83: "OP_INVERT",
    0x84: "OP_AND",
    0x85: "OP_OR",
    0x86: "OP_XOR",
    0x87: "OP_EQUAL",
    0x88: "OP_EQUALVERIFY",
    0x89: "OP_RESERVED1",
    0x8a: "OP_RESERVED2",

    # numeric
    0x8b: "OP_1ADD",
    0x8c: "OP_1SUB",
    0x8d: "OP_2MUL",
    0x8e: "OP_2DIV",
    0x8f: "OP_NEGATE",
    0x90: "OP_ABS",
    0x91: "OP_NOT",
    0x92: "OP_0NOTEQUAL",

    0x93: "OP_ADD",
    0x94: "OP_SUB",
    0x95: "OP_MUL",
    0x96: "OP_DIV",
    0x97: "OP_MOD",
    0x98: "OP_LSHIFT",
    0x99: "OP_RSHIFT",

    0x9a: "OP_BOOLAND",
    0x9b: "OP_BOOLOR",
    0x9c: "OP_NUMEQUAL",
    0x9d: "OP_NUMEQUALVERIFY",
    0x9e: "OP_NUMNOTEQUAL",
    0x9f: "OP_LESSTHAN",
    0xa0: "OP_GREATERTHAN",
    0xa1: "OP_LESSTHANOREQUAL",
    0xa2: "OP_GREATERTHANOREQUAL",
    0xa3: "OP_MIN",
    0xa4: "OP_MAX",

    0xa5: "OP_WITHIN",

    # crypto
    0xa6: "OP_RIPEMD160",
    0xa7: "OP_SHA1",
    0xa8: "OP_SHA256",
    0xa9: "OP_HASH160",
    0xaa: "OP_HASH256",
    0xab: "OP_CODESEPARATOR",
    0xac: "OP_CHECKSIG",
    0xad: "OP_CHECKSIGVERIFY",
    0xae: "OP_CHECKMULTISIG",
    0xaf: "OP_CHECKMULTISIGVERIFY",

    # expansion
    0xb0: "OP_NOP1",
    0xb1: "OP_CHECKLOCKTIMEVERIFY",  # == OP_NOP2
    0xb2: "OP_CHECKSEQUENCEVERIFY",  # == OP_NOP3
    0xb3: "OP_NOP4",
    0xb4: "OP_NOP5",
    0xb5: "OP_NOP6",
    0xb6: "OP_NOP7",
    0xb7: "OP_NOP8",
    0xb8: "OP_NOP9",
    0xb9: "OP_NOP10",

    # Opcode added by BIP 342 (Tapscript)
    0xba: "OP_CHECKSIGADD",

    0xff: "OP_INVALIDOPCODE",
}
OP_ALIASES = {
    # Push value aliases
    "OP_FALSE": "OP_0",  # 0x00
    "OP_TRUE": "OP_1",  # 0x51

    # Control flow aliases
    "OP_NOP2": "OP_CHECKLOCKTIMEVERIFY",  # BIP 65 (0xb1)
    "OP_NOP3": "OP_CHECKSEQUENCEVERIFY",  # BIP 112 (0xb2)

}



