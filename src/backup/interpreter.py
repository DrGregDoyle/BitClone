"""
The Bitcoin interpreter.cpp as written in Python by ChatGPT 4o
"""
from src.library.op_codes import OPCODES
from src.script import Stack


def eval_script(stack, script, altstack=None, flags=0):
    """
    Python version of Bitcoin Core's EvalScript.

    :param stack: The main stack for execution.
    :param script: The script to execute (as bytes).
    :param altstack: An alternative stack (used for OP_TOALTSTACK, OP_FROMALTSTACK).
    :param flags: Execution flags (e.g., VERIFY_MINIMALIF, CHECKLOCKTIMEVERIFY).
    :return: True if script executes successfully, False otherwise.
    """
    if altstack is None:
        altstack = Stack()

    pc = 0  # Program Counter
    length = len(script)
    vf_exec = []  # Condition stack for OP_IF, OP_ELSE, OP_ENDIF
    opcount = 0  # Opcode count
    pbegincodehash = 0  # Used for OP_CODESEPARATOR

    while pc < length:
        opcode = script[pc]
        pc += 1  # Move program counter forward

        # Handle push operations (OP_PUSHDATA)
        if 0x01 <= opcode <= 0x4b:
            push_size = opcode
            push_value = script[pc:pc + push_size]
            stack.push(push_value)
            pc += push_size  # Move past pushed data
            continue

        elif opcode in OP_FUNCTIONS:
            OP_FUNCTIONS[opcode](stack)  # Execute function-based opcode

        elif opcode == OPCODES["OP_TOALTSTACK"]:
            if stack.height < 1:
                return False  # Stack underflow
            altstack.push(stack.pop())

        elif opcode == OPCODES["OP_FROMALTSTACK"]:
            if altstack.height < 1:
                return False  # Altstack underflow
            stack.push(altstack.pop())

        elif opcode == OPCODES["OP_IF"] or opcode == OPCODES["OP_NOTIF"]:
            if stack.height < 1:
                return False  # Stack underflow
            condition = stack.pop() != b'\x00'
            if opcode == OPCODES["OP_NOTIF"]:
                condition = not condition
            vf_exec.append(condition)

        elif opcode == OPCODES["OP_ELSE"]:
            if not vf_exec:
                return False  # Unbalanced IF/ELSE
            vf_exec[-1] = not vf_exec[-1]

        elif opcode == OPCODES["OP_ENDIF"]:
            if not vf_exec:
                return False  # Unbalanced ENDIF
            vf_exec.pop()

        elif opcode == OPCODES["OP_CHECKSIG"]:
            if stack.height < 2:
                return False  # Stack underflow
            pubkey = stack.pop()
            signature = stack.pop()
            success = verify_signature(pubkey, signature)
            stack.push(b'\x01' if success else b'\x00')

        elif opcode == OPCODES["OP_CHECKMULTISIG"]:
            if stack.height < 1:
                return False  # Stack underflow
            n = int.from_bytes(stack.pop(), "little")  # Number of required signatures
            if stack.height < n + 1:
                return False  # Not enough pubkeys
            pubkeys = [stack.pop() for _ in range(n)]
            m = int.from_bytes(stack.pop(), "little")  # Number of provided signatures
            if stack.height < m:
                return False  # Not enough signatures
            signatures = [stack.pop() for _ in range(m)]

            success = check_multisig(pubkeys, signatures)
            stack.push(b'\x01' if success else b'\x00')

        elif opcode == OPCODES["OP_VERIFY"]:
            if stack.height < 1:
                return False  # Stack underflow
            if stack.pop() == b'\x00':
                return False  # OP_VERIFY fails

        elif opcode == OPCODES["OP_EQUALVERIFY"]:
            if stack.height < 2:
                return False  # Stack underflow
            if stack.pop() != stack.pop():
                return False  # OP_EQUALVERIFY fails
            stack.push(b'\x01')  # If equal, push True

        elif opcode == OPCODES["OP_RETURN"]:
            return False  # OP_RETURN always fails

        elif opcode == OPCODES["OP_DEPTH"]:
            stack.push(len(stack.stack).to_bytes(1, "little"))

        elif opcode == OPCODES["OP_SWAP"]:
            if stack.height < 2:
                return False  # Stack underflow
            a = stack.pop()
            b = stack.pop()
            stack.push(a)
            stack.push(b)

        elif opcode == OPCODES["OP_DUP"]:
            if stack.height < 1:
                return False  # Stack underflow
            stack.push(stack.top)

        elif opcode == OPCODES["OP_DROP"]:
            if stack.height < 1:
                return False  # Stack underflow
            stack.pop()

        elif opcode == OPCODES["OP_ADD"]:
            if stack.height < 2:
                return False  # Stack underflow
            a = int.from_bytes(stack.pop(), "little", signed=True)
            b = int.from_bytes(stack.pop(), "little", signed=True)
            stack.push((a + b).to_bytes(1, "little", signed=True))

        elif opcode == OPCODES["OP_EQUAL"]:
            if stack.height < 2:
                return False  # Stack underflow
            a = stack.pop()
            b = stack.pop()
            stack.push(b'\x01' if a == b else b'\x00')

        else:
            return False  # Unknown opcode

        # Check opcode execution limit
        opcount += 1
        if opcount > 201:  # Bitcoin Core enforces a 201 opcode limit
            return False

    # Final validation
    return stack.height > 0 and stack.top != b'\x00'  # Script succeeds if top of stack is nonzero
