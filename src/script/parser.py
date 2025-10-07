"""
Methods for parsing script
"""
from src.core import SERIALIZED, get_stream, StreamError, OpCodeError, OPCODES

__all__ = ["to_asm"]


def to_asm(script: SERIALIZED) -> list:
    """
    Given a script, we return the associated ASM
    """
    # --- Input Validation ---#
    if not isinstance(script, SERIALIZED):
        raise StreamError("Tried to parse unserialized object")

    if isinstance(script, bytes):
        data = script
    else:
        data = get_stream(script).read()

    pos = 0
    length = len(data)
    asm_log = []

    while pos < length:
        opcode_int = data[pos]
        pos += 1
        # Direct push length (0x01-0x4b) - most common case first
        if 0x01 <= opcode_int <= 0x4b:
            # Pre-compute strings to avoid repeated formatting
            asm_log.append(f"OP_PUSHBYTES_{opcode_int}")

            # Bounds check
            if pos + opcode_int > length:
                raise OpCodeError("Script truncated during push operation")

            # Direct slice - faster than stream.read()
            push_data = data[pos:pos + opcode_int]
            asm_log.append(push_data.hex())
            pos += opcode_int

        # OP_PUSHDATA
        elif 0x4c <= opcode_int <= 0x4e:
            # OP_PUSHDATA1 (0x4c)
            if opcode_int == 0x4c:
                if pos >= length:
                    raise OpCodeError("Script truncated during OP_PUSHDATA1")

                push_length = data[pos]
                pos += 1

                asm_log.append("OP_PUSHDATA1")
                asm_log.append(f"{push_length:x}")  # Faster than hex()[2:]

                if pos + push_length > length:
                    raise OpCodeError("Script truncated during OP_PUSHDATA1 data")

            # OP_PUSHDATA2 (0x4d)
            elif opcode_int == 0x4d:
                if pos + 2 > length:
                    raise OpCodeError("Script truncated during OP_PUSHDATA2")

                # Unpack directly from bytes - faster than int.from_bytes
                push_length = data[pos] | (data[pos + 1] << 8)
                pos += 2

                asm_log.append("OP_PUSHDATA2")
                asm_log.append(f"{push_length:x}")

                if pos + push_length > length:
                    raise OpCodeError("Script truncated during OP_PUSHDATA2 data")

            # OP_PUSHDATA4 (0x4e)
            elif opcode_int == 0x4e:
                if pos + 4 > length:
                    raise OpCodeError("Script truncated during OP_PUSHDATA4")

                # Unpack 4 bytes directly
                push_length = (data[pos] |
                               (data[pos + 1] << 8) |
                               (data[pos + 2] << 16) |
                               (data[pos + 3] << 24))
                pos += 4

                asm_log.append("OP_PUSHDATA4")
                asm_log.append(f"{push_length:x}")

                if pos + push_length > length:
                    raise OpCodeError("Script truncated during OP_PUSHDATA4 data")
            else:
                raise OSError("Inconceivable failure")

            push_data = data[pos:pos + push_length]
            asm_log.append(push_data.hex())
            pos += push_length

        # Known opcodes - use dict.get() with default to avoid KeyError exception overhead
        else:
            opcode_name = OPCODES.get_name(opcode_int)
            if opcode_name:
                asm_log.append(opcode_name)
            else:
                raise OpCodeError(f"Unknown OP Code: {opcode_int:02x}")

    return asm_log


# --- TESTING --- #
if __name__ == "__main__":
    test_script1 = bytes.fromhex(
        "473044022041bfefb81655f1e7dff85778670ea4c9275e82e331f6da8d3d76abe09b26122e022028f1aebcb8c7175f478f7c0a6a49767c18f013da967fe213ff9d984a02b0546a012103c3087b4c8210793607c7cad3602f6046b6ca463036a9506f6f9848158dd37adb")
    asm_log1 = to_asm(test_script1)
    print(f"ASK LOG: {asm_log1}")
