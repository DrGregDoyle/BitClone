"""
Class for outputting script into readable ASM
"""
from io import BytesIO

from src.backup.script import OPCODES

__all__ = ["ScriptParser"]


class ScriptParser:

    @staticmethod
    def parse_script(script: bytes) -> list:
        """
        Outputs the corresponding ASM of the script
        """
        if not isinstance(script, (bytes, BytesIO)):
            raise ValueError(f"Expected byte data stream, received {type(script)}")
        stream = BytesIO(script) if isinstance(script, bytes) else script

        asm_log = []

        while True:
            opcode = stream.read(1)
            if not opcode:
                break

            opcode_int = int.from_bytes(opcode, "little")

            # 0x01–0x4b: direct push length
            if 0x01 <= opcode_int <= 0x4b:
                asm_log.append(f"OP_PUSHBYTES_{opcode_int}")
                data = stream.read(opcode_int)
                asm_log.append(data.hex())

            # OP_PUSHDATA1
            elif opcode_int == 0x4c:
                length = int.from_bytes(stream.read(1), "little")
                asm_log.append("OP_PUSHDATA1")
                asm_log.append(f"{hex(length)[2:]}")
                data = stream.read(length)
                asm_log.append(data.hex())

            # OP_PUSHDATA2
            elif opcode_int == 0x4d:
                length = int.from_bytes(stream.read(2), "little")
                asm_log.append("OP_PUSHDATA2")
                asm_log.append(f"{hex(length)[2:]}")
                data = stream.read(length)
                asm_log.append(data.hex())

            # OP_PUSHDATA4
            elif opcode_int == 0x4e:
                length = int.from_bytes(stream.read(4), "little")
                asm_log.append("OP_PUSHDATA4")
                asm_log.append(f"{hex(length)[2:]}")
                data = stream.read(length)
                asm_log.append(data.hex())

            # Known opcode
            elif opcode_int in OPCODES:
                asm_log.append(OPCODES[opcode_int])

            # Unknown opcode
            else:
                asm_log.append(f"OP_UNKNOWN_{opcode_int:02x}")

        return asm_log
