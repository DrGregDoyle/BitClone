"""
The ScriptEngine class
"""

from io import BytesIO

from src.core.byte_stream import get_stream
from src.core.opcodes import OPCODES
from src.script.context import ExecutionContext
from src.script.opcode_map import OPCODE_MAP
from src.script.scriptpubkey import ScriptPubKey, P2PK_Key
from src.script.scriptsig import ScriptSig, P2PK_Sig
from src.script.stack import BitStack

_OP = OPCODES()


class ScriptContext:
    """
    Data class for holding elements necessary for script evaluation
    """
    pass


class ScriptEngine:
    opcode_map = OPCODE_MAP
    opcode_names = _OP.get_code_dict()

    def __init__(self):
        self.stack = BitStack()
        self.alt_stack = BitStack()
        self.ops_log = []

    def clear_stacks(self):
        self.stack.clear()
        self.alt_stack.clear()
        self.ops_log = []

    def _read_opcode(self, stream: BytesIO):
        opcode_byte = stream.read(1)
        return int.from_bytes(opcode_byte, "little") if opcode_byte else None

    def _handle_pushdata(self, opcode: int, stream: BytesIO):
        # Validate
        if not 0x01 <= opcode <= 0x4b:
            raise TypeError("Opcode out of bounds for pushdata operation")
        data = stream.read(opcode)
        self.stack.push(data)
        # ops_log
        self.ops_log.append(data.hex())

    def _handle_pushdata_n(self, n, stream: BytesIO):
        n_bytes = stream.read(n)
        num = int.from_bytes(n_bytes, "little")
        data = stream.read(num)
        self.stack.push(data)
        # ops_log
        self.ops_log.extend([num, data.hex()])

    def _handle_signatures(self, opcode: int, stream: BytesIO, ctx: ExecutionContext):
        pass

    def validate_script_pair(self, scriptpubkey: ScriptPubKey, scriptsig: ScriptSig, ctx: ExecutionContext = None):
        """
        We validate the scriptsig + scriptpubkey against the given ExecutionContext
        """
        combined_script = scriptsig.script + scriptpubkey.script
        return self.validate_script(combined_script, ctx)

    def validate_script(self, script: bytes, ctx: ExecutionContext = None):
        # Prep Stacks
        self.clear_stacks()

        # Get script as byte stream
        stream = get_stream(script)

        # Read script
        valid_script = True
        while valid_script:
            opcode = self._read_opcode(stream)

            # Handle end of stream
            if opcode is None:
                self.ops_log.append("--- END OF SCRIPT ---")
                break

            # Get opcode name
            opcode_name = _OP.get_name(opcode)
            self.ops_log.append(opcode_name)

            # Handle data
            if 0x01 <= opcode <= 0x4b:
                self._handle_pushdata(opcode, stream)

            # Handle pushdata_n
            elif 0x4c <= opcode <= 0x4e:
                match opcode:
                    case 0x4c:
                        n = 1
                    case 0x4d:
                        n = 2
                    case _:
                        n = 4
                self._handle_pushdata_n(n, stream)

            # Handle checksigs
            elif 0xab <= opcode <= 0xba:
                self._handle_signatures(opcode, stream, ctx)

            # Get function for operation
            else:
                func = OPCODE_MAP[opcode]
                # --  Call func with various inputs depending on opcode
                # Main stack and Alt Stack
                if opcode in [0x6b, 0x6c]:
                    func(self.stack, self.alt_stack)
                else:
                    func(self.stack)
        # TODO: Add stack validation once the script is over
        print(f"OPS LOG: {self.ops_log}")
        print(f"MAIN STACK: {self.stack.to_json()}")


# --- TESTING --- #
if __name__ == "__main__":
    _test_p2pk_key = P2PK_Key.from_bytes(bytes.fromhex(
        "41049464205950188c29d377eebca6535e0f3699ce4069ecd77ffebfbd0bcf95e3c134cb7d2742d800a12df41413a09ef87a80516353a2f0a280547bb5512dc03da8ac"))
    _test_p2pk_sig = P2PK_Sig.from_bytes(bytes.fromhex(
        "483045022100c219a522e65ca8500ebe05a70d5a49d840ccc15f2afa4ee9df783f06b2a322310220489a46c37feb33f52c586da25c70113b8eea41216440eb84771cb67a67fdb68c01"))
    print(f"P2PK KEY: {_test_p2pk_key.to_asm()}")
    print(f"P2PK SIG: {_test_p2pk_sig.to_asm()}")
    engine = ScriptEngine()
    engine.validate_script_pair(_test_p2pk_key, _test_p2pk_sig)
