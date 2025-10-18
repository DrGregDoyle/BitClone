"""
The ScriptEngine class
"""

from io import BytesIO

from src.core.byte_stream import get_stream
from src.core.exceptions import ScriptEngineError
from src.core.opcodes import OPCODES
from src.script.context import ExecutionContext
from src.script.opcode_map import OPCODE_MAP
from src.script.scriptpubkey import ScriptPubKey, P2SH_Key
from src.script.scriptsig import ScriptSig, P2SH_Sig
from src.script.signature_engine import SignatureEngine, SignatureContext
from src.script.stack import BitStack, BitNum
from src.tx.tx import Transaction
from src.tx.utxo import UTXO

__all__ = ["ScriptEngine"]

_OP = OPCODES()


class ScriptEngine:
    opcode_map = OPCODE_MAP
    opcode_names = _OP.get_code_dict()

    def __init__(self):
        self.stack = BitStack()
        self.alt_stack = BitStack()
        self.ops_log = []
        self.sig_engine = SignatureEngine()

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
        """
        0xab -- 0xba
        """
        # Parse signature type
        match opcode:
            # OP_CODESEPARATOR
            case 0xab:
                print("OP_CODESEPARATOR")
            # OP_CHECKSIG
            case 0xac:
                self._handle_checksig(ctx)
            # OP_CHECKSIGVERIFY
            case 0xad:
                self._handle_checksig(ctx)
                verified = self._op_verify()
                if not verified:
                    raise ScriptEngineError("Script failed OP_VERIFY call in OP_CHECKSIGVERIFY")
            # OP_CHECKMULTISIG
            case 0xae:
                self._handle_multisig(ctx)
            case _:
                print(f"OPCODE: {opcode}")

    def _handle_checksig(self, ctx: ExecutionContext):
        # Get context elements
        tx = ctx.tx
        utxo = ctx.utxo
        input_index = ctx.input_index

        # Validate
        if tx is None or utxo is None:
            raise ScriptEngineError("Missing context elements for OP_CHECKSIG")

        # Pop pubkey and signature
        pubkey, sig = self.stack.popitems(2)

        # Signature should be DER-encoded with sighash num
        der_sig = sig[:-1]
        sighash_num = sig[-1]

        # Get legacy sighash
        sig_ctx = SignatureContext(tx=tx, input_index=input_index, sighash_type=sighash_num,
                                   script_code=utxo.scriptpubkey)
        message_hash = self.sig_engine.get_legacy_sighash(sig_ctx)
        signature_verified = self.sig_engine.verify_ecdsa_sig(der_sig, message_hash, pubkey)
        self.stack.pushbool(signature_verified)

    def _handle_multisig(self, ctx: ExecutionContext):
        """
        OP_CHECKMULTISIG:
            1) pop n, then pop that number of public keys
            2) pop m, then pop that number of signatures
            3) compare each signature with the corresponding public key
        """
        # Step 1: Extract values
        pubkeynum = self.stack.popnum()
        pubkeys = [self.stack.pop() for _ in range(pubkeynum)]
        signum = self.stack.popnum()
        sigs = [self.stack.pop() for _ in range(signum)]
        empty_byte = self.stack.pop()

        # Validate
        if empty_byte != b'':
            raise ScriptEngineError("Missing NULLDUMMY at bottom of stack for OP_CHECKMULTISIG")

        # Step 2: Initialize indexes
        sig_index = 0
        key_index = 0
        matches = 0

        # Step 3: Try to match signatures to public keys
        while sig_index < len(sigs) and key_index < len(pubkeys):
            sig = sigs[sig_index]
            pub = pubkeys[key_index]

            # Signature should be DER-encoded with sighash num
            der_sig = sig[:-1]
            sighash_num = sig[-1]

            # Get legacy sighash
            sig_ctx = SignatureContext(tx=ctx.tx, input_index=ctx.input_index, sighash_type=sighash_num,
                                       script_code=ctx.utxo.scriptpubkey)
            message_hash = self.sig_engine.get_legacy_sighash(sig_ctx)

            if self.sig_engine.verify_ecdsa_sig(signature=der_sig, message=message_hash, public_key=pub):
                matches += 1
                sig_index += 1

            key_index += 1  # always advance key_index

        # Push bool
        self.stack.pushbool(matches == len(sigs))

    def _op_verify(self) -> bool:
        top = self.stack.pop()
        return top != b''  # Returns False whenever top of stack is b''

    def validate_script_pair(self, scriptpubkey: ScriptPubKey, scriptsig: ScriptSig, ctx: ExecutionContext = None):
        """
        We validate the scriptsig + scriptpubkey against the given ExecutionContext. For use with legacy signatures
        """
        # Check for P2SH

        combined_script = scriptsig.script + scriptpubkey.script
        return self.validate_script(combined_script, ctx)

    def validate_script(self, script: bytes, ctx: ExecutionContext = None, sighash_flag: bool = False):
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

            # Handle OP_num
            elif 0x51 <= opcode <= 0x60:
                num = opcode - 0x50
                self.stack.push(BitNum(num).to_bytes())

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

        # --- LOGGING --- #
        print("--- VALIDATE STACK ---")
        print(f"MAIN STACK: {self.stack.to_json()}")
        print(f"OPS LOG: {self.ops_log}")

        return self.validate_stack()

    def validate_stack(self) -> bool:
        """
        Called at the end of the script engine. Return False if any of the following are True:
            - Stack is empty
            - Only element left on the stack is OP_0 (aka b'')
            - More than one element left on the stack
            - Script exits prematurely (e.g OP_RETURN)
        """
        if self.stack.height != 1:
            # Handles empty stack and more than one element left on stack
            return False
        last_element = self.stack.pop()  # Also clears stack for next execution
        return last_element != b''  # Return True if element is anything other than OP_0


# --- TESTING --- #

if __name__ == "__main__":
    # P2SH - Setup
    test_p2sh_key = P2SH_Key.from_bytes(bytes.fromhex("a914748284390f9e263a4b766a75d0633c50426eb87587"))
    test_p2sh_sig = P2SH_Sig.from_bytes(bytes.fromhex(
        "00473044022100d0ed946330182916da16a6149cd313a4b1a7b41591ee52fb3e79d64e36139d66021f6ccf173040ef24cb45c4db3e9c771c938a1ba2cf8d2404416f70886e360af401475121022afc20bf379bc96a2f4e9e63ffceb8652b2b6a097f63fbee6ecec2a49a48010e2103a767c7221e9f15f870f1ad9311f5ab937d79fcaeee15bb2c722bca515581b4c052ae"))

    print(f"P2SH KEY: {test_p2sh_key.to_json()}")
    print(f"P2SH SIG: {test_p2sh_sig.to_json()}")

    # Context
    current_tx = Transaction.from_bytes(
        bytes.fromhex(
            "010000000c3e10e0814786d6e02dfab4e2569d01a63191b8449bb0f5b9af580fc754ae83b9000000006c493046022100b387bc213db8a333f737e7e6b47ac5e56ba707e97682c1d6ae1d01e28fcfba620221009b7651bbf054babce6884937d598f845f533bac5dc0ec235b0e3408532b9c6e101210308b4492122999b36c09e50121544aa402cef45cd41970f1be6b71dcbd092a35effffffff40629a5c656e8a9fb80ae8a5d55b80fbb598a059bad06c50fcddf404e932d59e000000006a473044022011097b0f58e39fe1f0df7b3159456b12c3b244dcdf6a0fd138ec17d76d41eb5c02202fb5e7cec4f2efbcc90989693b7b6309fcaa27d6aac71eb3dcef60e27a7e7357012103c241a14762ef670d96c0afa470463512f5f356e0752216d34d55b6bfa38acd93ffffffff5763070e224f18dbc8211e60c05ae31543958b248eb08c9e5989167c60b3c570000000006c49304602210088db31bb970f2e77a745d15b8a31d64734c8a9eca3a24540ffa850c90f8a6f50022100bc43eb2a20d70da74cfb2be8eee69c0c1adf741130792aa882a0cda9f7df4b6f012102b5e2177732d3f19abd0e15ac5ff2d5546f70e3f91674b110ccdee8458554f1acffffffff5b4e96a245f6fbc2efb910e25e9dd7a26e0ef8486eebd50dc658ae7d9719e5fd000000006a4730440220656be7132d238e4a848f0da1c3bdc0e22b475e1b66011e1b0536e18cbfe553f502205c89da6c8dad09f5e171404bf66fc19c7d5d2066d4ff4eff3f0766d31688cc4d012102086323b48e87d7fcacb014a58889f20a9881956bf46898c4ffda84b23c965d31ffffffff6889fe551cb869bf20284c64fc3adc229fded6e11fc8b79ec11bb2e499bd0d6c290000006a4730440220226d97d92d855bb2dad731b0cf339727e0f4449c89b1cc1cff7a9432db2a53fb02203478f549e5997b0dccd6abbc5bb206ce40f706672e27b58e3bab210da105dbcf012103c241a14762ef670d96c0afa470463512f5f356e0752216d34d55b6bfa38acd93ffffffff6a1c310490053bfc791ec646907941d3df59bfa8db1b21789d8780c7489695c1000000006a473044022079913e50a223d46c3800f33a6071651aabeecbcc7c726a78aca04dd2832ebe92022075275dbfadcfcca48fa834e7130d24b1055e9ee1470e0bf7ecdf0d9091b27fdc012102fbb8f0fcb28163dd56e26fd7d4b85b71016e62696e577057ddeac36d08a03e26ffffffff79d87f7daedaee7c6e80059b38cde214fec5e4546fbdccc7c24c01c47dce1c23200000008c493046022100ec02daed0c2ab978f588a0486deef52e62b6aa82297b994fe5486d79f8457acb02210098750e260959d6bbd4d47a018b27ea15493d4cd4cb7c96136282745c41aa1c9b014104658e3e86e3740257ebf67085deb14b877955aac502a6b5dcec0cfe1f3026f27b3a772a189b1bb2c28d026bc626a48710edffa9d40830286b80b3ac5709509974ffffffff9a19e8ede8836c192fe816d80d392bb7bb5453f320a78854a83e46bd9f27bf1e000000006c4930460221008b06d1813afd4f368a9570405df7978dca0b4400d173c937931942d88776bfa4022100a7a85b09e50e12e474b634a22fbe6645227dc13cbba2aaa2a84bb1da5e1dc2f1012103c241a14762ef670d96c0afa470463512f5f356e0752216d34d55b6bfa38acd93ffffffffd3090eb0855eee3d1dba53d68edeca6c368a37d3bba9579da3ac675ece42d7680e0000008a47304402204e2518419626eb846e0ef96fb7eda1d7b954b2821482b771f372484c0e327e560220370108f1a7b4676973585c861f5365d8fc2b2b170d922d6fccb15216976a82f80141044884e2974c370394aae8121735a56eaa7215a6a46661f1ca9454c1b99611ae34903e9515b2902f2a22104d10bfd1c2303b38a14be5f2b62b0591ca0d8bbb6864fffffffff61ff40c78b3e12e7d1f9a9db04a7b7736510014fc15a950d575c159b4b0b7a5000000008c493046022100b9b7c3ac969ee98295ec063c84f05c4bf4ee0d4c25448847d44c8e4af3425af7022100cfc90b396f524c366d66a44fa77502dd6f338a584ce653332bcb8909d14360c00141048501beadf835ce4da4078dce8a9dd57964f91da9d675b3d23d45f0de71a03b24d0daf75f29cd521531d5b4389331fe6891e7e1214710cf73e7dbc91cd41cfcecffffffff4471e66e1622bf197ba49ab31d1bd29b4917af60ce103bb6713ffb709b300c45000000006b483045022100a84f83410eb3b40959830b444a85dc1251486afa6e27288bd22fb5771d09795302207d604b1d1c3f8f2d3a9c2ee1007f6b034f69339d0de4f567c12f54af14e208b6012102cbac13c0b22e24ab33131c69e36bdbbe0218cd7f43dcbf9a4b488aadc8ac23b4ffffffff4471e66e1622bf197ba49ab31d1bd29b4917af60ce103bb6713ffb709b300c45010000009100473044022100d0ed946330182916da16a6149cd313a4b1a7b41591ee52fb3e79d64e36139d66021f6ccf173040ef24cb45c4db3e9c771c938a1ba2cf8d2404416f70886e360af401475121022afc20bf379bc96a2f4e9e63ffceb8652b2b6a097f63fbee6ecec2a49a48010e2103a767c7221e9f15f870f1ad9311f5ab937d79fcaeee15bb2c722bca515581b4c052aeffffffff0196e756080000000017a914748284390f9e263a4b766a75d0633c50426eb8758700000000")
    )
    current_input_index = 11

    # print(f'CURRENT TX: {current_tx.to_json()}')

    test_utxo = UTXO(
        # Reverse display txid
        txid=bytes.fromhex("450c309b70fb3f71b63b10ce60af17499bd21b1db39aa47b19bf22166ee67144")[::-1],
        vout=1,
        amount=10000000,
        scriptpubkey=test_p2sh_key.script,
        block_height=183729
    )

    p2ms_context = ExecutionContext(
        tx=current_tx,
        input_index=current_input_index,
        utxo=test_utxo
    )
    #
    # # Validate
    # engine = ScriptEngine()
    # script_valid = engine.validate_script_pair(test_p2ms_key, test_p2ms_sig, p2ms_context)
    # print(f"Validate P2MS Script Pair: {script_valid}")
