"""
The ScriptEngine class
"""

from io import BytesIO

from src.core.byte_stream import get_stream
from src.core.exceptions import ScriptEngineError
from src.core.opcodes import OPCODES
from src.script.context import ExecutionContext
from src.script.opcode_map import OPCODE_MAP
from src.script.scriptpubkey import ScriptPubKey, P2SH_Key, P2WPKH_Key, P2PKH_Key
from src.script.scriptsig import ScriptSig, P2SH_P2WPKH_Sig
from src.script.signature_engine import SignatureEngine, SignatureContext
from src.script.stack import BitStack, BitNum
from src.tx.tx import WitnessField, Transaction
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

        # Use script_code from context if available (for P2SH), otherwise use scriptpubkey
        script_code = ctx.script_code if hasattr(ctx, 'script_code') and ctx.script_code else utxo.scriptpubkey

        # Get sighash
        sig_ctx = SignatureContext(tx=tx, input_index=input_index, sighash_type=sighash_num,
                                   script_code=script_code, amount=utxo.amount)
        if ctx.is_segwit:
            message_hash = self.sig_engine.get_segwit_sighash(sig_ctx)
        else:
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

        # Use script_code from context if available (for P2SH), otherwise use scriptpubkey
        script_code = ctx.script_code if hasattr(ctx, 'script_code') and ctx.script_code else ctx.utxo.scriptpubkey

        # Step 3: Try to match signatures to public keys
        while sig_index < len(sigs) and key_index < len(pubkeys):
            sig = sigs[sig_index]
            pub = pubkeys[key_index]

            # Signature should be DER-encoded with sighash num
            der_sig = sig[:-1]
            sighash_num = sig[-1]

            # Get legacy sighash
            sig_ctx = SignatureContext(tx=ctx.tx, input_index=ctx.input_index, sighash_type=sighash_num,
                                       script_code=script_code)
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

    def validate_segwit(self, scriptpubkey: ScriptPubKey, ctx: ExecutionContext) -> bool:
        """
        For use with P2WPKH and P2WSH
        """
        # Clear stacks
        self.clear_stacks()

        # Find type
        if P2WPKH_Key.matches(scriptpubkey.script):
            is_p2wpkh = True
        else:
            is_p2wpkh = False

        # Handle P2WPKH
        if is_p2wpkh:
            # Get WitnessField from context
            tx = ctx.tx
            input_index = ctx.input_index
            witness_field: WitnessField = tx.witness[input_index]

            if len(witness_field.items) != 2:
                raise ScriptEngineError("Expected 2 stackitems for P2WPKH Witness")

            # Push Signature and public key to stack
            sig = witness_field.items[0]
            pubkey = witness_field.items[1]
            self.stack.push(sig)
            self.stack.push(pubkey)

            # Get pubkeyhash from ScriptPubKey and create P2PKH script
            pubkeyhash = scriptpubkey.script[2:]
            p2pkh_script = P2PKH_Key.from_pubkeyhash(pubkeyhash)

            # Execute the P2PKH script
            self.execute_script(p2pkh_script.script, ctx)

            # Validate the stack
            return self.validate_stack()

        return True

    def validate_script_pair(self, scriptpubkey: ScriptPubKey, scriptsig: ScriptSig, ctx: ExecutionContext = None) -> \
            bool:
        """
        We validate the scriptsig + scriptpubkey against the given ExecutionContext. For use with legacy signatures
        """
        # Proceed based on P2SH
        if not P2SH_Key.matches(scriptpubkey.script):
            # Not P2SH, validate combined script pairs
            return self.validate_script(scriptsig.script + scriptpubkey.script, ctx)

        # Assuming P2SH operation
        ctx.is_p2sh = True
        self.clear_stacks()  # Clear stacks here for P2SH

        # Execute scriptSig
        self.execute_script(scriptsig.script, ctx)

        # Before processing the scriptpubkey we copy the redeem_script
        redeem_script = self.stack.top
        print(f"REDEEM SCRIPT: {redeem_script.hex()}")

        # Execute scriptpubkey
        self.execute_script(scriptpubkey.script, ctx)

        # Stack should now have 1 on top of stack and signatures for redeem script
        if not self._op_verify():
            print("P2SH ScriptPubKey failed OP_EQUAL check for HASH160")
            return False

        # Handle P2WPKH
        if P2WPKH_Key.matches(redeem_script):
            # Get elements
            tx = ctx.tx
            witness = tx.witness[ctx.input_index]
            witsig = witness.items[0]
            witkey = witness.items[1]

            # Remove P2WPKH key and push signature and pubkey
            self.stack.push(witsig)
            self.stack.push(witkey)

            # Get pubkeyhash from P2SH-P2WPKH_Sig and create P2PKH script
            pubkeyhash = scriptsig.script[3:]
            p2pkh_script = P2PKH_Key.from_pubkeyhash(pubkeyhash)

            # Execute the P2PKH script
            self.execute_script(p2pkh_script.script, ctx)
        else:
            ctx.script_code = redeem_script
            # Execute redeem script
            self.execute_script(redeem_script, ctx)
        return self.validate_stack()

        # combined_script = scriptsig.script + scriptpubkey.script
        # return self.execute_script(combined_script, ctx)

    def execute_script(self, script: bytes, ctx: ExecutionContext = None):
        """
        We only execute the given script with the accompanying ExecutionContext. We do NOT manage or validate the
        stacks.
        """

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

    def validate_script(self, script: bytes, ctx: ExecutionContext) -> bool:
        # Clear stacks
        self.clear_stacks()

        # Execute script
        self.execute_script(script, ctx)

        # Validate stack
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
    # P2SH-P2WPKH

    # ScriptPubKey
    test_p2sh_key = P2SH_Key.from_bytes(bytes.fromhex("a9146d3ed4cf55dc6752a12d3091d436ef8f0f982ff887"))
    print(f"P2SH ScriptPubKey: {test_p2sh_key.to_json()}")
    test_p2wpkh_key = P2WPKH_Key.from_bytes(bytes.fromhex("001402c8147af586cace7589672191bb1c790e9e9a72"))
    print(f"P2WPKH ScriptPubLey: {test_p2wpkh_key.to_json()}")

    test_p2sh_p2wpkh_sig = P2SH_P2WPKH_Sig.from_bytes(bytes.fromhex("16001402c8147af586cace7589672191bb1c790e9e9a72"))
    print(f"P2SH-P2WPKH SIG: {test_p2sh_p2wpkh_sig.to_json()}")

    p2sh_utxo = UTXO(
        txid=bytes.fromhex("021e23df3cdb8b504bec1a3f7a382a83be7518354bac2331076753b5b4755a4e")[::-1],
        vout=0,
        amount=25552,
        scriptpubkey=test_p2sh_key.script,
        block_height=826281
    )

    witness_sig = bytes.fromhex(
        "304402201f85ab44217563b4ce9d11e4c7b00dc59dd102099eb250634f4b6906276ba07702206147cc98f29c5fcbad925b5e40fe154f4d429f9569f292f9298f615c4940044501")
    witness_pubkey = bytes.fromhex("022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c")
    test_witness = WitnessField(items=[witness_sig, witness_pubkey])

    test_tx = Transaction.from_bytes(bytes.fromhex(
        "0200000000010d4e5a75b4b55367073123ac4b351875be832a387a3f1aec4b508bdb3cdf231e02000000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffff419ea287480a53e96aaeb95db362eb4a608cabccb82ba78a701ea63a0b23af14000000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffff604b150686c6459235e69be6202154634639b81088d5f7011e31665c2a5a371f010000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffffe576dfe9c5c52146c666e2f554feb2dd2ad470cd03130a4b7ddaeef5ccfcc31f010000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffff0c3e97ca785fdf883b240bc7cbc407de6c4689aaf1368480fafabf6196702639000000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffff4529bc7981a486dae2cdf12a058816fac5a73ff283c8e2d3eb057da9b927d34c010000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffffa102354da66de20c297bd16eb5d01eef1460e0dcd6ffac5d415c7fdbc1b01b78410000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffff5fe060edff8c3317f86f4c0f3924f26d3614b72f2ed28461f6194d07daa3f587000000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffffa7b5e7eed6977fced331d6584dd2268c83c03b9bcf5959a0ebdf765c50f7e18f000000001716001402c8147af586cace7589672191bb1c790e9e9a72fdfffffff23eada5b5a698ce09738bd0d50f9fa5d0dbfcbf858f6452ca798f347c889ad9010000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffff775b6257bb283ceb283d313feb86a59eb1791f6f0cd370b584e1ca45642817e3000000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffff8d206dea8e821433af2a861ec6d37afcb643b8e2cd593673214e6f68e96913ea000000001716001402c8147af586cace7589672191bb1c790e9e9a72fdfffffffdc64af7edb03bca45cdb62cd605c7fc9f7bbacf928b46a075c9fbefcf2630ed000000008a4730440220730e055cefab7ac3120dd9e7fe7e9490c6b88b1dd2184635b15512e23d618d8302206f6aa6911e2e3ec348021633334c75b75486548fea38354e5aa772272e02a6cd01410408b281209f4e42f7a85a459eb19b65154a4eb078282bf58382f30eae58d249659cb67bc5e52afb23470dca828ff1193d43b46779d330332e3e1fd32955e5379bfdffffff010715990600000000160014907189739c6255dce21f61cc906707f949322add0247304402201f85ab44217563b4ce9d11e4c7b00dc59dd102099eb250634f4b6906276ba07702206147cc98f29c5fcbad925b5e40fe154f4d429f9569f292f9298f615c494004450121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c024730440220346d5b3ef82fcd35618cce141925474cc4a652c2bbedc54605af267f08f98dad022020b630ea92f193d30f36841bfacdaf7f21d877745a01cd70fb6f1ed8726165680121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c02473044022008e762cf7163c6adbd56d53648849fd6a606a65a4bd4888c3d8f55168afd13d002202778e6ac8eb2e6f35facef2e6fda07d7c39e44759a2c4e4253f895d02328b9900121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c0247304402207cf547a4f22aec344ec1b3cc7db7c2a63db1a1a9b8626aaeb32c9b2546e361f5022053fe8dcbc1bd133765b5caf95ff9db5c34a4066b25acb2df2791e193c823cc370121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c02473044022004c3c5517599fdf88c6209237a2b113cf4a4500538dfeee21c93f68c067319e202206a44299a0e9a45896f51d37a6b64d9587b6093a527fd8ccc129715fb4e3235e80121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c0247304402206268b59fb737258d90be572e89edca479826986a2be599b20b6000c4c131ae8c02204ca861d33240d0dadeb437c4e849a700b455847609a810e6236a71cda58a8ba90121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c0247304402205710dbfb624e0e05fe4b9874386c93084e88b89e16eb94608d6a92e451f5f3cd0220570367db12e3d07de3f08c735f3a3e719b6f78f87a7e20baf1f3db01764451bf0121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c0247304402206d43fe58a74044fc81df8b10854a4067af4c7fe1b61992818c2bac30eb5cb28b02204a58491439771f897a087748df55e78b6d63a7105f83491aac408e446391dac70121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c02473044022062599a99c5e7bcbce1fe649869cd017d7107a63550fa67c1677039f1ab4b593402201a4c271c3c0792d28d78338a97c3651de329e0cde31fb610157bf026f22b68e00121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c0247304402207b7bfd5c8abf833d2a9b10f95749e596eab49fd77ce9237fcfbb804be492d3ed02207a85b47a0ba69e483dd411e4da9c0470b6bf21664096be160067dd674701980e0121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c0247304402206d7db777e15bf1974aec93ce65d02802ded6ee2055dd890698e573f22b02f55e02206e21249c21f72700b583365ed111d1d172452175d8bb870e7076d6a4b3e529d50121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c0247304402202af8e3170475f06e91a26fe2c666d745406b91b9a063ec0513062f0e982a219f02200d6f865b3dc4eae5fcb2eb11fc15cefdb5d0c4868f2dd2a17f981d3065e28f280121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c0081a80c00"
    ))

    print(f'TEST TX: {test_tx.to_json()}')

    test_ctx = ExecutionContext(
        tx=test_tx,
        utxo=p2sh_utxo,
        input_index=0,
        is_segwit=True,
        script_code=bytes.fromhex("02c8147af586cace7589672191bb1c790e9e9a72")
    )

    engine = ScriptEngine()
    tx_validated = engine.validate_script_pair(test_p2sh_key, test_p2sh_p2wpkh_sig, test_ctx)
    print(f"TX VALIDATED: {tx_validated}")
