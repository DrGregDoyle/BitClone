"""
The ScriptSigEngine class
"""
from src.data import decode_der_signature


class ScriptSigEngine:
    # --- COMMON OP_CODES
    OP_0 = b'\x00'
    OP_PUSHBYTES_33 = b'\x21'
    OP_PUSHBYTES_65 = b'\x41'

    def __init__(self):
        pass

    def p2pk(self, signature: bytes) -> bytes:
        """
        Pay to public key | OP_PUSHBYTES + DER-ENCODED SIGNATURE
        """
        if not self._verify_signature(signature):
            raise ValueError("Signature is incorrectly formatted")

        # Return script sig
        return len(signature).to_bytes(1, "little") + signature

    def p2pkh(self, signature: bytes, pubkey: bytes):
        """
        Pay to public key hash | OP_PUSHBYTES + DER-ENCODED SIGNATURE + OP_PUSHBYTES + PUBKEY (compressed or
        uncompressed)
        """
        # Get p2pk bytes | Verify signature
        p2pk = self.p2pk(signature)  # OP_PUSHBYTES + DER-ENCODED SIGNATURE

        # Get pubkey bytes
        if len(pubkey) == 33:
            op_pushcode = self.OP_PUSHBYTES_33
        elif len(pubkey) == 65:
            op_pushcode = self.OP_PUSHBYTES_65
        else:
            raise ValueError("Pubkey not in correct format")

        # Return scriptisg
        return p2pk + op_pushcode + pubkey

    def p2ms(self, signatures: list):
        """
        Pay 2 multisig | OP_0 + (OP_PUSHBYTES + DER-ENCODED SIGNATURE) * len(signatures)
        """
        scriptsig = self.OP_0
        for sig in signatures:
            scriptsig += len(sig).to_bytes(1, "little") + sig
        return scriptsig

    def p2sh(self, locking_script: bytes, redeem_script: bytes):
        """
        Pay to script hash: Can only use the two-script scriptsig
        """
        op_pushbytes_locking = len(locking_script).to_bytes(1, "little")
        op_pushbytes_redeem = len(redeem_script).to_bytes(1, "little")
        scriptsig = self.OP_0 + op_pushbytes_locking + locking_script + op_pushbytes_redeem + redeem_script
        return scriptsig

    def _verify_signature(self, signature: bytes) -> bool:
        """
        We verify the signature is properly DER-encoded
        """
        try:
            decode_der_signature(signature)
            return True
        except ValueError:
            return False
