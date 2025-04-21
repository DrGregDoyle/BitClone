"""
The ScriptSigEngine class
"""
from src.data import decode_der_signature, to_little_bytes


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
        return to_little_bytes(len(signature), 1) + signature

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
            if not 0x01 <= len(sig) <= 0x4b:
                raise ValueError("Signature outside of pushbytes range")
            scriptsig += to_little_bytes(len(sig), 1) + sig
        return scriptsig

    def p2sh(self, items: list[bytes], redeem_script: bytes) -> bytes:
        """
        Generic P2SH scriptsig: pushes all 'items' (args for redeem script), then pushes redeem script bytes.
        Handles multisig case with leading OP_0.
        """
        parts = []

        # If it's a multisig script, we expect a dummy OP_0 (i.e., b'')
        if items and items[0] == b'\x00':
            parts.append(b'\x00')  # OP_0
            items = items[1:]  # Don't mutate original list

        # Push args
        parts.extend([self._pushdata(item) for item in items])

        # Push redeem script
        parts.append(self._pushdata(redeem_script))

        return b''.join(parts)

    def _verify_signature(self, signature: bytes) -> bool:
        """
        We verify the signature is properly DER-encoded
        """
        der_encoding = signature[:-1]
        sighash_num = signature[-1]
        try:
            decode_der_signature(der_encoding)
            return True
        except ValueError:
            return False

    def _pushdata(self, item: bytes) -> bytes:
        """
        For a given item, return the corresponding OP_CODES + Data for a datapush
        """
        length = len(item)
        if length <= 75:
            return length.to_bytes(1, "little") + item
        elif length <= 255:
            return b'\x4c' + length.to_bytes(1, "little") + item
        elif length <= 65535:
            return b'\x4d' + length.to_bytes(2, "little") + item
        else:
            return b'\x4e' + length.to_bytes(4, "little") + item
