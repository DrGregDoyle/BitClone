"""
The SignatureEngine class, used to create signatures for transactions
"""
from src.cryptography.ecc import Point
from src.cryptography.ecdsa import ecdsa, verify_ecdsa
from src.cryptography.schnorr import schnorr_sig, schnorr_verify


# cryptography/signature_engine.py
class SignatureEngine:
    """Pure cryptographic operations for signatures"""

    # --- Schnorr --- #
    def get_schnorr_sig(self, priv_key: int, msg: bytes, aux_bytes: bytes = None) -> bytes:
        # Validation here
        return schnorr_sig(priv_key, msg, aux_bytes)

    def verify_schnorr_sig(self, xonly_pubkey: int | bytes, msg: bytes, sig: bytes) -> bool:
        # Validation here
        return schnorr_verify(xonly_pubkey, msg, sig)

    # --- ECDSA --- #
    def get_ecdsa_sig(self, private_key: int, message: bytes):
        # Validation here
        return ecdsa(private_key, message)

    def verify_ecdsa_sig(self, signature: tuple, message: bytes, public_key: Point | tuple):
        # TODO: Modify signature to be a DER-encoded bytes object
        # TODO: Modify pubkey to be a bytes object, either compressed, uncompressed, or xonly
        # Validation here
        # Modify data here
        return verify_ecdsa(signature, message, public_key)

    # --- SIGHASH --- #

    # Keep sighash methods:
    # - get_legacy_sighash()
    # - get_segwit_sighash()
    # - get_taproot_sighash()
