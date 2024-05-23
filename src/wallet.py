"""
A class for BitClone wallets
"""
# --- IMPORTS --- #
import secrets
from hashlib import sha256

from ripemd.ripemd160 import ripemd160

from src.cryptography import SECP256K1


class Wallet:
    BIT_LENGTH = 256

    def __init__(self):
        self.curve = SECP256K1()
        self.private_key = secrets.randbits(self.BIT_LENGTH) % (self.curve.p - 1)
        self.public_key_point = self.curve.scalar_multiplication(
            n=self.private_key,
            pt=self.curve.g
        )
        self.pub_key_hash = ripemd160(
            sha256()
        )

    def get_keys(self):
        """
        We assign the private key, the public key point and the compressed public key
        """
        _private_key = secrets.randbits(self.BIT_LENGTH)
        pk_point = self.curve.scalar_multiplication(_private_key, self.curve.g)


# --- TESTING --- #
if __name__ == "__main__":
    w = Wallet()
    print(w.private_key)
    print(w.public_key_point)
