"""
A class for BitClone wallets
"""
# --- IMPORTS --- #
import secrets
from hashlib import sha256

from ripemd.ripemd160 import ripemd160

from src.cryptography import SECP256K1


def hash160(my_string: str):
    return ripemd160(sha256(my_string.encode()).hexdigest().encode()).hex().upper()


class Wallet:
    BIT_LENGTH = 256

    def __init__(self):
        self.curve = SECP256K1()
        self.private_key = secrets.randbits(self.BIT_LENGTH) % (self.curve.p - 1)
        self.public_key_point = self.curve.scalar_multiplication(
            n=self.private_key,
            pt=self.curve.g
        )
        self.h_upk, self.h_cpk = self.get_keys()

    def get_keys(self):
        """
        We assign the private key, the public key point and the compressed public key
        """
        _private_key = secrets.randbits(self.BIT_LENGTH)
        pk_point = self.curve.scalar_multiplication(_private_key, self.curve.g)
        pk_x, pk_y = pk_point
        hex_x = hex(pk_x)[2:]
        hex_y = hex(pk_y)[2:]

        uncompressed_public_key = "04" + hex_x + hex_y
        compressed_public_key = "02" + hex_x if pk_y % 2 == 0 else "03" + hex_x

        hashed_upk = hash160(uncompressed_public_key)
        hashed_cpk = hash160(compressed_public_key)

        return hashed_upk, hashed_cpk


# --- TESTING --- #
if __name__ == "__main__":
    w = Wallet()
    print(w.private_key)
    print(w.public_key_point)
    print(w.h_upk)
    print(w.h_cpk)
