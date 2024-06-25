"""
A library for private/public keys and their extension
"""

# --- IMPORTS --- #
import binascii
import hmac
from hashlib import sha256, sha512
from secrets import randbits

from ripemd.ripemd160 import ripemd160

from src.cryptography import SECP256K1


def hash160(data: str):
    sha_data = sha256(data.encode()).hexdigest()
    md_data = ripemd160(sha_data.encode()).hex()
    return md_data


def hmac512(key: str, data: str):
    """
    Given a hex key and an arbitrary message, we return the HMAC512 result
    """
    byte_key = binascii.unhexlify(key)
    message = binascii.unhexlify(data)
    return hmac.new(byte_key, message, sha512).hexdigest()


def get_public_key(private_key: int):
    """
    Given an integer we return the public key point
    """
    curve = SECP256K1()
    return curve.scalar_multiplication(private_key, curve.g)


def get_compressed_public_key(public_key: tuple):
    x, y = public_key
    prefix = "02" if y % 2 == 0 else "03"
    return prefix + format(x, f"0{64}x")


class KeyLib:
    """
    A library for extended keys.
    """
    SEED_BYTES = 64
    SEED_BIT_LENGTH = 512
    INITIAL_KEY_PHRASE = "Bitcoin seed"

    def __init__(self, seed=None):
        self._seed = seed if seed else randbits(self.SEED_BIT_LENGTH)
        ik_list = [format(ord(self.INITIAL_KEY_PHRASE[x]), "02x") for x in range(len(self.INITIAL_KEY_PHRASE))]
        initial_key = "".join(ik_list)
        self._mx_private_key = hmac512(initial_key, format(self._seed, f"0{2 * self.SEED_BYTES}x"))
        self._m_private_key = self._mx_private_key[:self.SEED_BYTES]
        self._chain_code = self._mx_private_key[self.SEED_BYTES:]
        self._m_public_key = get_compressed_public_key(get_public_key(int(self._m_private_key, 16)))
        self._mx_public_key = self._m_public_key + self._chain_code
        self.index = 0  # Start at master key level

        self.test_dict = {
            "seed": self._seed,
            "master_extended_private_key": self._mx_private_key,
            "chain_code": self._chain_code,
            "master_public_key": self._m_public_key,
            "master_extended_public_key": self._mx_public_key
        }

    def derive_extended_private_key(self, private_key=None, public_key=None, index=None):
        privkey = private_key if private_key else self._m_private_key
        pubkey = public_key if public_key else self._m_public_key
        i = index if index else self.index

        data = pubkey + format(i, "08x")  # 4 byte index
        hash_result = hmac512(key=self._chain_code, data=data)
        child_chain_code = hash_result[self.SEED_BYTES:]
        child_privkey_int = (int(privkey, 16) + int(hash_result[:self.SEED_BYTES], 16)) % SECP256K1().order
        child_privkey = format(child_privkey_int, f"0{self.SEED_BYTES}x")


# --- TESTING --- #
import json

if __name__ == "__main__":
    kl = KeyLib()
    print(json.dumps(kl.test_dict, indent=2))
