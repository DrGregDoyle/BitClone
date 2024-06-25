"""
A library file for public key encryption
"""
import binascii
import hmac
from hashlib import sha256, sha512
from secrets import randbits

from ripemd.ripemd160 import ripemd160

from src.cryptography import SECP256K1


def hash160(data: str) -> str:
    sha_data = sha256(data.encode()).hexdigest()
    return ripemd160(sha_data.encode()).hex()


def hmac512(key: str, data: str) -> str:
    byte_key = binascii.unhexlify(key)
    byte_data = binascii.unhexlify(data)
    return hmac.new(key=byte_key, msg=byte_data, digestmod=sha512).hexdigest()


def str2hex(ascii_string: str) -> str:
    hex_list = [hex(ord(ascii_string[i]))[2:] for i in range(len(ascii_string))]
    return "".join(hex_list)


def get_compressed_key(private_key: int | str):
    # Get integer value for private_key
    privkey = int(private_key, 16) if isinstance(private_key, str) else private_key

    # Get public key point
    curve = SECP256K1()
    x, y = curve.scalar_multiplication(privkey, curve.g)
    prefix = "02" if y % 2 == 0 else "03"
    hex_x = format(x, f"064x")
    return prefix + hex_x


def get_public_key_point(compressed_public_key: str):
    curve = SECP256K1()
    prefix = compressed_public_key[:2]
    hex_x = compressed_public_key[2:]
    x = int(hex_x, 16)
    y = curve.get_y_from_x(x)
    neg_y = (curve.p - y) % curve.p
    if prefix == "02":
        return (x, y) if y % 2 == 0 else (x, neg_y)
    else:
        return (x, y) if y % 2 == 1 else (x, neg_y)


class ExtendedPrivateKey:
    KEY_CHARS = 64
    INDEX_BYTES = 4

    def __init__(self, key: str, seed: str):
        # We use the key and data to create the extended private key
        self.xpriv = hmac512(key, seed)
        self.privkey = self.xpriv[:self.KEY_CHARS]
        self.chain_code = self.xpriv[self.KEY_CHARS:]
        self.pubkey = get_compressed_key(self.privkey)
        self.xpub = self.pubkey + self.chain_code

    def generate_xpriv(self, index: int):
        # Decide if hardened
        hardened = (index >= pow(2, 31))

        # Create seed: pub/privkey + index
        seed = self.privkey if hardened else self.pubkey
        seed += format(index, f"0{2 * self.INDEX_BYTES}x")

        # Return new xpriv
        return ExtendedPrivateKey(self.chain_code, seed)

    def generate_xpub(self, index: int):
        # Verify not hardened
        if index >= pow(2, 31):
            raise TypeError("Not allowed to generated hardened xpub")

        # Get hmac data
        seed = self.pubkey + format(index, f"0{2 * self.INDEX_BYTES}x")
        hmac_data = hmac512(self.chain_code, seed)
        pub_key_exp = hmac_data[:self.KEY_CHARS]
        child_cc = hmac_data[self.KEY_CHARS:]

        # Get new public key
        curve = SECP256K1()
        pt1 = get_public_key_point(self.pubkey)
        pt2 = curve.scalar_multiplication(int(pub_key_exp, 16), curve.g)
        new_pk_point = curve.add_points(pt1, pt2)
        new_cpk = g


class KeyLib:
    SEED_BYTES = 64
    SEED_BITS = SEED_BYTES * 8
    INITIAL_KEY = "Bitcoin Seed"

    def __init__(self, seed=None):
        # New Keys
        if seed is None:
            # New random seed
            self._seed = randbits(self.SEED_BITS)
        # Restore Keys
        else:
            self._seed = seed

        # Master Extended Private Key
        formatted_seed = format(self._seed, f"0{2 * self.SEED_BYTES}x")
        formatted_key = str2hex(self.INITIAL_KEY)
        self.master_xpriv = ExtendedPrivateKey(key=formatted_key, seed=formatted_seed)


# --- TESTING --- #
if __name__ == "__main__":
    kl1 = KeyLib()
    print(kl1.master_xpriv.xpriv)
