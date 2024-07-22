"""
Wallet and Addresses
"""
from secrets import randbits

from src.library.ecc import SECP256K1
from src.library.hash_func import pbkdf2, hmac512, sha_256
from src.library.word_list import WORDLIST


class KeyPair:
    """
    A class for private and public keys
    """
    KEY_BYTES = 32
    curve = SECP256K1()

    def __init__(self, pk: int):
        self.private_key = pk % self.curve.order
        self.public_key = self.curve.generator(self.private_key)

    @property
    def compressed_public_key(self):
        x, y = self.public_key
        parity = "02" if y % 2 == 0 else "03"
        return parity + format(x, f"0{2 * self.KEY_BYTES}x")

    @property
    def uncompressed_public_key(self):
        x, y = self.public_key
        h_x = format(x, f"0{2 * self.KEY_BYTES}x")
        h_y = format(y, f"0{2 * self.KEY_BYTES}x")
        return "04" + h_x + h_y


class Wallet:
    INITIAL_KEY = "Bitcoin Seed"
    INITIAL_SALT = "mnemonic"
    KEY_LENGTH = 32  # Bytes

    def __init__(self, seed_phrase=None):
        """
        Wallet can be recovered with a seed phrase. Otherwise, it generates an initial KeyPair.
        """
        self.seed_phrase = seed_phrase if seed_phrase else self.new_seed_phrase()
        _seed_string = " ".join(self.seed_phrase)
        self._seed = pbkdf2(_seed_string, self.INITIAL_SALT)
        _priv_hex = hmac512(self.INITIAL_KEY, self._seed)
        self.keypair = KeyPair(int(_priv_hex, 16))

    @staticmethod
    def new_seed_phrase(bit_size=256):
        # Entropy | 256 bit binary string
        entropy = format(randbits(bit_size), f"0{bit_size}b")

        # Checksum | first 8 bits (1 byte) from SHA256(entropy)
        checksum = format(int(sha_256(entropy), 16), f"0{bit_size}b")[:bit_size // 32]

        # Get seed phrase
        binary_string = entropy + checksum
        seed_phrase = [WORDLIST[int(binary_string[x:x + 11], 2)] for x in range(0, bit_size + bit_size // 32, 11)]
        return seed_phrase

    @staticmethod
    def check_seed_phrase(seed_phrase: list, bit_size=256):
        # Get binary string from wordlist
        num_list = [WORDLIST.index(w) for w in seed_phrase]
        binary_string = "".join([format(n, "011b") for n in num_list])

        # Get entropy and verify checksum
        entropy, checksum = binary_string[:bit_size], binary_string[bit_size:]
        calculated_checksum = format(int(sha_256(entropy), 16), f"0{bit_size}b")[:bit_size // 32]
        return calculated_checksum == checksum

    @property
    def private_key(self):
        return self.keypair.private_key

    @property
    def public_key_point(self):
        return self.keypair.public_key

    @property
    def compressed_public_key(self):
        return self.keypair.compressed_public_key


# -- TESTING -- #

if __name__ == "__main__":
    _w = Wallet()
    print(format(_w.private_key, f"0256b"))
    print(format(_w.private_key, f"64x"))
    print(_w.public_key_point)
    print(_w.compressed_public_key)
