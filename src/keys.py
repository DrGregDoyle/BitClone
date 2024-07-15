"""
Classes for public and private keys
"""
from secrets import randbits

from src.library.ecc import SECP256K1
from src.library.hash_func import sha_256, hash256
from src.library.word_list import WORDLIST


class PrivateKey:
    KEY_SIZE = 32  # 32 byte keys

    def __init__(self, private_key: int | str):
        self.pk_int = private_key if isinstance(private_key, int) else int(private_key, 16)
        self.private_key = private_key.to_bytes(length=self.KEY_SIZE, byteorder="big").hex()
        self.public_key = PublicKey(SECP256K1().generator(self.pk_int))

    def __repr__(self):
        return format(self.pk_int, f"0{2 * self.KEY_SIZE}x")

    @property
    def public_key_point(self):
        return self.public_key.x, self.public_key.y

    @property
    def compressed_public_key(self):
        return self.public_key.compressed


class PublicKey:
    KEY_SIZE = 32

    def __init__(self, pubkey_point: tuple):
        self.x, self.y = pubkey_point
        self.hex_x = self.x.to_bytes(length=self.KEY_SIZE, byteorder="big").hex()
        self.hex_y = self.y.to_bytes(length=self.KEY_SIZE, byteorder="big").hex()

    @property
    def compressed(self):
        parity = "02" if self.y % 2 == 0 else "03"
        return parity + self.hex_x

    @property
    def uncompressed(self):
        return "04" + self.hex_x + self.hex_y


class SimpleWallet:

    def __init__(self, seed=None, seed_phrase=None):
        # Seed = None
        if seed is None:
            # New wallet
            if seed_phrase is None:
                self.seed_phrase, self.seed = self.new_seed_phrase()
            # Seed phrase
            else:
                self.seed_phrase = seed_phrase
                self.seed = self.get_seed_from_phrase(self.seed_phrase)
        # Get phrase from seed
        else:
            self.seed = seed
            self.seed_phrase = self.get_phrase_from_seed(self.seed)

        # Get Keys
        _seed_hex = format(self.seed, "x")
        self.private_key = PrivateKey(int(hash256(_seed_hex), 16))
        self.public_key = self.private_key.public_key  # PublicKey

    def new_seed_phrase(self, bit_size=256):
        # Checksum
        seed = format(randbits(bit_size), f"0{bit_size}b")
        binary_hash = format(int(sha_256(seed), 16), f"0{bit_size}b")
        seed += binary_hash[:len(seed) // 32]

        word_list = self.get_phrase_from_seed(int(seed, 2))
        return word_list, int(seed, 2)

    def get_phrase_from_seed(self, seed: int | str, bit_size=256):
        # Get seed as integer value, then binary string of bit_size length
        seed = int(seed, 16) if isinstance(self, str) else seed
        binary_seed = format(seed, f"0{bit_size + bit_size // 32}b")

        # 11-bit word list
        binary_word_list = [binary_seed[11 * x: 11 * (x + 1)] for x in range(len(binary_seed) // 11)]
        num_indices = [int(word, 2) for word in binary_word_list]
        word_list = [WORDLIST[n] for n in num_indices]
        return word_list

    def get_seed_from_phrase(self, seed_phrase: list):
        # Get binary strings
        index_list = [WORDLIST.index(m) for m in seed_phrase]
        binary_word_list = [format(i, "011b") for i in index_list]
        binary_string = "".join([w for w in binary_word_list])

        # Return integer
        return int(binary_string, 2)


# --- TESTING
if __name__ == "__main__":
    w = SimpleWallet()
    print(f"SEED: {w.seed}")
    print(w.seed_phrase)
    print(w.get_phrase_from_seed(w.seed))
    s1 = w.get_seed_from_phrase(w.seed_phrase)
    print(f"RECOVERED SEED: {s1}")
    print(f"PRIVATE KEY: {w.private_key}")
