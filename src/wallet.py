"""
A class for BitClone wallets
"""
# --- IMPORTS --- #
from hashlib import sha256
from secrets import randbits

from ripemd.ripemd160 import ripemd160

from src.cryptography import SECP256K1
from word_list import WORDLIST


def hash160(my_string: str):
    return ripemd160(sha256(my_string.encode()).hexdigest().encode()).hex().upper()


class Wallet:
    BIT_LENGTH = 256

    def __init__(self):
        self.curve = SECP256K1()
        self.private_key = randbits(self.BIT_LENGTH) % (self.curve.p - 1)
        self.public_key_point = self.curve.scalar_multiplication(
            n=self.private_key,
            pt=self.curve.g
        )
        self.h_upk, self.h_cpk = self.get_keys()

    def get_keys(self):
        """
        We assign the private key, the public key point and the compressed public key
        """
        _private_key = randbits(self.BIT_LENGTH)
        pk_point = self.curve.scalar_multiplication(_private_key, self.curve.g)
        pk_x, pk_y = pk_point
        hex_x = hex(pk_x)[2:]
        hex_y = hex(pk_y)[2:]

        uncompressed_public_key = "04" + hex_x + hex_y
        compressed_public_key = "02" + hex_x if pk_y % 2 == 0 else "03" + hex_x

        hashed_upk = hash160(uncompressed_public_key)
        hashed_cpk = hash160(compressed_public_key)

        return hashed_upk, hashed_cpk

    def get_recovery_code(self):
        """
        1) Create a random sequence of 128 to 256 bits
        2) Create a checksum of the random sequence
        """
        # 1 - Get entropy in bit format
        entropy = bin(randbits(self.BIT_LENGTH))[2:]
        while len(entropy) < self.BIT_LENGTH:
            entropy = "0" + entropy
        assert len(entropy) == self.BIT_LENGTH

        # 2 - Create a checksum of the entropy
        checksum = bin(int(sha256(entropy.encode()).hexdigest(), 16))[2:2 + self.BIT_LENGTH // 32]

        # 3 - Add checksum to entropy
        entropy += checksum
        print(f"ENTROPY + CHECKSUM: {entropy}")

        # 4 - Split entropy into 11-bit length segments
        number_of_words = len(entropy) // 11
        word_index = []
        for x in range(number_of_words):
            word_index.append(int(entropy[x * 11:(x + 1) * 11], 2))

        # 5 - Map each 11-bit value to a word from the list of 2048 words
        words = []
        for i in word_index:
            words.append(WORDLIST[i])

        # 6 - Recovery code is the sequence of words
        print("===== RECOVERY PHRASE =====")
        for w in words:
            print(w)
        print("===== ===== ===== ===== =====")
        return words


# --- TESTING --- #
if __name__ == "__main__":
    w = Wallet()
    # print(w.private_key)
    # print(w.public_key_point)
    # print(w.h_upk)
    # print(w.h_cpk)
    w.get_recovery_code()
