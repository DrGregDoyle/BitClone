"""
A class for BitClone wallets

TODO:
    -Link recovery phrase seed to private key generation
    -Add recovery function 
"""
# --- IMPORTS --- #
from hashlib import sha256
from secrets import randbits

from ripemd.ripemd160 import ripemd160

from src.cryptography import SECP256K1
from src.word_list import WORDLIST


def hash160(my_string: str):
    return ripemd160(sha256(my_string.encode()).hexdigest().encode()).hex().upper()


class WalletFactory:

    def new_wallet(self):
        return Wallet()

    def recover_wallet(self, seed_words: list):
        # Recover wallet using seed phrase
        seed_strings = []
        for word in seed_words:
            temp_index = WORDLIST.index(word)
            binary_index = bin(temp_index)[2:]
            while len(binary_index) != 11:
                binary_index = "0" + binary_index
            seed_strings.append(binary_index)

        # Create entropy string
        entropy = ""
        for seed_string in seed_strings:
            entropy += seed_string

        # Verify entropy string
        assert len(entropy) == Wallet.BIT_LENGTH + (Wallet.BIT_LENGTH // 32)

        # Get checksum
        checksum = entropy[-Wallet.BIT_LENGTH // 32:]
        entropy = entropy[:-Wallet.BIT_LENGTH // 32]

        # Verify checksum
        assert bin(int(sha256(entropy.encode()).hexdigest(), 16))[2:2 + Wallet.BIT_LENGTH // 32] == checksum

        # Return seed
        return int(entropy, 2)


class Wallet:
    """
    When a Wallet is created:
        - Generate BIT_LENGTH seed value
        - Get private/public keys
        - Generate recovery phrase
    """
    BIT_LENGTH = 256

    def __init__(self, seed=None):
        self.curve = SECP256K1()
        # New Wallet
        if seed is None:
            self._seed = randbits(self.BIT_LENGTH)  # New seed
        # Existing Wallet
        else:
            self._seed = seed

        self._private_key, self.pk_point = self.get_keys(self._seed)  # Get first keypair
        self.seed_phrase = self.get_recovery_code(self._seed)  # Get seed phrase

    def get_keys(self, seed: int):
        """
        We assign the private key, the public key point and the compressed public key
        """
        _private_key = int(sha256(hex(seed).encode()).hexdigest()[2:], 16)
        pk_point = self.curve.scalar_multiplication(_private_key, self.curve.g)

        return _private_key, pk_point

    def get_recovery_code(self, seed: int):
        """
        We use the seed value to generate a 256-bit length binary value for the entropy. We then add on the first
        8-bits of the corresponding sha256 hash of the entropy. Call this the checksum. Our entropy bit length is now
        divisible by 11. We break up the entropy into 11-bit binary strings and use this integer value as the index
        of the corresponding word in the word list. The 24 words make up the recovery phrase.
        """
        # 1 - Get entropy in bit format
        entropy = bin(seed)[2:]
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
    print(f"WALLET SEED: {w._seed}")
    seed_phrase = w.seed_phrase

    wf = WalletFactory()
    recovered_seed = wf.recover_wallet(seed_words=seed_phrase)
    print(f"RECOVERED SEED: {recovered_seed}")
