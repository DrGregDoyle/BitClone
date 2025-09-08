"""
The Mnemonic class - and object created for seed retrieval. Constructed using 12 or 24 words or blank for randomly
generated one
"""
import os

from src.core import WALLET, WalletError
from src.cryptography import sha256, pbkdf2
from src.data import load_wordlist

# --- CONSTANTS --- #
DEFAULT_ENTROPY_BYTELEN = WALLET.DEFAULT_ENTROPY_BYTES  # 16 bytes | 12 words
ALLOWED_ENTROPY_BYTELEN = WALLET.MNEMONIC.keys()
CHECKSUM_KEY = WALLET.CHECKSUM_KEY
WORD_KEY = WALLET.WORD_KEY
BITLEN_KEY = WALLET.BITLEN_KEY
WORD_BITS = WALLET.WORD_BITS


class Mnemonic:
    __slots__ = ("phrase",)

    def __init__(self, phrase: list | None = None, entropy_bytelen: int = DEFAULT_ENTROPY_BYTELEN):
        """
        We create a mnemonic phrase corresponding to a seed value. The number of words in the phrase corresponds to
        the entropy byte length (32 bytes = 12 words, 64 bytes = 24 words)
        """
        # --- BIP39 ENTROPY BYTE LENGTH VALIDATION --- #
        if entropy_bytelen not in ALLOWED_ENTROPY_BYTELEN:
            raise WalletError(
                f"Entropy byte length {entropy_bytelen} not BIP30 compliant. Must be one of {ALLOWED_ENTROPY_BYTELEN}")

        # --- GET PHRASE --- #

        # Validate phrase if given
        if phrase is not None:
            if not self.validate_phrase(phrase):
                print(f"Given phrase doesn't pass checksum validation: {phrase}")
                # raise WalletError(f"Given phrase doesn't pass checksum validation: {phrase}")
            self.phrase = phrase
        else:
            # Generate new phrase
            self.phrase = self._generate_phrase(entropy_bytelen)

    def _generate_phrase(self, entropy_bytelen: int) -> list[str]:
        """
        Generates phrase for randomly generated entropy of ta given byte length
        """
        _entropy = os.urandom(entropy_bytelen)
        return self._generate_phrase_fron_entropy(_entropy)

    def _generate_phrase_fron_entropy(self, entropy: bytes) -> list[str]:
        """
        Entropy assumed at this point to be of allowed byte len
        """
        # Get entropy and checksum as integers
        entropy_int = int.from_bytes(entropy, "big")
        checksum_int = self._get_checksum_from_entropy(entropy)

        # Get the checksum bit length from config (not from the actual value!)
        entropy_bytelen = len(entropy)
        checksum_bitlen = WALLET.MNEMONIC[entropy_bytelen][CHECKSUM_KEY]

        # Shift entropy_int by checksum_bitlen then OR the checksum_int to append it (as an integer)
        ent_check = (entropy_int << checksum_bitlen) | checksum_int

        # Get phrase
        entropy_bytelen = len(entropy)
        word_count = WALLET.MNEMONIC[entropy_bytelen][WORD_KEY]
        wordlist = load_wordlist()
        phrase = []
        for _ in range(word_count):
            # Extract 11-bit groups from right to left
            word_index = ent_check & ((1 << WORD_BITS) - 1)  # Get last 11 bits
            phrase.insert(0, wordlist[word_index])  # Insert at beginning
            ent_check >>= WORD_BITS  # Shift right by 11 bits

        # --- TESTING
        print("--- GENERATE PHRASE --- ")
        print("===" * 60)
        print(f"ENTROPY: {entropy.hex()}")
        print(f"ENTROPY INTEGER: {entropy_int}")
        print(f"CHECKSUM INTEGER: {checksum_int}")
        print(f"ENT CHECK: {ent_check}")
        print(f"PHRASE: {phrase}")

        return phrase

    def _get_checksum_from_entropy(self, entropy: bytes) -> int:
        """
        Return the integer associated with the checksum for the given entropy
        """
        # TESTING
        print(f"ENTROPY BEFORE CHECKSUM: {entropy.hex()}")
        # Get integer value of the hash
        entropy_hash = sha256(entropy)
        entropy_hash_int = int.from_bytes(entropy_hash, "big")

        # Calculate shift
        bytelen = len(entropy)
        shift = 256 - WALLET.MNEMONIC[bytelen][CHECKSUM_KEY]  # SHA256 generates 256 bit hash

        # Return first checksum_bits as int
        return entropy_hash_int >> shift  # Shift = entropy_bitlen - checksum_bitlen

    def validate_phrase(self, phrase: list | None = None) -> bool:
        """
        For a given mnemonic phrase, we validate the checksum according to BIP-39
        """
        # Use phrase instance var if phrase is None
        phrase = self.phrase if phrase is None else phrase

        # Find entropy_bytelen based on word_count
        word_count = len(phrase)
        _m = WALLET.MNEMONIC
        entropy_bytelen = next(
            (bytelen for bytelen in ALLOWED_ENTROPY_BYTELEN if _m.get(bytelen, {}).get(WORD_KEY) == word_count), None
        )

        if entropy_bytelen is None:
            return False

        # wordlist
        wordlist = load_wordlist()

        # Get configuration for this entropy length
        mnemonic_dict = WALLET.MNEMONIC.get(entropy_bytelen)
        checksum_bitlen = mnemonic_dict.get(CHECKSUM_KEY)
        entropy_bitlen = mnemonic_dict.get(BITLEN_KEY)

        # Convert phrase to combined integer
        ent_check = 0
        for word in phrase:
            try:
                word_index = wordlist.index(word)
            except ValueError:
                return False  # Word not in wordlist
            ent_check = (ent_check << WORD_BITS) | word_index  # | OR bitwise operation

        # Extract checksum and entropy
        checksum_mask = (1 << checksum_bitlen) - 1  # Creates mask with checksum_bitlen 1's
        checksum = ent_check & checksum_mask  # Extract rightmost checksum bits
        entropy = ent_check >> checksum_bitlen  # Shift right to get entropy bits

        # Get checksum from entropy
        calc_checksum = self._get_checksum_from_entropy(entropy.to_bytes(entropy_bytelen, "big"))

        # --- TESTING --- #
        print("--- VALIDATE PHRASE --- ")
        print("===" * 60)
        print(f"PHRASE: {phrase}")
        print(f"PHRASE INTEGER ENT_CHECK: {ent_check}")
        print(f"CHECKSUM FROM ENT_CHECK: {checksum}")
        print(f"ENTROPY FROM ENT_CHECK: {entropy}")
        print(f"CHECKSUM FROM ENTROPY: {calc_checksum}")

        return calc_checksum == checksum

    def to_seed(self, passphrase: str = "", iterations: int = WALLET.SEED_ITERATIONS,
                dklen: int = WALLET.DKLEN) -> bytes:
        """
        Returns seed value associated with mnemonic phrase of the object
        """
        return pbkdf2(mnemonic=self.phrase, passphrase=passphrase, iterations=iterations, dklen=dklen)


# --- TESTING ---
if __name__ == "__main__":
    byte_list = WALLET.MNEMONIC.keys()
    mnemonics = []
    byte_size = 16
    # for byte_size in byte_list:
    random_mnemonic = Mnemonic()  # 12 words by default
    print(f"RANDOM MNEMONIC: {random_mnemonic.phrase}")
    print(f"RANDOM SEED FROM MNEMONIC: {random_mnemonic.to_seed().hex()}")

    # recovered mnemonic
    recovered_mnemonic = Mnemonic(phrase=random_mnemonic.phrase)
    print(f"RECOVERED MNEMONIC: {recovered_mnemonic.phrase}")
    print(f"RECOVERED SEED FROM MNEMONIC: {recovered_mnemonic.to_seed().hex()}")
    print("===" * 80)

    # Verify
    print(f"TWO SEED VALUES EQUAL: {random_mnemonic.to_seed() == recovered_mnemonic.to_seed()}")
    print("---" * 80)

    print(f"VALIDATE MNEMONIC: {random_mnemonic.validate_phrase(random_mnemonic.phrase)}")
