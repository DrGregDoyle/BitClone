"""
HD Wallet
"""

# --- IMPORTS

from secrets import randbits

from src.library.hash_functions import sha256, pbkdf2
from src.library.word_list import WORDLIST
from src.logger import get_logger

logger = get_logger(__name__)


class Mnemonic:
    """
    A class for storing the mnemonic phrase used to generate the seed from which all extended keys are derived.
    """
    DEFAULT_ENTROPY_BIT_LENGTH = 256

    def __init__(self, mnemonic: list | None = None, entropy: bytes | str | None = None,
                 entropy_bit_length: int = DEFAULT_ENTROPY_BIT_LENGTH):

        # Check to see if a mnemonic is given
        if mnemonic is not None:
            if not self.validate_mnemonic(mnemonic):
                raise ValueError("Given mnemonic words do not pass validation")
            self.mnemonic = mnemonic

        # Generate new mnemonic otherwise
        else:
            # Check for entropy
            if entropy is not None:
                _entropy = self.parse_entropy(entropy, entropy_bit_length)
            # Generate random one
            else:
                _entropy = format(randbits(entropy_bit_length), f"0{entropy_bit_length}b")

            # Get checksum
            _checksum = self.get_entropy_checksum(_entropy)

            # Get mnemonic
            _seed_materials = _entropy + _checksum
            self.mnemonic = self.get_mnemonic_words(_seed_materials)

    @staticmethod
    def parse_entropy(input_entropy: bytes | str, entropy_bit_length: int):
        entropy_num = None
        # Handle bytes
        if isinstance(input_entropy, bytes):
            entropy_num = int.from_bytes(input_entropy, byteorder="big")
        # Handle strings
        elif isinstance(input_entropy, str):
            # Hex
            if all(c in "0123456789abcdefABCDEF" for c in input_entropy):
                entropy_num = int(input_entropy, 16)
            # Binary
            elif all(c in "01" for c in input_entropy):
                entropy_num = int(input_entropy, 2)
            # Error
            else:
                raise ValueError("Inputted entropy not the correct datatype")
        return format(entropy_num, f"0{entropy_bit_length}b")

    @staticmethod
    def get_entropy_checksum(entropy):
        # Get entropy length
        bit_length = len(entropy) // 32

        # Hash entropy first
        entropy_hash = sha256(int(entropy, 2).to_bytes(len(entropy) // 8, byteorder="big"))

        # Get entropy_hash as binary string
        binary_entropy_hash = format(int.from_bytes(entropy_hash, byteorder="big"), f"0{len(entropy)}b")

        # Return first bit_length bits from the binary hash
        return binary_entropy_hash[:bit_length]

    @staticmethod
    def get_mnemonic_words(seed_materials: str):
        # Seed materials should be a binary string, with length divisible by 11
        if len(seed_materials) % 11 != 0 or not all(c in "01" for c in seed_materials):
            raise ValueError(f"Seed materials incorrectly formatted")

        # Break up binary string into chunks of length 11
        binary_chunks = [seed_materials[i:i + 11] for i in range(0, len(seed_materials), 11)]

        # Use binary chunks to get index from WORDLIST
        return [WORDLIST[int(c, 2)] for c in binary_chunks]

    def validate_mnemonic(self, word_list: list | None = None) -> bool:
        # Use instance mnemonic if none given
        _mnemonic = self.mnemonic if word_list is None else word_list

        # Convert words in the mnemonic back in to bits
        index_list = [WORDLIST.index(w) for w in _mnemonic]
        binary_string = "".join([format(i, f"011b") for i in index_list])

        # Get entropy and checksum part
        checksum_length = len(binary_string) // 33
        _entropy, _checksum = binary_string[:-checksum_length], binary_string[-checksum_length:]

        # Compute expected checksum from entropy
        expected_checksum = self.get_entropy_checksum(_entropy)

        # Return True if both checksums are equal, false otherwise
        return expected_checksum == _checksum

    def mnemonic_to_seed(self, passphrase: str = "") -> bytes:
        seed_bytes = pbkdf2(mnemonic=self.mnemonic, passphrase=passphrase)
        return seed_bytes


# class MasterKey:
#     KEY = b"Bitcoin seed"
#     HALF_HMAC_HASH_LENGTH = 32  # Avoiding magic numbers
#     CURVE = secp256k1()
#
#     def __init__(self, mnemonic: Mnemonic | None = None, passphrase: str = ""):
#         # If no mnemonic exists create a random one
#         self.mnemonic = mnemonic if mnemonic is not None else Mnemonic()
#         _seed = self.mnemonic.mnemonic_to_seed(passphrase=passphrase)  # _seed is a bytes object
#         logger.debug(f"SEED GENERATED: {_seed.hex()}")
#
#         # Create hmac hash | bytes object
#         hmac_hash = hmac_sha512(key=self.KEY, message=_seed)
#
#         # Get master private key and master chain code
#         self.__master_private_key = hmac_hash[:self.HALF_HMAC_HASH_LENGTH]
#         self.__master_chain_code = hmac_hash[self.HALF_HMAC_HASH_LENGTH:]
#
#         # Get master public key
#         _public_key_pt = self.CURVE.multiply_generator(int.from_bytes(self.__master_private_key, byteorder="big"))
#         self.__master_public_key = compress_public_key(_public_key_pt)
#
#     def get_chain_code(self) -> bytes:
#         return self.__master_chain_code
#
#     def get_private_key(self) -> bytes:
#         return self.__master_private_key
#
#     def get_public_key(self) -> bytes:
#         return self.__master_public_key
#
#     def __repr__(self):
#         return f"<MasterKey: Chain Code={self.__master_chain_code.hex()[:8]}...>"


if __name__ == "__main__":
    m1 = Mnemonic()
    m2 = Mnemonic()
    k1 = MasterKey(mnemonic=m1)
    k2 = MasterKey(mnemonic=m2)
    print(f"PRIVATE KEY: {k1.get_private_key().hex()}")
    print(f"CHAIN  CODE: {k1.get_chain_code().hex()}")
    print(f"REPR: {k1}")
    print(f"PUBLIC KEY: {k1.get_public_key().hex()}")
