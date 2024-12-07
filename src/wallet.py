"""
HD Wallet

--
Explanation of classes goes here

"""

# --- IMPORTS
from secrets import randbits

from src.library.hash_functions import sha256, pbkdf2
from src.library.word_list import WORDLIST
from src.logger import get_logger

logger = get_logger(__name__)


class Mnemonic:
    """
    A class for generating and managing a BIP-39 compliant mnemonic phrase,
    which can be used to derive an extended master key (seed) for hierarchical
    deterministic wallets.

    This class supports three initialization paths:
    1. Using a known mnemonic phrase (`input_mnemonic`):
       - The mnemonic is verified against the BIP-39 checksum rules.
       - On success, the instance is initialized with that mnemonic.
    2. Using provided entropy (`input_entropy`) in bytes or string format:
       - Bytes are converted directly to a binary string of appropriate length.
       - Strings are interpreted as either binary or hexadecimal entropy.
       - The resulting entropy is validated and used to compute a checksum,
         then to generate a mnemonic if needed.
    3. Generating random entropy internally:
       - If neither `input_mnemonic` nor `input_entropy` is provided, random
         entropy of `entropy_bit_length` bits is generated via `randbits`.

    BIP-39 Entropy Lengths:
    The BIP-39 standard allows specific entropy sizes:
    {128, 160, 192, 224, 256} bits.

    Attributes:
        BIP39_ENTROPY_BIT_LENGTHS (set): Supported entropy lengths.
        CHECKSUM_RATIO (int): Ratio for determining checksum length (1 bit per 32 bits of entropy).
        entropy (str): Binary string representing the entropy.
        checksum (str): Binary string of the computed checksum bits.
        mnemonic (list): Optional. List of mnemonic words if initialized from a mnemonic.
    """

    BIP39_ENTROPY_BIT_LENGTHS = {128, 160, 192, 224, 256}
    BIP39_MNEMONIC_WORD_COUNTS = {12, 15, 18, 21, 24}
    CHECKSUM_RATIO = 32

    def __init__(self,
                 input_entropy: bytes | str | None = None,
                 input_mnemonic: list | None = None,
                 skip_entropy_validation: bool = False,
                 entropy_bit_length: int = 256):
        """
        Initialize the Mnemonic instance with either a mnemonic, entropy, or none.

        Args:
            input_entropy (bytes | str | None):
                The entropy source. If bytes, its length is converted into a binary string.
                If str, it may be binary ('0' and '1') or hexadecimal, validated by `parse_entropy`.
                If None, random entropy is generated using `entropy_bit_length`.
            input_mnemonic (list | None):
                A list of words forming a mnemonic phrase. If provided, this overrides
                the entropy path. The mnemonic is verified, and if invalid, raises ValueError.
            skip_entropy_validation (bool):
                If True, bypasses the standard BIP-39 entropy length validation.
                Useful for testing or non-standard scenarios.
            entropy_bit_length (int):
                Bit length of entropy if generated internally. Defaults to 256.
                Should be one of the supported BIP-39 sizes unless skipping validation.

        Raises:
            ValueError:
                - If `input_mnemonic` is invalid.
                - If `input_entropy` is of an unsupported format (not bytes, not binary/hex str).
                - If the resulting entropy length is not a BIP-39 standard size
                  and `skip_entropy_validation` is False.
        """

        # Validate entropy_bit_length unless testing
        if not skip_entropy_validation and entropy_bit_length not in self.BIP39_ENTROPY_BIT_LENGTHS:
            raise ValueError(f"Entropy length must be one of {self.BIP39_ENTROPY_BIT_LENGTHS} bits.")

        # If a mnemonic phrase is provided, verify it.
        if input_mnemonic is not None:
            mnemonic_is_valid = self.verify_mnemonic(input_mnemonic)
            if mnemonic_is_valid:
                self.mnemonic = input_mnemonic
            else:
                raise ValueError("Invalid mnemonic phrase.")

        # Otherwise, handle entropy-based initialization.
        elif input_entropy is not None:
            if isinstance(input_entropy, bytes):
                derived_bit_length = len(input_entropy) * 8  # Byte length to bit length
                self.entropy = format(int.from_bytes(input_entropy, byteorder="big"), f"0{derived_bit_length}b")
            elif isinstance(input_entropy, str):
                self.entropy = self.parse_entropy(input_entropy)
            else:
                raise ValueError("Entropy must be of type bytes, str, or None.")

        # No mnemonic or entropy provided - generate new entropy.
        # Use cryptographically secure secrets library
        else:
            self.entropy = format(randbits(entropy_bit_length), f"0{entropy_bit_length}b")

        # Validate the entropy length unless skipping is requested.
        if len(self.entropy) not in self.BIP39_ENTROPY_BIT_LENGTHS and not skip_entropy_validation:
            raise ValueError(f"Entropy length must be one of {self.BIP39_ENTROPY_BIT_LENGTHS} bits.")

        # Compute the checksum for this entropy.
        self.checksum = self.get_entropy_checksum(self.entropy)

    @staticmethod
    def parse_entropy(entropy: str) -> str:
        """
        Parse a string representing entropy into a binary string.

        The input string can be:
        - Binary (composed of '0' and '1'), or
        - Hexadecimal (composed of 0-9 and a-f/A-F).

        Args:
            entropy (str): Input entropy string.

        Returns:
            str: A binary string corresponding to the input entropy.

        Raises:
            ValueError: If the input string is not binary or hexadecimal.
        """
        if all(c in "01" for c in entropy):
            return entropy
        elif all(c in "0123456789abcdefABCDEF" for c in entropy):
            bit_length = len(entropy) * 4  # 1 hex char = 4 bits
            return format(int(entropy, 16), f"0{bit_length}b")
        raise ValueError("Invalid entropy string format.")

    @staticmethod
    def mnemonic_to_seed(mnemonic: list, passphrase: str = ""):
        """
        Convert a mnemonic phrase and optional passphrase into a seed.

        This function uses PBKDF2-HMAC-SHA512 with 2048 iterations and a key length of 64 bytes,
        as specified by BIP-39. The resulting seed is a hex-encoded string commonly used as the
        root seed to derive extended master keys for HD wallets.

        Args:
            mnemonic (list): The mnemonic words.
            passphrase (str): An optional passphrase that adds additional security to the seed.

        Returns:
            str: A hex-encoded seed derived from the mnemonic and passphrase.
        """
        return pbkdf2(mnemonic=mnemonic, passphrase=passphrase).hex()

    def verify_mnemonic(self, mnemonic: list, testing: bool = False) -> bool:
        """
        Verifies the validity of a mnemonic phrase.
        - Converts mnemonic words to binary representation.
        - Splits binary data into entropy and checksum.
        - Validates checksum.

        Args:
            mnemonic (list): List of mnemonic words.
            testing (bool): Use if using non-standard mnemonics

        Returns:
            bool: True if the mnemonic is valid, False otherwise.
        """
        # Verify mnemonic length
        if not testing and len(mnemonic) not in self.BIP39_MNEMONIC_WORD_COUNTS:
            return False

        # Get binary string corresponding to mnemonic word list
        index_list = [WORDLIST.index(w) for w in mnemonic]
        binary_data = "".join(format(i, "011b") for i in index_list)

        # For every 32 bits there is 1 checksum bit
        bit_length = len(binary_data) // (self.CHECKSUM_RATIO + 1)
        entropy, checksum = binary_data[:bit_length], binary_data[bit_length:]

        # Return true if get_entropy_checksum == checksum
        return self.get_entropy_checksum(entropy) == checksum

    def get_entropy_checksum(self, entropy: str) -> str:
        """
        Compute the BIP-39 checksum bits from the given entropy.

        This method:
        - Interprets the binary `entropy` string as a big-endian integer.
        - Computes its SHA-256 hash.
        - Extracts the first (len(entropy)//CHECKSUM_RATIO) bits of the SHA-256 hash
          to serve as the checksum.

        Args:
            entropy (str): A binary string representing the entropy.

        Returns:
            str: The binary string representing the truncated checksum bits derived from the SHA-256 hash.
        """
        entropy_bytes = int(entropy, 2).to_bytes(len(entropy) // 8, "big")
        entropy_hash = sha256(entropy_bytes)
        checksum_length = len(entropy) // self.CHECKSUM_RATIO
        return format(int.from_bytes(entropy_hash, "big"), f"0{len(entropy) // 8 * 8}b")[:checksum_length]

# --- METHODS


# from secrets import randbits
# from typing import Union
#
# from src.library.hash_functions import sha256, pbkdf2, hmac_sha512, hash160
# from src.library.word_list import WORDLIST
# from src.logger import get_logger
#
# logger = get_logger(__name__)
#
# ENTROPY_BITLENGTH = 256
# CHECKSUM_BITFACTOR = 32
# CHECKSUM_LENGTH = ENTROPY_BITLENGTH // CHECKSUM_BITFACTOR
#
#
# def generate_entropy(bit_length: int = ENTROPY_BITLENGTH) -> str:
#     """
#     We return a random binary string of the given bit length
#     """
#     random_num = randbits(bit_length)
#     return format(random_num, f"0{bit_length}b")
#
#

#
#
# def get_mnemonic(seed_material: str) -> list:
#     """
#     seed_material = entropy + checksum (as binary strings)
#     """
#     index_list = [int(seed_material[x:x + 11], 2) for x in range(0, len(seed_material), 11)]
#     return [WORDLIST[i] for i in index_list]
#
#
#
#
# def verify_mnemonic(mnemonic: list) -> bool:
#     binary = mnemonic_to_binary_string(mnemonic)
#     checksum_length = len(binary) // 33
#     entropy, checksum = binary[:-checksum_length], binary[-checksum_length:]
#     return checksum == get_entropy_checksum(entropy)
#
#

#
#
# def generate_master_xkey(seed_hex: str) -> dict:
#     """
#     Generates a master extended key for Bitcoin from a seed using HMAC-SHA512.
#
#     Args:
#         seed_hex (str): A hexadecimal string representing the seed.
#
#     Returns:
#         dict: A dictionary containing the master private key and chain code.
#     """
#     # Convert the seed from hex to bytes
#     seed = bytes.fromhex(seed_hex)
#
#     # Define the key for HMAC-SHA512 (as per BIP-32)
#     hmac_key = b"Bitcoin seed"
#
#     # Generate the HMAC-SHA512 hash of the seed
#     hmac_result = hmac_sha512(hmac_key, seed)
#
#     # Split the result into master private key (left 32 bytes) and chain code (right 32 bytes)
#     master_private_key = hmac_result[:32]
#     chain_code = hmac_result[32:]
#
#     return {
#         "master_private_key": master_private_key.hex(),
#         "chain_code": chain_code.hex()
#     }
#
#
# class ExtendedKey:
#     """
#     Base class for extended keys.
#     """
#
#     def __init__(self, key: bytes, chain_code: bytes, depth: int = 0, index: int = 0,
#                  parent_fingerprint: bytes = b'\x00\x00\x00\x00'):
#         self.key = key
#         self.chain_code = chain_code
#         self.depth = depth
#         self.index = index
#         self.parent_fingerprint = parent_fingerprint
#
#     def serialize(self, is_private: bool) -> str:
#         """
#         Serializes the extended key to base58 (not implemented here for simplicity).
#         """
#         # 0488ade4 = xprv | 0488b21e = xpub
#         version = bytes.fromhex("0488ade4") if is_private else bytes.fromhex("0488b21e")
#         raise NotImplementedError("Serialization to base58 not implemented.")
#
#
# class PrivateKey(ExtendedKey):
#     """
#     Represents an extended private key.
#     """
#
#     def __init__(self, private_key: bytes, chain_code: bytes, depth: int = 0, index: int = 0,
#                  parent_fingerprint: bytes = b'\x00\x00\x00\x00'):
#         super().__init__(private_key, chain_code, depth, index, parent_fingerprint)
#
#     def derive_child(self, index: int) -> "PrivateKey":
#         """
#         Derives a child private key using the given index.
#         """
#         if index >= 0x80000000:  # Hardened key
#             data = b'\x00' + self.key + index.to_bytes(4, 'big')
#         else:  # Non-hardened key
#             public_key = self.get_public_key()  # Derive the public key
#             data = public_key + index.to_bytes(4, 'big')
#         hmac_result = hmac_sha512(self.chain_code, data)
#         new_private_key = (int.from_bytes(hmac_result[:32], 'big') + int.from_bytes(self.key, 'big')) % (2 ** 256)
#         return PrivateKey(
#             new_private_key.to_bytes(32, 'big'),
#             hmac_result[32:],
#             depth=self.depth + 1,
#             index=index,
#             parent_fingerprint=self.fingerprint()
#         )
#
#     def get_public_key(self) -> bytes:
#         """
#         Derives the public key from the private key.
#         """
#         # This would require an elliptic curve library like `ecdsa` or `secp256k1`
#         raise NotImplementedError("Elliptic curve point multiplication not implemented.")
#
#     def fingerprint(self) -> bytes:
#         """
#         Computes the fingerprint of the public key.
#         """
#         public_key = self.get_public_key()
#         return hash160(public_key)[:4]
#
#
# class PublicKey(ExtendedKey):
#     """
#     Represents an extended public key.
#     """
#
#     def __init__(self, public_key: bytes, chain_code: bytes, depth: int = 0, index: int = 0,
#                  parent_fingerprint: bytes = b'\x00\x00\x00\x00'):
#         super().__init__(public_key, chain_code, depth, index, parent_fingerprint)
#
#     def derive_child(self, index: int) -> "PublicKey":
#         """
#         Derives a child public key using the given index (non-hardened only).
#         """
#         if index >= 0x80000000:
#             raise ValueError("Cannot derive hardened keys from public keys.")
#         data = self.key + index.to_bytes(4, 'big')
#         hmac_result = hmac_sha512(self.chain_code, data)
#         new_public_key = (int.from_bytes(hmac_result[:32], 'big') + int.from_bytes(self.key, 'big')) % (2 ** 256)
#         return PublicKey(
#             new_public_key.to_bytes(32, 'big'),
#             hmac_result[32:],
#             depth=self.depth + 1,
#             index=index,
#             parent_fingerprint=self.fingerprint()
#         )
#
#
# def parse_derivation_path(path: str) -> list:
#     """
#     Parses a derivation path into a list of indices.
#     """
#     if not path.startswith("m"):
#         raise ValueError("Invalid derivation path.")
#     indices = path.lstrip("m/").split("/")
#     result = []
#     for index in indices:
#         if index.endswith("'"):  # Hardened index
#             result.append(0x80000000 + int(index[:-1]))
#         else:
#             result.append(int(index))
#     return result
#
#
# def derive_from_path(master_key: PrivateKey, path: str) -> Union[PrivateKey, PublicKey]:
#     """
#     Derives a key (private or public) using a derivation path.
#     """
#     indices = parse_derivation_path(path)
#     key = master_key
#     for index in indices:
#         key = key.derive_child(index)
#     return key
#
#
# # # Example Usage
# # seed_hex = "000102030405060708090a0b0c0d0e0f"
# # master_key = generate_master_extended_key(seed_hex)
# # master_private_key = PrivateKey(bytes.fromhex(master_key["master_private_key"]), bytes.fromhex(master_key["chain_code"]))
# #
# # # Derive a child key
# # child_key = derive_from_path(master_private_key, "m/44'/0'/0'/0/0")
# # print("Child Private Key:", child_key.key.hex())
#
#
# if __name__ == "__main__":
#     # _e1 = generate_entropy()
#     # _c1 = get_entropy_checksum(_e1)
#     # _m1 = get_mnemonic(_e1 + _c1)
#     # print(f"MNEMONIC: {_m1}")
#     # # test_mnemonic = ["street", "valley", "exotic", "gun", "print", "harsh", "about", "depart", "guitar", "guide",
#     # #                  "twelve", "that"]
#     # # mnemonic_to_binary_string(test_mnemonic)
#     # print(f"MNEMONIC VERIFIED: {verify_mnemonic(mnemonic=_m1)}")
#     # print(f"SEED FROM MNEMONIC: {mnemonic_to_seed(mnemonic=_m1)}")
#     test_mnemonic = ["symptom", "fade", "whip", "country", "require", "trial", "mom", "review", "liberty", "winter",
#                      "between", "joke"]
#     test_seed = mnemonic_to_seed(test_mnemonic)
#     print(f"MASTER_XKEY: {generate_master_xkey(test_seed)}")
