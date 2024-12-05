"""
HD Wallet class
"""
from secrets import randbits

from src.library.hash_functions import sha256, pbkdf2
from src.library.word_list import WORDLIST
from src.logger import get_logger

logger = get_logger(__name__)

ENTROPY_BITLENGTH = 256
CHECKSUM_BITFACTOR = 32
CHECKSUM_LENGTH = ENTROPY_BITLENGTH // CHECKSUM_BITFACTOR


# def get_seed(bit_length: int = ENTROPY_BITLENGTH, entropy: str | None = None):
#     """
#     1) Get 256-bit random number and express it as a 256-character binary string. This is our entropy.
#     2) Get the first 8 bits of the SHA256 hash of step 1 and append it to the entropy. This is entropy + checksum and
#         will serve as the binary string corresponding to the mnemonic phrase.
#     3) Break up the binary string into 11-bit words and use the integer value as the index of the wordlist
#     4) Use the mnemonic sentence in the PBKDF2 function to get the seed.
#     """
#     # 1 - Get entropy as binary string
#     if entropy is not None and all((char in "01") for char in entropy):
#         entropy = entropy
#     else:
#         entropy = format(randbits(bit_length), f"0{bit_length}b")
#     logger.debug(f"ENTROPY: {entropy}")
#
#     # 2 - Get checksum and add to entropy
#     entropy_hash = sha256(bytes.fromhex(hex(int(entropy, 2))[2:]))
#     logger.debug(f"ENTROPY HASH: {entropy_hash.hex()}")
#     checksum_length = len(entropy) // 32
#     checksum = "".join(format(byte, "08b") for byte in entropy_hash)[:checksum_length]
#     logger.debug(f"CHECKSUM: {checksum}")
#     entropy_chk = entropy + checksum
#     logger.debug(f"ENTROPY + CHECKSUM: {entropy_chk}")
#
#     # 3 - Get word list
#     indices = [int(entropy_chk[i:i + 11], 2) for i in range(0, len(entropy_chk), 11)]  # Binary strings of length 11
#     words = [WORDLIST[i] for i in indices]
#     logger.debug(f"WORD LIST: {words}")
#
#     # 4 - Mnemonic to seed
#
#
# def get_mnemonic(entropy: int | str):


def generate_entropy(bit_length: int = ENTROPY_BITLENGTH) -> str:
    """
    We return a random binary string of the given bit length
    """
    random_num = randbits(bit_length)
    return format(random_num, f"0{bit_length}b")


def get_entropy_checksum(entropy: str) -> str:
    """
    We return the first len(entropy)//32 bits of the SHA25 hash of the byte value of the integer associated with entropy as a binary string
    """
    entropy_hash = sha256(bytes.fromhex(hex(int(entropy, 2))[2:]))
    checksum = "".join(format(byte, "08b") for byte in entropy_hash)[:len(entropy) // 32]
    return checksum


def mnemonic_to_binary_string(mnemonic: list):
    """
    Given a list of words, we return the corresponding binary string
    """
    ind_list = [WORDLIST.index(m) for m in mnemonic]
    binary_string = "".join(format(num, "011b") for num in ind_list)
    logger.debug(f"BINARY STRING: {binary_string}")
    logger.debug(f"BINARY STRING LENGTH: {len(binary_string)}")
    return binary_string


def verify_mnemonic(mnemonic: list):
    binary_mnemonic = mnemonic_to_binary_string(mnemonic)
    c_length = len(binary_mnemonic) // 33
    entropy = binary_mnemonic[:-c_length]
    checksum = binary_mnemonic[-c_length:]
    test_checksum = get_entropy_checksum(entropy)
    return test_checksum == checksum


def mnemonic_to_seed(mnemonic: list, passphrase: str = ""):
    seed_bytes = pbkdf2(mnemonic=mnemonic, passphrase=passphrase)  # Iterations = 2048, KeyLength = 64
    return seed_bytes.hex()


if __name__ == "__main__":
    # test_entropy = "1000000010100001011011010011101001010101111100011010111010001100011011011101101101100011101110010100001111110101011000110011110010100011101111101110111000011001111110000100100001101101100010001101001000111000111001101011000001111011111010001011100011101111"
    # hex_entropy = hex(int(test_entropy, 2))
    # get_seed(bit_length=256, entropy=test_entropy)
    # print(f"HEX ENTROPY: {hex_entropy}")
    test_mnemonic = ["street", "valley", "exotic", "gun", "print", "harsh", "about", "depart", "guitar", "guide",
                     "twelve", "that"]
    mnemonic_to_binary_string(test_mnemonic)
    print(f"MNEMONIC VERIFIED: {verify_mnemonic(mnemonic=test_mnemonic)}")
