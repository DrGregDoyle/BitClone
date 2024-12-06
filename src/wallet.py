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


def get_mnemonic(seed_material: str) -> list:
    """
    seed_material = entropy + checksum (as binary strings)
    """
    index_list = [int(seed_material[x:x + 11], 2) for x in range(0, len(seed_material), 11)]
    return [WORDLIST[i] for i in index_list]


def mnemonic_to_binary_string(mnemonic: list):
    """
    Given a list of words, we return the corresponding binary string
    """
    ind_list = [WORDLIST.index(m) for m in mnemonic]
    binary_string = "".join(format(num, "011b") for num in ind_list)
    return binary_string


def verify_mnemonic(mnemonic: list) -> bool:
    binary = mnemonic_to_binary_string(mnemonic)
    checksum_length = len(binary) // 33
    entropy, checksum = binary[:-checksum_length], binary[-checksum_length:]
    return checksum == get_entropy_checksum(entropy)


def mnemonic_to_seed(mnemonic: list, passphrase: str = ""):
    seed_bytes = pbkdf2(mnemonic=mnemonic, passphrase=passphrase)  # Iterations = 2048, KeyLength = 64
    return seed_bytes.hex()


if __name__ == "__main__":
    _e1 = generate_entropy()
    _c1 = get_entropy_checksum(_e1)
    _m1 = get_mnemonic(_e1 + _c1)
    print(f"MNEMONIC: {_m1}")
    # test_mnemonic = ["street", "valley", "exotic", "gun", "print", "harsh", "about", "depart", "guitar", "guide",
    #                  "twelve", "that"]
    # mnemonic_to_binary_string(test_mnemonic)
    print(f"MNEMONIC VERIFIED: {verify_mnemonic(mnemonic=_m1)}")
    print(f"SEED FROM MNEMONIC: {mnemonic_to_seed(mnemonic=_m1)}")
