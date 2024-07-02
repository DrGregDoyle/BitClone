"""
A library for common encoding functions
"""
# --- IMPORTS --- #
import hmac
from binascii import unhexlify
from hashlib import sha256, sha512, sha1
from math import ceil

from ripemd.ripemd160 import ripemd160


# --- HASH FUNCTIONS --- #

def op_sha1(data: str):
    return sha1(data.encode()).hexdigest()


def secure_hash_256(data: str):
    """
    Returns hex digest of SHA256(data)
    """
    return sha256(data.encode()).hexdigest()


def hash256(data: str) -> str:
    """
    Returns the hex digest of SHA256(SHA256(data)) - 32-bytes
    """
    return sha256(sha256(data.encode()).hexdigest().encode()).hexdigest()


def hash160(data: str) -> str:
    """
    Returns the hex digest of RIPEMD160(SHA256(data)) - 20-bytes
    """
    return ripemd160(sha256(data.encode()).hexdigest()).hexdigest()


def hmac512(key: str, data: str) -> str:
    """
    Returns the hex digest of the HMAC-SHA512(key, data) hash function - 64-bytes (we force 128-char length)
    """
    byte_key = unhexlify(key)  # HMAC takes byte values for key and data
    byte_data = unhexlify(data)
    return hmac.new(key=byte_key, msg=byte_data, digestmod=sha512).hexdigest().zfill(128)


def pbkdf2(key: str, data: str, iterations=2048):
    """
    For the PBKDF2, we assume the key and data are arbitrary strings. Hence we can byte-encode them using .encode().
    """
    byte_key = key.encode()
    message = data.encode()
    for _ in range(iterations):
        message = hmac.new(byte_key, message, sha512).hexdigest().encode()
    return message.decode()


# --- BASE 58 --- #
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_LIST = [x for x in BASE58_ALPHABET]


def base58_check(data: int | str, checksum=True):
    # Make sure data is in hex format
    if isinstance(data, int):
        data = format(data, "0x")

    # Checksum
    if checksum:
        _checksum = hash256(data)[:8]  # Take 4-bytes (8 chars) for checksum
        data += _checksum

    # Convert
    buffer = ""
    data_int = int(data, 16)
    while data_int > 0:
        r = data_int % 58
        buffer = BASE58_LIST[r] + buffer
        data_int = data_int // 58

    return buffer


def decode_base58_check(encoded_data: str, checksum=True):
    total = 0
    data_range = len(encoded_data)
    for x in range(data_range):
        total += BASE58_LIST.index(encoded_data[x:x + 1]) * pow(58, data_range - x - 1)
    if checksum:
        datacheck = format(total, "0x")
        data = datacheck[:-8]
        check = datacheck[-8:]
        assert sha256(data.encode()).hexdigest()[:8] == check
    else:
        data = format(total, "0x")
    return data


# --- BITS/TARGET --- #
def bits_to_target(bits: str) -> str:
    """
    Given an 4-byte (8 character) bits string, we return the 64-character hex string.
    """
    exp = bits[:2]
    coeff = bits[2:]

    trailing_zeros = "00" * (int(exp, 16) - len(coeff) // 2)
    target_int = int(coeff + trailing_zeros, 16)
    return format(target_int, f"064x")


def target_to_bits(hex_target: str):
    """
    Given a 64-character target string we return the corresponding exponent (bit shift) as 2-char hex string (1-byte)
    """
    # Find significant byte
    byte = 0
    while True:
        temp_bit = hex_target[byte:byte + 2]
        if temp_bit != "00":
            break
        byte += 2

    # Get coeff
    coeff = hex_target[byte:]

    # -- Formatting -- #
    exp = format(32 - byte // 2, "02x")
    coeff = coeff[:6]
    return exp + coeff


# --- GENERAL ENCODING --- #

BYTE_DICT = {
    "tx": 32,
    "v_out": 4,
    "height": 8,
    "amount": 8,
    "sequence": 4,
    "byte": 1,
    "version": 4,
    "locktime": 4,
    "hash": 32,
    "target": 64,
    "bits": 4,
    "time": 4,
    "nonce": 4
}

WEIGHT_UNIT_DICT = {
    "version": 4,
    "marker": 1,
    "flag": 1,
    "input": 4,
    "output": 4,
    "witness": 1,
    "locktime": 4
}


class EncodedNum:
    """
    A class for encoding integers as bytes. Can be either of big or little endianness or in variable length CompactSize.
    """

    def __init__(self, num: int, byte_size=None, encoding=None):
        # Get byte_size
        if byte_size is None:
            byte_size = ceil(num.bit_length() // 8)

        # Get num
        self.num = num

        # Get endianness, determine if CompactSize num
        self.little_endian, self.compact = self._get_encoding(encoding)

        # Handle Compact size
        if self.compact:
            self.value = self._encode_compact_size(num)
        else:
            # Not compact means endian specific encoding
            encoding = "little" if self.little_endian else "big"
            self.value = num.to_bytes(length=byte_size, byteorder=encoding, signed=False)

        # Hex display
        self.display = self.value.hex()

    def _get_encoding(self, encoding: str):
        match encoding:
            case "little":
                return True, False
            case "compact":
                return False, True
            case _:
                return False, False

    def _encode_compact_size(self, num: int):
        if 0 <= num <= 0xfc:
            return num.to_bytes(length=1, byteorder="little")
        elif 0xfd <= num <= 0xffff:
            b1 = 0xfd.to_bytes(length=1, byteorder="big")
            b2 = num.to_bytes(length=2, byteorder="little")
            return b1 + b2
        elif 0x10000 <= num <= 0xffffffff:
            b1 = 0xfe.to_bytes(length=1, byteorder="big")
            b2 = num.to_bytes(length=4, byteorder="little")
            return b1 + b2
        elif 0x100000000 <= num <= 0xffffffffffffffff:
            b1 = 0xff.to_bytes(length=1, byteorder="big")
            b2 = num.to_bytes(length=8, byteorder="little")
            return b1 + b2


# -- TESTING
if __name__ == "__main__":
    data = "Hello world"
    # val = secure_hash_256(data)
    # print(f"DIGEST: {val.digest()}")
    # print(f"DIGEST TYPE: {type(val.digest())}")
    # print(f"HEX DIGEST: {val.hexdigest()}")
    # print(f"TYPE HEX DIGEST: {type(val.hexdigest())}")
