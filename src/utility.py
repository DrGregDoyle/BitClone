"""
A module for various helper methods
"""
# --- IMPORTS --- #
import random
import string
from hashlib import sha256
from secrets import randbits

from ripemd.ripemd160 import ripemd160


# --- RANDOM VALUES --- #
def random_tx_id():
    return random_hash256()


def random_v_out():
    return random_integer(4)


def random_height():
    return random_integer(16)


def random_amount():
    return random_integer(8)


def random_bool():
    return random.choice([True, False])


# --- HELPERS --- #
def get_random_string(max_chars=64):
    """
    We return a random string with max chars
    """
    random_string = ""
    for x in range(max_chars):
        random_string += random.choice(string.ascii_letters)
    return random_string


def random_hash256(max_chars=64):
    random_string = get_random_string(max_chars)
    return hash256(random_string)


def random_hash160(max_chars=64):
    random_string = get_random_string(max_chars)
    return hash160(random_string)


def random_integer(byte_length=8):
    return randbits(8 * byte_length)


# --- HASH FUNCTIONS --- #
def hash160(hash_string: str):
    hash_256 = hash256(hash_string)
    return ripemd160(hash_256.encode()).hex()


def hash256(hash_string: str) -> str:
    return sha256(hash_string.encode()).hexdigest()
