"""
A module for various helper methods
"""
# --- IMPORTS --- #
import random
import string
from hashlib import sha256

from ripemd.ripemd160 import ripemd160


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


# --- HASH FUNCTIONS --- #
def hash160(hash_string: str):
    hash_256 = hash256(hash_string)
    return ripemd160(hash_256.encode()).hex()


def hash256(hash_string: str) -> str:
    return sha256(hash_string.encode()).hexdigest()
