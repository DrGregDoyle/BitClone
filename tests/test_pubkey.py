"""
We test the serialization methods for the PubKey class
"""
from secrets import token_bytes

from src.cryptography import PubKey


def test_pubkey():
    # Pubkey 1 is random coordinates
    random_pubkey1 = PubKey(int.from_bytes(token_bytes(64), "big"))

    # Pubkey 2 has even y coordinate
    random_pubkey2 = PubKey(int.from_bytes(token_bytes(64), "big"), is_even_y=True)

    # Test Pubkey1
    pk1_serial = PubKey.from_bytes(random_pubkey1.serial_pubkey())
    pk1_compressed = PubKey.from_bytes(random_pubkey1.serial_compressed())

    assert pk1_serial == random_pubkey1, "Deserialization of uncompressed pubkey failed"
    assert pk1_compressed == random_pubkey1, "Deserialization of compressed pubkey failed"

    # Test Pubkey2
    pk2_serial = PubKey.from_bytes(random_pubkey2.serial_pubkey())
    pk2_compressed = PubKey.from_bytes(random_pubkey2.serial_compressed())
    pk2_xonly = PubKey.from_bytes(random_pubkey2.serial_xonly())

    assert pk2_serial == random_pubkey2, "Deserialization of uncompressed pubkey failed"
    assert pk2_compressed == random_pubkey2, "Deserialization of compressed pubkey failed"
    assert pk2_xonly == random_pubkey2, "Deserialization of xonly pubkey failed"
