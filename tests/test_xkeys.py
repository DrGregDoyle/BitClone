"""
Tests for extended keys
"""
from random import randint, choice
from secrets import token_bytes, randbelow

from src.core import XKEYS
from src.data.ecc_keys import PubKey
from src.wallet import ExtendedKey


def random_version():
    """
    We take a random version from the list of known versions for MAINNET
    """
    version_list = [
        XKEYS.BIP44_XPRV, XKEYS.BIP44_XPUB,
        XKEYS.BIP49_XPRV, XKEYS.BIP49_XPUB,
        XKEYS.BIP84_XPRV, XKEYS.BIP84_XPUB
    ]
    return choice(version_list)


def get_random_xkey(key_data: bytes, hardened: bool = False) -> ExtendedKey:
    chain_code = token_bytes(32)
    depth = randbelow(XKEYS.MAX_DEPTH)  # Max depth = 255
    parent_fingerprint = token_bytes(4)
    child_number = randbelow(XKEYS.HARDENED_OFFSET) if not hardened else randint(XKEYS.HARDENED_OFFSET + 1,
                                                                                 XKEYS.MAX_INDEX)
    version = random_version()
    return ExtendedKey(key_data, chain_code, depth, parent_fingerprint, child_number, version)


def get_random_xpub():
    random_privkey = int.from_bytes(token_bytes(32), "big")
    key_data = PubKey(random_privkey).compressed()
    return get_random_xkey(key_data, hardened=False)  # Cannot have hardened public keys


def get_random_xprv(hardened: bool = False):
    """
    We return a random XPRV key. The index will depend on the hardened boolean.
    """
    key_data = token_bytes(32)
    return get_random_xkey(key_data, hardened)


def test_xprv_recovery():
    """
    For a normal XPRV key, we verify recovery from serial and address
    """
    random_xprv = get_random_xprv(hardened=False)
    from_serial = ExtendedKey.from_serial(random_xprv.to_bytes())
    from_addy = ExtendedKey.from_address(random_xprv.address())

    # Verify
    assert from_serial == random_xprv, "Failed to reconstruct random XPRV from serial"
    assert from_addy == random_xprv, "Failed to reconstruct random XPRV from address"


def test_hardened_xprv_recovery():
    """
    For a hardened XPUB key, we verify recovery from serial and address
    """
    random_xprv = get_random_xprv(hardened=True)
    from_serial = ExtendedKey.from_serial(random_xprv.to_bytes())
    from_addy = ExtendedKey.from_address(random_xprv.address())

    # Verify
    assert from_serial == random_xprv, "Failed to reconstruct random hardened XPRV from serial"
    assert from_addy == random_xprv, "Failed to reconstruct random hardened XPRV from address"


def test_xpub_recovery():
    """
    For a normal XPUB key, we verify recovery from serial and address
    """
    random_xpub = get_random_xpub()
    from_serial = ExtendedKey.from_serial(random_xpub.to_bytes())
    from_addy = ExtendedKey.from_address(random_xpub.address())

    # Verify
    assert from_serial == random_xpub, "Failed to reconstruct random XPUB from serial"
    assert from_addy == random_xpub, "Failed to reconstruct random XPUB from address"
