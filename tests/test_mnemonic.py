"""
Tests for the Mnemonic class
"""
from src.wallet import Mnemonic

KNOWN_MNEMONIC = ['nature', 'bike', 'manual', 'ensure', 'audit', 'special', 'upon', 'pole', 'donate', 'mean', 'simple',
                  'dolphin', 'siren', 'panel', 'twice', 'atom', 'caught', 'stereo', 'shed', 'leave', 'behave', 'kit',
                  'canal', 'rack']
KNOWN_SEED = \
    "3a6d4603e997d4335795e2cfce9d62697157d462d02be4d14b3a86a94f7ee290f23c30b8563b8b4bde1498cdfd11f3b9e8a31783ff740e8eaaa5df794b7624e4"


def test_seed_phrase():
    """
    Given a known phrase, we create a Mnemonic object and verify we get the same seed
    """
    known_mnemonic = Mnemonic(KNOWN_MNEMONIC)
    assert known_mnemonic.to_seed() == bytes.fromhex(KNOWN_SEED), "Failed to generate known seed from known phrase"


def test_validate_mnemonic():
    random_mnemonic = Mnemonic()
    assert random_mnemonic.validate_phrase(), "Failed to validate phrase for random Mnemonic"
