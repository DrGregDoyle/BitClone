"""
Tests for the mnemonic seed phrase
"""
from src.logger import get_logger
from src.wallet import Mnemonic

logger = get_logger(__name__)

KNOWN_MNEMONIC = ['nature', 'bike', 'manual', 'ensure', 'audit', 'special', 'upon', 'pole', 'donate', 'mean', 'simple',
                  'dolphin', 'siren', 'panel', 'twice', 'atom', 'caught', 'stereo', 'shed', 'leave', 'behave', 'kit',
                  'canal', 'rack']
KNOWN_SEED = "3a6d4603e997d4335795e2cfce9d62697157d462d02be4d14b3a86a94f7ee290f23c30b8563b8b4bde1498cdfd11f3b9e8a31783ff740e8eaaa5df794b7624e4"


def test_mnemonic_phrase():
    # Get random mnemonic
    random_mnemonic = Mnemonic()
    assert random_mnemonic.validate_mnemonic(), "Randomly generated mnemonic failed to validate"


def test_mnemonic_seed_recovery():
    _mnemonic = Mnemonic(mnemonic=KNOWN_MNEMONIC)
    assert _mnemonic.mnemonic_to_seed() == KNOWN_SEED, "PBKDF2 hash failed to generate KNOWN_SEED from KNOWN_MNEMONIC"
