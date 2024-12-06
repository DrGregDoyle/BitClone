"""
Tests for the mnemonic seed phrase
"""
from src.logger import get_logger
from src.wallet import generate_entropy, get_entropy_checksum, get_mnemonic, verify_mnemonic, mnemonic_to_seed

logger = get_logger(__name__)

KNOWN_MNEMONIC = ['nature', 'bike', 'manual', 'ensure', 'audit', 'special', 'upon', 'pole', 'donate', 'mean', 'simple',
                  'dolphin', 'siren', 'panel', 'twice', 'atom', 'caught', 'stereo', 'shed', 'leave', 'behave', 'kit',
                  'canal', 'rack']
KNOWN_SEED = "3a6d4603e997d4335795e2cfce9d62697157d462d02be4d14b3a86a94f7ee290f23c30b8563b8b4bde1498cdfd11f3b9e8a31783ff740e8eaaa5df794b7624e4"


def test_mnemonic_phrase():
    # Get random mnemonic
    entropy = generate_entropy()
    checksum = get_entropy_checksum(entropy)
    mnemonic = get_mnemonic(entropy + checksum)

    # Verify mnemonic yields correct checksum
    assert verify_mnemonic(mnemonic), f"Mnemonic failed to confirm checksum"


def test_mnemonic_seed_recovery():
    assert mnemonic_to_seed(
        KNOWN_MNEMONIC) == KNOWN_SEED, "PBKDF2 hash failed to generate KNOWN_SEED from KNOWN_MNEMONIC"
