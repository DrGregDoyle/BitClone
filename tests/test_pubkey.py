"""
We test the serialization methods for the PubKey class
"""
from secrets import token_bytes

from src.data.ecc_keys import PubKey


def test_pubkey_recovery():
    """
    We have the following class methods:
        -from uncompressed
        -from compressed
        -from point
    We will verify that we can recover a pubkey using all 3 methods
    """
    random_privkey = int.from_bytes(token_bytes(32), "big")
    random_pubkey = PubKey(random_privkey)

    # From uncompressed
    unc_pubkey = random_pubkey.uncompressed()
    from_uncompressed = PubKey.from_uncompressed(unc_pubkey)
    assert from_uncompressed == random_pubkey, "Failed to reconstruct Pubkey from uncompressed"

    # From compressed
    comp_pubkey = random_pubkey.compressed()
    from_compressed = PubKey.from_compressed(comp_pubkey)
    assert from_compressed == random_pubkey, "Failed to reconstruct Pubkey from compressed"

    # From point
    pk_pt = random_pubkey.to_point()
    from_point = PubKey.from_point(pk_pt)
    assert from_point == random_pubkey, "Failed to reconstruct PUbkey from point"
