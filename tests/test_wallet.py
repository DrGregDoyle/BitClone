"""
Tests for the HD Wallet
"""
from src.wallet import Mnemonic, XPrv, HDWallet

# -- CONSTANTS
KNOWN_MNEMONIC_WORDS = ["thrive", "quiz", "thing", "kit", "umbrella", "shock", "elevator", "expire", "century",
                        "ketchup", "ill", "salute", "winter", "amused", "crop", "stairs", "spend", "submit", "below",
                        "color", "cook", "concert", "lamp", "photo"]
KNOWN_MNEMONIC_SEED = "2863db68a179a677e62fff17a314b059699304a655960b05aebc165d0d39a9da2870cc9f4fd17b3a21b61e26e2b9c92af1d57f9492ba8060a680a5e436032213"
KNOWN_MASTER_XPRV = "xprv9s21ZrQH143K28RxcoLzcGPLThWByQvbzD77yf5hJHyqf8aokDPKDvEE9LjCusKnrMHac7qaajjFJyR5JUfwCSL83UbscdXADeT2tmwYzTU"
KNOWN_MASTER_COMPRESSED_KEY = "03915cbd8ed37dcffe3bd8422c4b9b9e13d11ab329e358ff853e0ff9eec216241c"
KNOWN_BIP44_FIRST_ADDRESS = "xprvA3zNYxvoY5w8GgouWVwpyjHiy1XuyydVWs9ghyqHNfctPFFYDT8ScmwTz8h2WHEisKQZtdmn8L6NAAaT9WJyXR79YVCWNaMvHzXRqPVAPrX"
KNOWN_BIP49_FIRST_ADDRESS = "xprvA2qiFxeuFdKvNATut9ZfsyR5YY9bpupmF9HgtrvnLPcpP4Sioh9FiEc2HTPQBM22YWZpksYMntg2L9dioy4iaEjErSVwYhJZk4AoHKqNpb7"
KNOWN_BIP84_FIRST_ADDRESS = "xprvA3Mrm5MRYo2b6P7D3e9FBWiKmJsFagXKtKjkcVBeaXPJxfwLzYW265uLKUiJzaytXDFhYJUvAiqTom1qvpbkp44pjfezXhwRmpNHEE958vx"
KNOWN_BIP86_FIRST_ADDRESS = "xprvA4DGAeBQJi1jPdXsSVYMAQhMdasVDWPCTMEJWDCPsarGaXGxhjjeBAKU2un5iHTfjBeNpRoxgBbnaFs6dzp31e4iY2HhUyvWdUXFFo4PZ3e"


def test_mnemonic():
    """
    Various tests to verify the mnemonic function
    """
    # Create known mnemonic
    created_mnemonic_obj = Mnemonic(KNOWN_MNEMONIC_WORDS)

    # Verify seed
    assert created_mnemonic_obj.mnemonic_to_seed().hex() == KNOWN_MNEMONIC_SEED, \
        "Known mnemonic word list didn't generate expected mnemonic seed"

    # Validate known mnemonic
    assert created_mnemonic_obj.validate_mnemonic(), "Mnemonic created from know word list fails to validate"

    # Create random mnemonic and validate it
    random_mnemonic = Mnemonic()
    assert random_mnemonic.validate_mnemonic(), "Randomly created mnemonic fails to validate"


def test_xprv_fromclass_methods():
    """
    We verify the two class methods used to create an XPrv obj.
    """
    known_mnemonic = Mnemonic(KNOWN_MNEMONIC_WORDS)
    xprv1 = XPrv.from_mnemonic(known_mnemonic)

    xprv2 = XPrv.from_master_seed(seed=bytes.fromhex(KNOWN_MNEMONIC_SEED))

    # Verify both xprv1 and xprv2 are the same
    assert xprv1.address() == xprv2.address(), "Class methods failed to create Xprv with same address"

    # Verify that the address matches expected address
    assert xprv1.address() == KNOWN_MASTER_XPRV, \
        f"Created Xprv address {xprv1.address()} doesn't match expected address {KNOWN_MASTER_XPRV}"

    # Verify that the compressed public key from xprv matches expected value
    assert xprv1.compressed_pubkey().hex() == KNOWN_MASTER_COMPRESSED_KEY


def test_xprv_child_derivation():
    """
    We verify that the derived children for specific paths match known results
    """
    bip44_path = "m/44'/0'/0'/0/0"
    bip49_path = "m/49'/0'/0'/0/0"
    bip84_path = "m/84'/0'/0'/0/0"
    bip86_path = "m/86'/0'/0'/0/0"

    test_wallet = HDWallet(mnemonic=Mnemonic(KNOWN_MNEMONIC_WORDS))

    # Verify masterkey
    assert test_wallet.master_xprv.address() == KNOWN_MASTER_XPRV, \
        "Master_XPrv address in HDWallet doesn't match known address."

    # Verify derivation
    # BIP44
    bip44_derived_xprv = test_wallet.derive_key(path=bip44_path)
    assert bip44_derived_xprv.address() == KNOWN_BIP44_FIRST_ADDRESS, \
        f"Key address from derived path {bip44_path} doesn't match known address"

    # BIP49
    bip49_derived_xprv = test_wallet.derive_key(path=bip49_path)
    assert bip49_derived_xprv.address() == KNOWN_BIP49_FIRST_ADDRESS, \
        f"Key address from derived path {bip49_path} doesn't match known address"

    # BIP84
    bip84_derived_xprv = test_wallet.derive_key(path=bip84_path)
    assert bip84_derived_xprv.address() == KNOWN_BIP84_FIRST_ADDRESS, \
        f"Key address from derived path {bip84_path} doesn't match known address"

    # BIP86
    bip86_derived_xprv = test_wallet.derive_key(path=bip86_path)
    assert bip86_derived_xprv.address() == KNOWN_BIP86_FIRST_ADDRESS, \
        f"Key address from derived path {bip86_path} doesn't match known address"
