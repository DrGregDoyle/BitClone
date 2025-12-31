"""
The Wallet class - ties together Mnemonic and ExtendedKey for HD wallet functionality
"""
from src.core.formats import XKEYS
from src.wallet.mnemonic import Mnemonic
from src.wallet.xkeys import ExtendedKey

__all__ = ["Wallet"]
_X = XKEYS()


class Wallet:
    """
    Hierarchical Deterministic Wallet implementing BIP32/BIP39/BIP44
    """
    __slots__ = ('mnemonic', 'seed', 'master_key')

    def __init__(
            self,
            phrase: list | None = None,
            passphrase: str = "",
            entropy_bytelen: int = 16,
            version: bytes = _X.BIP44_XPRV
    ):
        """
        Initialize a wallet from a mnemonic phrase or generate a new one

        Args:
            phrase: Optional mnemonic phrase (12 or 24 words). If None, generates random phrase
            passphrase: Optional BIP39 passphrase for seed derivation (default: "")
            entropy_bytelen: Entropy byte length for random mnemonic generation (default: 16 = 12 words)
            version: Extended key version bytes (default: BIP44_XPRV for mainnet)
        """
        # Create or validate mnemonic
        self.mnemonic = Mnemonic(phrase=phrase, entropy_bytelen=entropy_bytelen)

        # Derive seed from mnemonic
        _seed = self.mnemonic.to_seed(passphrase=passphrase)

        # Generate master extended private key from seed
        self.master_key = ExtendedKey.from_master_seed(_seed, version=version)

    @classmethod
    def from_seed(cls, seed: bytes, version: bytes = _X.BIP44_XPRV):
        """
        Create a wallet directly from a seed (bypasses mnemonic)

        Args:
            seed: Raw seed bytes (typically 64 bytes)
            version: Extended key version bytes

        Returns:
            Wallet instance with master_key set, mnemonic=None
        """
        wallet = cls.__new__(cls)
        wallet.mnemonic = None
        wallet.seed = seed
        wallet.master_key = ExtendedKey.from_master_seed(seed, version=version)
        return wallet

    def derive_path(self, path: str) -> ExtendedKey:
        """
        Derive a key at the given BIP32 path

        Args:
            path: Derivation path (e.g., "m/44'/0'/0'/0/0")

        Returns:
            ExtendedKey at the specified path
        """
        if not path.startswith('m'):
            raise ValueError("Path must start with 'm'")

        # Start from master key
        key = self.master_key

        # Parse and apply each level
        parts = path.split('/')[1:]  # Skip 'm'
        for part in parts:
            if not part:
                continue

            # Check for hardened derivation
            if part.endswith("'") or part.endswith("h"):
                index = int(part[:-1]) + 0x80000000  # Hardened offset
            else:
                index = int(part)

            key = key.derive_child(index)

        return key

    def get_master_pubkey(self) -> ExtendedKey:
        """
        Get the master public key (xpub)

        Returns:
            ExtendedKey public key
        """
        return self.master_key.get_pubkey()

    def to_dict(self) -> dict:
        """
        Export wallet information as dictionary

        Returns:
            Dictionary with mnemonic, seed, and master key info
        """
        return {
            "mnemonic": self.mnemonic.phrase if self.mnemonic else None,
            "master_xprv": self.master_key.address(),
            "master_xpub": self.get_master_pubkey().address(),
        }


# --- TESTING --- #
if __name__ == "__main__":
    print("=== Testing Wallet Creation ===\n")

    # Test 1: Create wallet with known phrase
    test_phrase = ["shine", "fly", "above", "velvet", "identify", "glance",
                   "practice", "deposit", "rule", "upset", "entry", "flag"]
    wallet1 = Wallet(phrase=test_phrase, passphrase="thispartisoptional")

    print("Wallet from known phrase:")
    print(f"Mnemonic: {wallet1.mnemonic.phrase}")
    print(f"Seed: {wallet1.seed.hex()}")
    print(f"Master xprv: {wallet1.master_key.address()}")
    print(f"Master xpub: {wallet1.get_master_pubkey().address()}")
    print()

    # Test 2: Create random wallet
    wallet2 = Wallet()  # Random 12-word mnemonic

    print("Random wallet:")
    print(f"Mnemonic: {wallet2.mnemonic.phrase}")
    print(f"Master xprv: {wallet2.master_key.address()}")
    print()

    # Test 3: Derive child keys
    print("=== Testing Key Derivation ===\n")

    # Standard BIP44 path: m/44'/0'/0'/0/0
    child_key = wallet1.derive_path("m/44'/0'/0'/0/0")
    print(f"Derived key at m/44'/0'/0'/0/0:")
    print(f"Address: {child_key.address()}")
    print()

    # Test 4: From seed
    print("=== Testing Wallet from Seed ===\n")
    wallet3 = Wallet.from_seed(wallet1.seed)
    print(f"Master keys match: {wallet3.master_key == wallet1.master_key}")
    print()

    # Test 5: Export
    print("=== Wallet Export ===\n")
    import json

    print(json.dumps(wallet1.to_dict(), indent=2))
