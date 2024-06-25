"""
A class for BitClone wallets


"""

# --- IMPORTS --- #
import logging
import secrets
import sys
from hashlib import sha256
from random import choice
from secrets import randbits

from ripemd.ripemd160 import ripemd160

from src.cryptography import SECP256K1
from src.encoder_lib import base58_check
from src.word_list import WORDLIST

# --- LOGGING --- #
log_level = logging.INFO
logger = logging.getLogger(__name__)
logger.setLevel(log_level)
handler = logging.StreamHandler(stream=sys.stdout)
logger.addHandler(handler)


# --- CLASSES --- #


class WalletFactory:

    def new_wallet(self):
        return Wallet()

    def recover_wallet(self, seed_words: list):
        # Recover wallet using seed phrase
        seed_strings = []
        for word in seed_words:
            temp_index = WORDLIST.index(word)
            binary_index = bin(temp_index)[2:]
            while len(binary_index) != 11:
                binary_index = "0" + binary_index
            seed_strings.append(binary_index)

        # Create entropy string
        entropy = ""
        for seed_string in seed_strings:
            entropy += seed_string

        # Verify entropy string
        assert len(entropy) == Wallet.BIT_LENGTH + (Wallet.BIT_LENGTH // 32)

        # Get checksum
        checksum = entropy[-Wallet.BIT_LENGTH // 32:]
        entropy = entropy[:-Wallet.BIT_LENGTH // 32]

        # Verify checksum
        try:
            assert bin(int(sha256(entropy.encode()).hexdigest(), 16))[2:2 + Wallet.BIT_LENGTH // 32] == checksum
        except AssertionError:
            logger.error(f"Given seed phrase {seed_words} does not have matching checksum")
            return None

        # Return Wallet
        seed = int(entropy, 2)
        return Wallet(seed=seed)


class Wallet:
    """
    When a Wallet is created:
        - Generate BIT_LENGTH seed value
        - Get private/public keys
        - Generate recovery phrase
    """
    BIT_LENGTH = 256
    SIGNATURE_BYTES = 32
    PUBLIC_KEY_BYTES = 32

    def __init__(self, seed=None):
        self.curve = SECP256K1()
        # New Wallet
        if seed is None:
            self._seed = randbits(self.BIT_LENGTH)  # New seed
        # Existing Wallet
        else:
            self._seed = seed

        self._private_key, self.pk_point = self.get_keys(self._seed)  # Get first keypair
        self.seed_phrase = self.get_recovery_code(self._seed)  # Get seed phrase

    @property
    def compressed_public_key(self):
        # 33 bytes
        x, y = self.pk_point
        prefix = "02" if y % 2 == 0 else "03"
        return prefix + format(x, f"0{2 * self.PUBLIC_KEY_BYTES}x")

    @property
    def public_key(self):
        # 65 bytes
        x, y = self.pk_point
        hex_x = format(x, f"0{2 * self.PUBLIC_KEY_BYTES}x")
        hex_y = format(y, f"0{2 * self.PUBLIC_KEY_BYTES}x")
        return "04" + hex_x + hex_y

    def legacy_address(self, prefix="00"):
        """
        We return a base58 address of the compressed public key. The prefix corresponds to the type of locking script
        used.
        """
        match prefix:
            case "05":
                base58_prefix = "3"
            case "80":
                base58_prefix = choice(["K", "L", "5"])
            case "0488ADE4":
                base58_prefix = "xprv"
            case "0488B21E":
                base58_prefix = "xpub"
            case _:
                base58_prefix = "1"

        base58_cpk = base58_check(self.hash160(self.compressed_public_key))
        return base58_prefix + base58_cpk

    @staticmethod
    def hash160(data: str):
        return ripemd160(sha256(data.encode()).hexdigest().encode()).hex()

    def get_keys(self, seed: int):
        """
        We assign the private key and the public key point.
        """
        _private_key = int(sha256(hex(seed).encode()).hexdigest()[2:], 16)
        pk_point = self.curve.scalar_multiplication(_private_key, self.curve.g)

        return _private_key, pk_point

    def get_recovery_code(self, seed: int):
        """
        We use the seed value to generate a 256-bit length binary value for the entropy. We then add on the first
        8-bits of the corresponding sha256 hash of the entropy. Call this the checksum. Our entropy bit length is now
        divisible by 11. We break up the entropy into 11-bit binary strings and use this integer value as the index
        of the corresponding word in the word list. The 24 words make up the recovery phrase.
        """
        # 1 - Get entropy in bit format
        entropy = bin(seed)[2:]
        while len(entropy) < self.BIT_LENGTH:
            entropy = "0" + entropy
        assert len(entropy) == self.BIT_LENGTH

        # 2 - Create a checksum of the entropy
        checksum = bin(int(sha256(entropy.encode()).hexdigest(), 16))[2:2 + self.BIT_LENGTH // 32]

        # 3 - Add checksum to entropy
        entropy += checksum

        # 4 - Split entropy into 11-bit length segments
        number_of_words = len(entropy) // 11
        word_index = []
        for x in range(number_of_words):
            word_index.append(int(entropy[x * 11:(x + 1) * 11], 2))

        # 5 - Map each 11-bit value to a word from the list of 2048 words
        words = []
        for i in word_index:
            words.append(WORDLIST[i])

        # 6 - Recovery code is the sequence of words
        logger.debug("===== RECOVERY PHRASE =====")
        for w in words:
            logger.debug(w)
        logger.debug("===== ===== ===== ===== =====")
        return words

    def sign_transaction(self, tx_id: str):
        """
        Using the private key associated with the wallet, we follow the ECDSA to sign the transaction id.

        Algorithm:
        =========
        Let E denote the elliptic curve of the wallet and let n denote the group order. As we
        are using the SECP256K1 curve, we know that n is prime. (This is a necessary condition for the ECDSA.) We
        emphasize that n IS NOT necessarily equal to the characteristic p of F_p. Let t denote the private_key.

        1) Let Z denote the integer value of the first n BITS of the transaction hash.
        2) Select a cryptographically secure random integer k in [1, n-1]. As n is prime, k will be invertible.
        3) Calculate the curve point (x,y) =  k * generator
        4) Compute r = x (mod n) and s = k^(-1)(Z + r * t) (mod n). If either r or s = 0, repeat from step 2.
        5) The signature is the pair (r, s), formatted to hex_r + hex_s.
        """
        # Assign known variables
        n = self.curve.order
        r = 0
        s = 0

        # 1 - Let Z denote the first n bits of the tx_id
        Z = int(format(int(tx_id, 16), "b")[:n], 2)

        while r == 0 or s == 0:
            # 2 - Select a cryptographically secure random integer k in [1,n-1]
            k = secrets.randbelow(n - 1)

            # 3 - Calculate k * generator
            point = self.curve.scalar_multiplication(k, self.curve.g)
            (x, y) = point

            # 4 - Compute r and s. If either r or s = 0 repeat from step 3
            r = x % n
            s = (pow(k, -1, n) * (Z + r * self._private_key)) % n

        # 5 - Return formatted signature
        hex_r = format(r, f"0{2 * self.SIGNATURE_BYTES}x")
        hex_s = format(s, f"0{2 * self.SIGNATURE_BYTES}x")
        return hex_r + hex_s

    def verify_signature(self, signature: str, tx_id: str, public_key: tuple) -> bool:
        """
        Given a signature pair (r,s), an encoded message tx_id and a public key point (x,y), we verify the
        signature.

        Algorithm
        --------
        Let n denote the group order of the elliptic curve wrt the Wallet.

        1) Verify (r,s) are integers in the interval [1,n-1]
        2) Let Z be the integer value of the first n BITS of the transaction hash
        3) Let u1 = Z * s^(-1) (mod n) and u2 = r * s^(-1) (mod n)
        4) Calculate the curve point (x,y) = (u1 * generator) + (u2 * public_key)
            (where * is scalar multiplication, and + is rational point addition mod p)
        5) If r = x (mod n), the signature is valid.
        """
        # Decode signature
        hex_r = signature[:2 * self.SIGNATURE_BYTES]
        hex_s = signature[2 * self.SIGNATURE_BYTES:]
        r = int(hex_r, 16)
        s = int(hex_s, 16)

        # Assign known variables
        n = self.curve.order

        # 1 - Verify (r,s)
        try:
            assert 1 <= r <= n - 1
            assert 1 <= s <= n - 1
        except AssertionError:
            logger.error("Signature does not meet group order requirements.")
            return False

        # 2 - Let Z be the first n bits of tx_id
        Z = int(format(int(tx_id, 16), "b")[:n], 2)

        # 3 - Calculate u1 and u2
        s_inv = pow(s, -1, n)
        u1 = (Z * s_inv) % n
        u2 = (r * s_inv) % n

        # 4 - Calculate the curve point
        point1 = self.curve.scalar_multiplication(u1, self.curve.g)
        point2 = self.curve.scalar_multiplication(u2, public_key)
        curve_point = self.curve.add_points(point1, point2)

        # 5 - Return True/False based on r = x (mod n)
        if curve_point is None:
            return False
        x, _ = curve_point
        return r == x % n


# --- TESTING --- #
if __name__ == "__main__":
    w = Wallet()
    address = w.legacy_address()
    print(f"ADDRESS: {address}")
    print(f"CHARS: {len(address)}")
