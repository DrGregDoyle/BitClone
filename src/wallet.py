"""
A class for BitClone wallets


"""

# --- IMPORTS --- #
import logging
import secrets
import sys
from hashlib import sha256
from secrets import randbits

from primefac import isprime
from ripemd.ripemd160 import ripemd160

from src.cryptography import SECP256K1
from src.word_list import WORDLIST

# --- LOGGING --- #
log_level = logging.INFO
logger = logging.getLogger(__name__)
logger.setLevel(log_level)
handler = logging.StreamHandler(stream=sys.stdout)
logger.addHandler(handler)


# --- HELPERS --- #
def hash160(my_string: str):
    return ripemd160(sha256(my_string.encode()).hexdigest().encode()).hex().upper()


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

    def get_keys(self, seed: int):
        """
        We assign the private key, the public key point and the compressed public key
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
        ---------
        Let E denote the elliptic curve of the wallet and let n denote the group order.
        We emphasize that n IS NOT necessarily equal to the characteristic p of F_p.
        Let t denote the private_key.

        1) Verify that n is prime - the signature will not work if we do not have prime group order.
        2) Let Z denote the integer value of the first n BITS of the transaction hash.
        3) Select a cryptographically secure random integer k in [1, n-1]. As n is prime, k will be invertible.
        4) Calculate the curve point (x,y) =  k * generator
        5) Compute r = x (mod n) and s = k^(-1)(Z + r * t) (mod n). If either r or s = 0, repeat from step 3.
        6) The signature is the pair (r, s)
        """
        # 1 - Verify n (curve order) is prime
        n = self.curve.order
        curve_order_prime = isprime(n)
        if not curve_order_prime:
            logger.error(f"Given elliptic curve doesn't have prime group order, a necessary condition for the ECDSA.")
            return None

        # 2 - Let Z denote the first n bits of the tx_id
        tx_id_int = int(tx_id, 16)
        Z = format(tx_id_int, "b")[:n]
        Z = int(Z, 2)

        r = 0
        s = 0
        while r == 0 or s == 0:
            # 3 - Select a cryptographically secure random integer k in [1,n-1]
            k = secrets.randbelow(n - 1)

            # 4 - Calculate k * generator
            point = self.curve.scalar_multiplication(k, self.curve.g)
            (x, y) = point

            # 5 - Compute r and s. If either r or s = 0 repeat from step 3
            r = x % n
            s = (pow(k, -1, n) * (Z + r * self._private_key)) % n

        # 6 - Format r and s to each be 64 character hex strings (32 bytes)
        hex_r = format(r, f"0{2 * self.SIGNATURE_BYTES}x")
        hex_s = format(s, f"0{2 * self.SIGNATURE_BYTES}x")

        # 7 - Signature = hex_r + hex_s (64 bytes | 128 characters)
        return hex_r + hex_s

    def verify_signature(self, signature: str, tx_id: str, public_key: tuple) -> bool:
        """
        Given a signature pair (r,s), an encoded message tx_id and a public key point (x,y), we verify the
        signature.

        Algorithm
        --------
        Let n denote the group order of the elliptic curve wrt the Wallet.

        1) Verify that n is prime and that (r,s) are integers in the interval [1,n-1]
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

        # 1 - Verify n and (r,s)
        n = self.curve.order
        curve_order_prime = isprime(n)
        if not curve_order_prime:
            logger.error(f"Given elliptic curve doesn't have prime group order, a necessary condition for the ECDSA.")
            return False

        try:
            assert 1 <= r <= n - 1
            assert 1 <= s <= n - 1
        except AssertionError:
            logger.error("Signature does not meet group order requirements.")
            return False

        # 2 - Let Z be the first n bits of tx_id
        tx_id_int = int(tx_id, 16)
        Z = format(tx_id_int, "b")[:n]
        Z = int(Z, 2)

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
    tx_id = hash160("Hello world!")
    sig = w.sign_transaction(tx_id)
    print(f"SIGNATURE: {sig}")
    verified = w.verify_signature(signature=sig, tx_id=tx_id, public_key=w.pk_point)
    print(f"SIGNATURE VERIFIED: {verified}")
