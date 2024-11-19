"""
A class for BitClone wallets
"""

# --- IMPORTS --- #
from secrets import randbits

from src.backup.library.ecc import SECP256K1

from src.backup.library.hash_func import hmac512, pbkdf2, sha_256
from src.library.word_list import WORDLIST


# --- CLASSES --- #

class ExtendedPrivateKey:
    """
    All keys are displayed as hex strings.
    """
    KEY_CHAR = 64
    INDEX_CHAR = 8
    HARDENED_INDEX = pow(2, 31)

    def __init__(self, xpriv: str):
        self.priv = xpriv[:self.KEY_CHAR]
        self.cc = xpriv[self.KEY_CHAR:]
        self.pub = self.get_pub(self.priv)
        self.child_priv = {}
        self.child_pub = {}
        self.index = 0
        self.h_index = self.HARDENED_INDEX
        self.pub_index = 0

    @property
    def xpriv(self):
        return self.priv + self.cc

    @property
    def xpub(self):
        return self.pub + self.cc

    def get_pub(self, priv: str):
        pk_pt = SECP256K1().generator(int(priv, 16))
        return self.compress_point(pk_pt)

    def compress_point(self, point: tuple):
        return ("02" if point[1] % 2 == 0 else "03") + format(point[0], f"0{self.KEY_CHAR}x")

    def get_pt(self, pub: str):
        # Get integer values
        parity, hex_x = pub[:2], pub[2:]
        x = int(hex_x, 16)
        parity = int(parity, 16) % 2

        # Get y values
        curve = SECP256K1()
        _y = curve.get_y_from_x(x)
        y_neg = (curve.p - _y) % curve.p

        # Find y
        y = _y if _y % 2 == parity else y_neg

        # Check point
        if not curve.is_point_on_curve((x, y)):
            raise ValueError(f"Calculated point is not on curve: {(x, y)}")

        return x, y

    def _extended_private_key(self, index: int):
        # Get hmac
        data = self.pub if index < self.HARDENED_INDEX else self.priv
        data += format(index, f"0{self.INDEX_CHAR}x")
        key = self.cc
        hmac_val = hmac512(key, data)

        # Add values
        c_priv = format((int(self.priv, 16) + int(hmac_val[:self.KEY_CHAR], 16)) % SECP256K1.ORDER,
                        f"0{self.KEY_CHAR}x")

        # Return xpriv
        c_cc = hmac_val[self.KEY_CHAR:]
        return c_priv + c_cc

    def _extended_public_key(self, index: int):
        # Get hmac
        data = self.pub + format(index, f"0{self.INDEX_CHAR}x")
        key = self.cc
        hmac_val = hmac512(key, data)

        # Point operations
        curve = SECP256K1()
        pt1 = curve.generator(int(hmac_val[:self.KEY_CHAR], 16))
        pt2 = self.get_pt(self.pub)
        c_pub = self.compress_point(
            curve.add_points(pt1, pt2)
        )

        # Return xpub
        c_cc = hmac_val[self.KEY_CHAR:]
        return c_pub + c_cc

    def new_private_child(self, hardened=True):
        # Get current index
        func_index = self.h_index if hardened else self.index

        # Get xpriv
        c_xpriv = self._extended_private_key(func_index)

        # Update children dict
        self.child_priv.update({func_index: c_xpriv})

        # Updated index
        if hardened:
            self.h_index += 1
        else:
            self.index += 1

    def new_public_child(self):
        # Get xpub
        c_xpub = self._extended_public_key(self.pub_index)

        # Updated children dict
        self.child_pub.update({self.pub_index: c_xpub})

        # Updated index
        self.pub_index += 1

    def get_private_child(self, index):
        return self.child_priv.get(index)

    def get_public_child(self, index):
        return self.child_pub.get(index)


class HDWallet:
    # -- Formatting constants
    BIT_SIZE = 256
    CHAR_SIZE = BIT_SIZE // 4
    BYTE_SIZE = BIT_SIZE // 8
    HARDENED_INDEX = pow(2, 31)
    PRIV_CHAR = 64
    PUB_CHAR = 66
    # -- Elliptic curve
    CURVE = SECP256K1()

    def __init__(self, seed_phrase=None):
        # Seed phrase
        seed_phrase = seed_phrase if seed_phrase else self.get_seed_phrase()
        if not self.check_seed_phrase(seed_phrase):
            raise TypeError(f"Seed phrase {seed_phrase} did not pass checksum.")

        self.seed_phrase = seed_phrase

        # Master Extended private key
        _mxpriv = self.master_extended_private_key(seed_phrase)

        # -- Wallet structure
        # Purpose
        _mxpriv.new_private_child()
        _xpriv_purpose = ExtendedPrivateKey(_mxpriv.get_private_child(index=self.HARDENED_INDEX))

        # Coin Type
        _xpriv_purpose.new_private_child()
        _xpriv_cointype = ExtendedPrivateKey(_xpriv_purpose.get_private_child(index=self.HARDENED_INDEX))

        # Account
        _xpriv_cointype.new_private_child()
        _xpriv_account = ExtendedPrivateKey(_xpriv_cointype.get_private_child(index=self.HARDENED_INDEX))

        # Receiving
        _xpriv_account.new_private_child(hardened=False)
        _xpriv_receiving = ExtendedPrivateKey(_xpriv_account.get_private_child(index=0))

        # Change
        _xpriv_account.new_private_child(hardened=False)
        _xpriv_change = ExtendedPrivateKey(_xpriv_account.get_private_child(index=1))

        self.keys = {
            "master": _mxpriv.xpriv,
            "purpose": _xpriv_purpose.xpriv,
            "coin_type": _xpriv_cointype.xpriv,
            "account": _xpriv_account.xpriv,
            "receiving": _xpriv_receiving.xpriv,
            "change": _xpriv_change.xpriv
        }

    # --- SEED PHRASE --- #

    def get_seed_phrase(self, bit_size=BIT_SIZE) -> list:
        # Checksum
        entropy = format(randbits(bit_size), f"0{bit_size}b")
        binary_hash = format(int(sha_256(entropy), 16), f"0{bit_size}b")
        entropy += binary_hash[:len(entropy) // 32]

        # 11-bit word list
        binary_word_list = [entropy[11 * x: 11 * (x + 1)] for x in range(len(entropy) // 11)]
        num_indices = [int(word, 2) for word in binary_word_list]
        word_list = [WORDLIST[n] for n in num_indices]
        return word_list

    def check_seed_phrase(self, mnemonic: list, bit_size=BIT_SIZE):
        # Get binary strings
        index_list = [WORDLIST.index(m) for m in mnemonic]
        binary_word_list = [format(i, "011b") for i in index_list]
        binary_string = "".join([w for w in binary_word_list])

        # Find checksum
        bit_length = len(binary_string) % 32
        checksum = binary_string[-bit_length:]

        # Hash entropy
        entropy = binary_string[:-bit_length]
        binary_hash = format(int(sha_256(entropy), 16), f"0{bit_size}b")

        # Return True/False
        return checksum == binary_hash[:len(entropy) // 32]

    def master_extended_private_key(self, seed_phrase: list, salt=None) -> ExtendedPrivateKey:
        """
        Given a seed (as hex string), we generate the master extended key (mxpriv)
        """
        # salt
        salt = "mnemonic" + salt if salt else "mnemonic"

        # seed
        seed_phrase_string = "".join(seed_phrase)
        _seed = pbkdf2(salt, seed_phrase_string)

        # Fixed key for mxpriv is "Bitcoin seed"
        seed_string = "Bitcoin seed"
        key_hex = "".join([format(ord(seed_string[c]), "02x") for c in range(len(seed_string))])
        mxpriv = ExtendedPrivateKey(hmac512(key=key_hex, data=_seed))
        return mxpriv

    # def sign_transaction(self, tx_id: str, private_key: int):
    #     """
    #     Using the private key associated with the wallet, we follow the ECDSA to sign the transaction id.
    #
    #     Algorithm:
    #     =========
    #     Let E denote the elliptic curve of the wallet and let n denote the group order. As we
    #     are using the SECP256K1 curve, we know that n is prime. (This is a necessary condition for the ECDSA.) We
    #     emphasize that n IS NOT necessarily equal to the characteristic p of F_p. Let t denote the private_key.
    #
    #     1) Let Z denote the integer value of the first n BITS of the transaction hash.
    #     2) Select a cryptographically secure random integer k in [1, n-1]. As n is prime, k will be invertible.
    #     3) Calculate the curve point (x,y) =  k * generator
    #     4) Compute r = x (mod n) and s = k^(-1)(Z + r * t) (mod n). If either r or s = 0, repeat from step 2.
    #     5) The signature is the pair (r, s), formatted to hex_r + hex_s.
    #     """
    #     # Assign known variables
    #     n = self.CURVE.order
    #     r = 0
    #     s = 0
    #
    #     # 1 - Let Z denote the first n bits of the tx_id
    #     Z = int(format(int(tx_id, 16), "b")[:n], 2)
    #
    #     while r == 0 or s == 0:
    #         # 2 - Select a cryptographically secure random integer k in [1,n-1]
    #         k = randbelow(n - 1)
    #
    #         # 3 - Calculate k * generator
    #         point = self.CURVE.scalar_multiplication(k, self.CURVE.g)
    #         (x, y) = point
    #
    #         # 4 - Compute r and s. If either r or s = 0 repeat from step 3
    #         r = x % n
    #         s = (pow(k, -1, n) * (Z + r * private_key)) % n
    #
    #     # 5 - Return formatted signature
    #     hex_r = format(r, f"0{self.CHAR_SIZE}x")
    #     hex_s = format(s, f"0{self.CHAR_SIZE}x")
    #     return hex_r + hex_s
    #
    # def verify_signature(self, signature: str, tx_id: str, public_key: tuple) -> bool:
    #     """
    #     Given a signature pair (r,s), an encoded message tx_id and a public key point (x,y), we verify the
    #     signature.
    #
    #     Algorithm
    #     --------
    #     Let n denote the group order of the elliptic curve wrt the Wallet.
    #
    #     1) Verify (r,s) are integers in the interval [1,n-1]
    #     2) Let Z be the integer value of the first n BITS of the transaction hash
    #     3) Let u1 = Z * s^(-1) (mod n) and u2 = r * s^(-1) (mod n)
    #     4) Calculate the curve point (x,y) = (u1 * generator) + (u2 * public_key)
    #         (where * is scalar multiplication, and + is rational point addition mod p)
    #     5) If r = x (mod n), the signature is valid.
    #     """
    #     # Decode signature
    #     hex_r = signature[:self.CHAR_SIZE]
    #     hex_s = signature[self.CHAR_SIZE:]
    #     r = int(hex_r, 16)
    #     s = int(hex_s, 16)
    #
    #     # Assign known variables
    #     n = self.CURVE.order
    #
    #     # 1 - Verify (r,s)
    #     try:
    #         assert 1 <= r <= n - 1
    #         assert 1 <= s <= n - 1
    #     except AssertionError:
    #         return False
    #
    #     # 2 - Let Z be the first n bits of tx_id
    #     Z = int(format(int(tx_id, 16), "b")[:n], 2)
    #
    #     # 3 - Calculate u1 and u2
    #     s_inv = pow(s, -1, n)
    #     u1 = (Z * s_inv) % n
    #     u2 = (r * s_inv) % n
    #
    #     # 4 - Calculate the curve point
    #     point1 = self.CURVE.generator(u1)
    #     point2 = self.CURVE.scalar_multiplication(u2, public_key)
    #     curve_point = self.CURVE.add_points(point1, point2)
    #
    #     # 5 - Return True/False based on r = x (mod n)
    #     if curve_point is None:
    #         return False
    #     x, _ = curve_point
    #     return r == x % n


class KeyPair:
    """
    A class for private and public keys
    """
    KEY_BYTES = 32
    curve = SECP256K1()

    def __init__(self, pk: int):
        self.private_key = pk % self.curve.order
        self.public_key = self.curve.generator(self.private_key)

    @property
    def compressed_public_key(self):
        x, y = self.public_key
        parity = "02" if y % 2 == 0 else "03"
        return parity + format(x, f"0{2 * self.KEY_BYTES}x")

    @property
    def uncompressed_public_key(self):
        x, y = self.public_key
        h_x = format(x, f"0{2 * self.KEY_BYTES}x")
        h_y = format(y, f"0{2 * self.KEY_BYTES}x")
        return "04" + h_x + h_y

    @property
    def pubkeyhash(self):
        return hash160(self.compressed_public_key)


class Wallet:
    INITIAL_KEY = "Bitcoin Seed"
    INITIAL_SALT = "mnemonic"
    KEY_LENGTH = 32  # Bytes

    def __init__(self, seed_phrase=None):
        """
        Wallet can be recovered with a seed phrase. Otherwise, it generates an initial KeyPair.
        """
        self.seed_phrase = seed_phrase if seed_phrase else self.new_seed_phrase()
        _seed_string = " ".join(self.seed_phrase)
        self._seed = pbkdf2(_seed_string, self.INITIAL_SALT)
        _priv_hex = hmac512(self.INITIAL_KEY, self._seed)
        self.keypair = KeyPair(int(_priv_hex, 16))

    @staticmethod
    def new_seed_phrase(bit_size=256):
        # Entropy | 256 bit binary string
        entropy = format(randbits(bit_size), f"0{bit_size}b")

        # Checksum | first 8 bits (1 byte) from SHA256(entropy)
        checksum = format(int(sha_256(entropy), 16), f"0{bit_size}b")[:bit_size // 32]

        # Get seed phrase
        binary_string = entropy + checksum
        seed_phrase = [WORDLIST[int(binary_string[x:x + 11], 2)] for x in range(0, bit_size + bit_size // 32, 11)]
        return seed_phrase

    @staticmethod
    def check_seed_phrase(seed_phrase: list, bit_size=256):
        # Get binary string from wordlist
        num_list = [WORDLIST.index(w) for w in seed_phrase]
        binary_string = "".join([format(n, "011b") for n in num_list])

        # Get entropy and verify checksum
        entropy, checksum = binary_string[:bit_size], binary_string[bit_size:]
        calculated_checksum = format(int(sha_256(entropy), 16), f"0{bit_size}b")[:bit_size // 32]
        return calculated_checksum == checksum

    @property
    def private_key(self):
        return self.keypair.private_key

    @property
    def public_key_point(self):
        return self.keypair.public_key

    @property
    def compressed_public_key(self):
        return self.keypair.compressed_public_key

    @property
    def pubkeyhash(self):
        return self.keypair.pubkeyhash


# --- TESTING
if __name__ == "__main__":
    w = HDWallet()
