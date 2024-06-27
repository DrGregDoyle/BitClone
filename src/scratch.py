"""
The HD Wallet class
"""
import json
from secrets import randbits

from encoder_lib import secure_hash_256, pbkdf2, hmac512
from src.cryptography import SECP256K1
from src.word_list import WORDLIST


class HDWallet:
    BIT_SIZE = 256
    KEY_LENGTH = BIT_SIZE // 4
    BIP_44 = "44'"
    BIP_49 = "49'"
    BIP_84 = "84'"
    HARDENED_INDEX = pow(2, 31)
    CURVE = SECP256K1()

    def __init__(self, seed_phrase=None):
        if seed_phrase is None:
            seed_phrase = self.get_seed_phrase()
        _mxpriv = self.master_extended_private_key(seed_phrase)
        _mxpub = self.get_extended_public_key(_mxpriv)
        _master_dict = {
            "xpriv": _mxpriv,
            "xpub": _mxpub
        }

        self.seed_phrase = seed_phrase

        # -- Setup Extended Keys
        # Purpose - hardened
        _xpurpose = self.derive_private_key(_mxpriv, index=self.HARDENED_INDEX)
        _purpose_dict = {"xpriv": _xpurpose, "index": self.HARDENED_INDEX}

        # Coin Type - hardened
        _xcointype = self.derive_private_key(_xpurpose, index=self.HARDENED_INDEX)
        _cointype_dict = {"xpriv": _xcointype, "index": self.HARDENED_INDEX}

        # Account - hardened
        _xaccount = self.derive_private_key(_xcointype, index=self.HARDENED_INDEX)
        _account_dict = {"xpriv": _xaccount, "index": self.HARDENED_INDEX}

        # Change
        _xchange = self.derive_private_key(_xaccount)  # xpriv
        _xchangepub = self.get_extended_public_key(_xchange)
        _change_dict = {"xpriv": _xchange, "xpub": _xchangepub, "index": 0}

        # Index
        _xindex = self.derive_private_key(_xchange)
        _xindexpub = self.get_extended_public_key(_xindex)
        _index_dict = {"xpriv": _xindex, "xpub": _xindexpub, "index": 0}

        # Create initial key dict
        _change_dict.update({"0": _index_dict})
        _account_dict.update({"0": _change_dict})
        _cointype_dict.update({"0'": _account_dict})
        _purpose_dict.update({"0'": _cointype_dict})
        _master_dict.update({"44'": _purpose_dict})
        self.key_dict = {"m": _master_dict}

    def get_seed_phrase(self, bit_size=BIT_SIZE) -> list:
        # Checksum
        entropy = format(randbits(bit_size), f"0{bit_size}b")
        binary_hash = format(int(secure_hash_256(entropy), 16), f"0{bit_size}b")
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
        binary_hash = format(int(secure_hash_256(entropy), 16), f"0{bit_size}b")

        # Return True/False
        return checksum == binary_hash[:len(entropy) // 32]

    def master_extended_private_key(self, seed_phrase: list, salt=None):
        """
        Given a seed (as hex string), we generate the master extended key (mxpriv)
        """
        # seed
        seed_phrase_string = "".join(seed_phrase)

        # salt
        salt = "mnemonic" + salt if salt else "mnemonic"

        _seed = pbkdf2(salt, seed_phrase_string)

        key_string = "Bitcoin seed"
        key_hex = "".join([format(ord(key_string[c]), "02x") for c in range(len(key_string))])
        return hmac512(key=key_hex, data=_seed)

    def get_extended_public_key(self, xpriv: str):
        priv = xpriv[:self.KEY_LENGTH]
        chain_code = xpriv[self.KEY_LENGTH:]
        pk_pt = self.CURVE.generator(int(priv, 16))
        cpk = self.compress_public_key(pk_pt)
        return cpk + chain_code

    def compress_public_key(self, public_key: tuple):
        return ("02" if public_key[1] % 2 == 0 else "03") + format(public_key[0], "064x")
        # x, y = public_key
        # prefix = "02" if y % 2 == 0 else "03"
        # return prefix + format(x, "064x")

    def decompress_public_key(self, public_key: str):
        x = int(public_key[2:], 16)
        y1 = self.CURVE.get_y_from_x(x)
        y2 = self.CURVE.p - y1 % self.CURVE.p
        if public_key[:2] == "02":
            return y1 if y1 % 2 == 0 else y2
        else:
            return y1 if y1 % 2 == 1 else y2

    def derive_private_key(self, xpriv: str, index=0):
        # Config
        n = SECP256K1.ORDER
        key_length = self.KEY_LENGTH

        def half(array: str, length=key_length):
            return array[:length], array[length:]

        # Check index for hardened
        hardened = True if index >= self.HARDENED_INDEX else False

        # Get private key and chain code from extended private key
        priv, chain_code = half(xpriv)

        # Derive
        if not hardened:
            # Derive normal xpriv
            data = self.pubkeypriv(priv) + format(index, "08x")  # 4-byte Index
        else:
            # Derive hardened xpriv
            data = priv + format(index, "08x")  # 4-byte Index
        _privsum, child_chain_code = half(hmac512(key=chain_code, data=data))
        child_priv = format((int(priv, 16) + int(_privsum, 16)) % n, "064x")

        # Return xpriv
        return child_priv + child_chain_code

    def derive_public_key(self, xpub: str, index=0):
        # Config
        key_length = self.KEY_LENGTH

        def half(array: str, length=key_length):
            return array[:length], array[length:]

        # Get compressed public key and chain code from extended public key
        pub, chain_code = half(xpub)

        # Derive new xpub
        data = pub + format(index, "08x")  # 4-byte index
        _pubsum, child_chain_code = half(hmac512(key=chain_code, data=data))
        _pubsum_pt = self.CURVE.generator(int(_pubsum, 16))
        pk_pt = self.decompress_public_key(pub)
        child_pub = self.compress_public_key(self.CURVE.add_points(pk_pt, _pubsum_pt))
        return child_pub + child_chain_code

    def pubkeypriv(self, private_key: str):
        curve = SECP256K1()
        return self.compress_public_key(curve.generator(int(private_key, 16)))

    def to_json(self):
        return json.dumps(self.key_dict, indent=2)


# -- TESTING
if __name__ == "__main__":
    w = HDWallet()
    print(w.to_json())
    print(w.seed_phrase)
