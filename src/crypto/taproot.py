"""
We create the utility class Taproot, for use in taproot signature schemes
"""

from src.crypto.ecc import secp256k1
from src.crypto.hash_functions import tagged_hash_function, HashType
from src.script.scriptpubkey_factory import ScriptPubKeyFactory


class Taproot:
    curve = secp256k1()
    PUBKEYBYTES = 32

    def taptweak(self, data: bytes):
        """
        Returns tagged hash function with tag = "TapTweak"
        """
        return tagged_hash_function(data, b"TapTweak", HashType.SHA256)

    def tweak_pubkey(self, pubkey: bytes, merkle_root: bytes = b''):
        """
        Returns tweaked pubkey based on given pubkey and merkle_root
        """
        x = int.from_bytes(pubkey, "big")
        y = self.curve.find_y_from_x(x)

        # Ensure even y
        if y % 2 != 0:
            y = self.curve.p - y
        pubkey_point = (x, y)

        # Verify (x,y)
        if not self.curve.is_point_on_curve((x, y)):
            raise ValueError("Public key point not on curve")

        # Calculate tweak
        tweak = self.taptweak(pubkey + merkle_root)

        # Get tweak point from tweak int
        tweak_point = self.curve.multiply_generator(int.from_bytes(tweak, "big"))
        tweakedpubkey = self.curve.add_points(pubkey_point, tweak_point)
        return tweakedpubkey[0].to_bytes(32, "big")  # x-only

    def tweak_privkey(self, privkey: int, tweak: bytes):
        # Check pubkey
        x, y = self.curve.multiply_generator(privkey)
        if y % 2 != 0:
            privkey = self.curve.order - privkey

        # Tweaked private key
        tweaked_privkey = (privkey + int.from_bytes(tweak, "big")) % self.curve.order
        return tweaked_privkey.to_bytes((tweaked_privkey.bit_length() + 7) // 8, "big")

    def get_pubkey_x(self, privkey: int) -> bytes:
        """
        Returns corresponding x coordinate of public key in bytes
        """
        x, _ = self.curve.multiply_generator(privkey)
        return x.to_bytes(self.PUBKEYBYTES, "big")


# --- TESTING
if __name__ == "__main__":
    # init
    taproot = Taproot()
    spfactory = ScriptPubKeyFactory()

    # Construct
    privkey = bytes.fromhex("ce1fc7baa9db31c4ef9c6564f70d551f41fc479bb23fa844d50848220edaaf91")
    tweak = bytes.fromhex("bf0094eae70ba67e2f9fc3c4b81f078c90931855a8d24c959619174c92060cde")
    privkey_int = int.from_bytes(privkey, "big")
    pubkey_x = taproot.get_pubkey_x(privkey_int)
    print(f"PUBKEY: {pubkey_x.hex()}")

    tweaked_privkey = taproot.tweak_privkey(privkey_int, tweak)
    print(f"TWEAKED PRIVKEY: {tweaked_privkey.hex()}")

    merkle = bytes.fromhex("b5b72eea07b3e338962944a752a98772bbe1f1b6550e6fb6ab8c6e6adb152e7c")
    tweak = taproot.taptweak(pubkey_x + merkle)
    print(f"TWEAK: {tweak.hex()}")
    tweaked_pubkey = taproot.tweak_pubkey(pubkey_x, merkle)
    print(f"TWEAKED PUBKEY: {tweaked_pubkey.hex()}")

    p2tr_scriptpubkey = spfactory.p2tr(tweaked_pubkey)
    print(f"PT2R SCRIPTPUBKEY: {p2tr_scriptpubkey.to_json()}")
