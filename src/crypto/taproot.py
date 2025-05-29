"""
We create the utility class Taproot, for use in taproot signature schemes
"""
from src.crypto.curve_utils import get_y_from_x, get_pt_from_x, generator_exponent, add_points, ORDER
from src.crypto.hash_functions import tagged_hash_function, HashType
from src.data import write_compact_size

__all__ = ["Taproot"]


class Taproot:
    """
    A utility class for use in P2TR signatures
    """
    PUBKEYBYTES = 32
    HASHTYPE = HashType.SHA256
    VERSION_INT = 192
    VERSION_BYTE = b'\xc0'

    def _get_curve_pt(self, xonly_pubkey: bytes):
        """
        Returns a point on the curve for the xonly_pubkey
        """
        x = int.from_bytes(xonly_pubkey, "big")
        try:
            y = get_y_from_x(x)  # Will return ValueError if x not on curve
        except ValueError as e:
            raise e
        return x, y

    def _get_pubkey_pt(self, xonly_pubkey: bytes):
        """
        Given an x-coordinate, we return an integer tuple with even y-coordinate
        """
        x_int = int.from_bytes(xonly_pubkey, "big")
        return get_pt_from_x(x_int)  # Returns even by default

    def tap_tweak(self, data: bytes):
        """
        Returns the TapTweak hash of the given data
        """
        return tagged_hash_function(data, b'TapTweak', self.HASHTYPE)

    def tap_branch(self, leaf1: bytes, leaf2: bytes):
        data = leaf1 + leaf2 if leaf1 < leaf2 else leaf2 + leaf1
        return tagged_hash_function(data, b"TapBranch", HashType.SHA256)

    def get_tweak(self, data: bytes):
        """
        Returns TapTweak SHA256 hash of the given data
        """
        return self.tap_tweak(data)

    def get_control_byte(self, xonly_pubkey: bytes) -> bytes:
        """
        Given the xonly pubkey, we return the VERSION_BYTE + PARITY_BIT as control_byte
        """
        pubkey_pt = self._get_pubkey_pt(xonly_pubkey)
        parity = pubkey_pt[1] % 2
        return (self.VERSION_INT + parity).to_bytes(1, "big")

    def eval_merkle_path(self, leaf_hash: bytes, merkle_path: bytes) -> bytes:
        """
        Computes the Merkle root given a leaf hash and its associated merkle path.
        The merkle_path must be a multiple of 32 bytes.
        """
        path_length = len(merkle_path)
        if path_length % 32 != 0:
            raise ValueError("Merkle path must be a multiple of 32 bytes")

        current_hash = leaf_hash

        for i in range(0, path_length, 32):
            node = merkle_path[i:i + 32]

            # Lexicographic order
            pair = current_hash + node if current_hash < node else node + current_hash
            current_hash = tagged_hash_function(pair, b"TapBranch", HashType.SHA256)

        return current_hash

    def get_leaf(self, data: bytes):
        return self.VERSION_BYTE + write_compact_size(len(data)) + data

    def get_leaf_hash(self, data: bytes, hash_type: HashType = HashType.SHA256):
        leaf_data = self.get_leaf(data)
        return tagged_hash_function(leaf_data, b'TapLeaf', hash_type)

    def tweak_data(self, data: bytes):
        return tagged_hash_function(data, b'TapTweak', HashType.SHA256)

    def tweak_pubkey(self, xonly_pubkey: bytes, merkle_root: bytes = b''):
        """
        Returns tweaked pubkey based on given pubkey and merkle_root
        """
        # Get tweak
        tweak = self.tweak_data(xonly_pubkey + merkle_root)

        # Get tweaked pubkey point
        tweaked_pubkey_pt = self.tweak_pubkey_point(xonly_pubkey, tweak)

        # Return x coordinate as pubkey
        return tweaked_pubkey_pt[0].to_bytes(self.PUBKEYBYTES, "big")

    def tweak_pubkey_point(self, xonly_pubkey: bytes, tweak: bytes):
        """
        Given the xonly pubkey and tweak data, we return the integer tuple of the sum of the two corresponding points
        """
        # Get pubkey point
        pubkey_pt = self._get_pubkey_pt(xonly_pubkey)

        # Get tweak point
        tweak_int = int.from_bytes(tweak, "big") % ORDER
        tweak_pt = generator_exponent(tweak_int)

        # Return sum of points
        return add_points(pubkey_pt, tweak_pt)

    def tweak_privkey(self, privkey: int, tweak: bytes):
        # Check pubkey
        x, y = generator_exponent(privkey)
        if y % 2 != 0:
            privkey = ORDER - privkey

        # Tweaked private key
        tweaked_privkey = (privkey + int.from_bytes(tweak, "big")) % ORDER  # self.curve.order
        return tweaked_privkey.to_bytes((tweaked_privkey.bit_length() + 7) // 8, "big")


# --- TESTING
if __name__ == "__main__":
    hash_list = [
        bytes.fromhex("6b13becdaf0eee497e2f304adcfa1c0c9e84561c9989b7f2b5fc39f5f90a60f6"),
        bytes.fromhex("ed5af8352e2a54cce8d3ea326beb7907efa850bdfe3711cef9060c7bb5bcf59e"),
        bytes.fromhex("160bd30406f8d5333be044e6d2d14624470495da8a3f91242ce338599b233931"),
        bytes.fromhex("bf2c4bf1ca72f7b8538e9df9bdfd3ba4c305ad11587f12bbfafa00d58ad6051d"),
        bytes.fromhex("54962df196af2827a86f4bde3cf7d7c1a9dcb6e17f660badefbc892309bb145f")
    ]
    sorted_list = sorted(hash_list)
    print(f"HASHLIST: {[h.hex() for h in hash_list]}")
    print(f"SORTED LIST: {[s.hex() for s in sorted_list]}")

    # init
    # taproot = Taproot()
    # spfactory = ScriptPubKeyFactory()
    #
    # # Construct
    # leaf_hash = bytes.fromhex("160bd30406f8d5333be044e6d2d14624470495da8a3f91242ce338599b233931")
    # merkle_path = bytes.fromhex(
    #     "1324300a84045033ec539f60c70d582c48b9acf04150da091694d83171b44ec9bf2c4bf1ca72f7b8538e9df9bdfd3ba4c305ad11587f12bbfafa00d58ad6051d54962df196af2827a86f4bde3cf7d7c1a9dcb6e17f660badefbc892309bb145f")
    # merkle_root = taproot.eval_merkle_path(leaf_hash, merkle_path)
    # print(f"MERKLE ROOT: {merkle_root.hex()}")
