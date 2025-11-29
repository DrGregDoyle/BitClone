import json

from src.core import PubKeyError
from src.cryptography import SECP256K1, Point, hash160


class PubKey:
    """
    Used for Serializaing a public key in BitClone
    """
    __slots__ = ("x", "y")

    def __init__(self, private_key: int | bytes):
        private_key = int.from_bytes(private_key, "big") if isinstance(private_key, bytes) else private_key
        self.x, self.y = SECP256K1.multiply_generator(private_key)

    # --- OVERRIDES --- #
    def __eq__(self, other) -> bool:
        # Check instance
        if not isinstance(other, PubKey):
            print(isinstance(other, PubKey))
            raise PubKeyError("Compared Pubkey  with different type")

        return self.x == other.x and self.y == other.y

    # --- CLASS METHODS --- #
    @classmethod
    def from_uncompressed(cls, full_pubkey: bytes):
        # --- Validation --- #
        if len(full_pubkey) != 65:
            raise PubKeyError("Uncompressed pubkey not of correct length.")

        prefix = full_pubkey[0]
        if prefix != 0x04:
            raise PubKeyError("Uncompressed pubkey has incorrect prefix")

        x_bytes = full_pubkey[1:33]
        y_bytes = full_pubkey[33:]

        x = int.from_bytes(x_bytes, "big")
        y = int.from_bytes(y_bytes, "big")

        # Check point
        if not SECP256K1.is_point_on_curve(Point(x, y)):
            raise PubKeyError("Decoded public key point not on SECP256K1 curve")

        # Return instance
        obj = cls.__new__(cls)
        obj.x = x
        obj.y = y
        return obj

    @classmethod
    def from_compressed(cls, compressed_pubkey: bytes):
        if len(compressed_pubkey) != 33:
            raise PubKeyError("Compressed pubkey must be 33 bytes")
        prefix = compressed_pubkey[0]
        if prefix not in (0x02, 0x03):
            raise PubKeyError("Invalid prefix for compressed pubkey")
        x = int.from_bytes(compressed_pubkey[1:], "big")
        if not (0 < x < SECP256K1.p):
            raise PubKeyError("x out of range")

        if not SECP256K1.is_x_on_curve(x):
            raise PubKeyError("Given x coordinate not on curve")

        y = SECP256K1.find_y_from_x(x)
        want_odd = 1 if prefix == 0x03 else 0
        if (y & 1) != want_odd:
            y = SECP256K1.p - y

        obj = object.__new__(cls)  # bypass __init__
        obj.x, obj.y = x, y
        return obj

    @classmethod
    def from_xonly(cls, xonly_pubkey: bytes):
        """
        Any pubkey generated from x-only coordinates is assumed to have even y-coordinate
        """
        if len(xonly_pubkey) != 32:
            raise PubKeyError("X-only pubkey must be 32 bytes")
        x = int.from_bytes(xonly_pubkey, "big")
        if not (0 < x < SECP256K1.p):
            raise PubKeyError("x out of range")
        if not SECP256K1.is_x_on_curve(x):
            raise PubKeyError("Given x coordinate not on curve")

        y = SECP256K1.find_y_from_x(x)
        if y % 2 != 0:  # Take -y (mod p) if y is odd
            y = SECP256K1.p - y

        obj = object.__new__(cls)  # bypass __init__
        obj.x, obj.y = x, y
        return obj

    @classmethod
    def from_point(cls, point: Point):
        # Validate point
        if not SECP256K1.is_point_on_curve(point):
            raise PubKeyError("Given point not on SECP256K1 curve")
        x, y = point

        obj = object.__new__(cls)
        obj.x = x
        obj.y = y
        return obj

    @classmethod
    def from_bytes(cls, pubkey_bytes: bytes):
        """
        Proceed based on length of pubkey
        """
        # Compressed
        if len(pubkey_bytes) == 65 and pubkey_bytes[0] == 4:
            return cls.from_uncompressed(pubkey_bytes)
        # Uncompresed
        elif len(pubkey_bytes) == 33 and pubkey_bytes[0] in (2, 3):
            return cls.from_compressed(pubkey_bytes)
        # X-only
        elif len(pubkey_bytes) == 32:
            return cls.from_xonly(pubkey_bytes)
        else:
            raise PubKeyError("Unrecognized pubkey type")

    # --- FORMATTING

    def compressed(self) -> bytes:
        """
        Returns a compressed public key
        """
        y_byte = b'\x02' if self.y % 2 == 0 else b'\x03'
        return y_byte + self.x.to_bytes(32, "big")

    def uncompressed(self) -> bytes:
        """
        Returns an uncompressed public key
        """
        return b'\x04' + self.x_bytes() + self.y_bytes()

    def x_bytes(self):
        return self.x.to_bytes(32, "big")

    def y_bytes(self):
        return self.y.to_bytes(32, "big")

    def to_point(self):
        return Point(self.x, self.y)

    def pubkey_hash(self):
        return hash160(self.compressed())

    # --- TAPROOT TWEAK
    def tweak_pubkey(self, tweak: int | bytes) -> 'PubKey':
        # Calculate tweak
        tweak_int = int.from_bytes(tweak, "big") if isinstance(tweak, bytes) else tweak
        tweak_point = SECP256K1.multiply_generator(tweak_int)
        new_pubkey_point = SECP256K1.add_points(self.to_point(), tweak_point)
        return PubKey.from_point(new_pubkey_point)

    # --- DISPLAY --- #
    def to_dict(self):
        """
        Returns a dictionary with the all available pubkey info
        """
        return {
            "x": self.x,
            "y": self.y,
            "x_bytes": self.x_bytes().hex(),
            "y_bytes": self.y_bytes().hex(),
            "uncomressed": self.uncompressed().hex(),
            "compressed": self.compressed().hex(),
            "pubkey_hash": self.pubkey_hash().hex()
        }

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)
