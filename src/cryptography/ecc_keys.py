"""
The ECCKey class - given an elliptic curve, we generate a private/public keypair, along with methods for serialization
"""
import json

from src.core import ECC, ECCPrivateKeyError, SERIALIZED, get_stream, read_stream, read_big_int, ECCError
from src.cryptography.ecc import EllipticCurve, SECP256K1, Point

__all__ = ["PubKey"]
BYTE_LEN = ECC.COORD_BYTES


class PubKey:
    __slots__ = ("pub_key", "is_even_y")

    def __init__(self, private_key: int, is_even_y: bool = False, curve: EllipticCurve = SECP256K1):
        # Check priv_key
        priv_key = private_key % curve.order
        if priv_key == 0:
            raise ECCPrivateKeyError("Private key = 0 modulo the order of the curve")

        self.is_even_y = is_even_y
        self.pub_key = curve.multiply_generator(priv_key)  # Point

        if self.is_even_y:
            temp_y = self.pub_key.y
            y = curve.p - temp_y if temp_y % 2 != 0 else temp_y
            self.pub_key = Point(self.pub_key.x, y)

    def __eq__(self, other):
        """Check equality based on the public key point"""
        if not isinstance(other, PubKey):
            return False
        return self.pub_key.x == other.pub_key.x and self.pub_key.y == other.pub_key.y

    def __hash__(self):
        """Make PubKey hashable based on the point coordinates. Needed for overriding __eq__"""
        return hash((self.pub_key.x, self.pub_key.y))

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED, curve: EllipticCurve = SECP256K1):
        stream = get_stream(byte_stream)

        # Create a new instance without calling __init__
        instance = cls.__new__(cls)

        # Check for x-only pubkey | Must have even y coordinate
        if stream.getbuffer().nbytes == BYTE_LEN:
            x_int = read_big_int(stream, BYTE_LEN, "x_only pubkey")
            y_int = curve.find_y_from_x(x_int)
            y_int = curve.p - y_int if y_int % 2 != 0 else y_int  # Force even y
            instance.pub_key = Point(x_int, y_int)
            instance.is_even_y = True
            return instance

        # Get type
        type_byte = read_stream(stream, 1)

        # 32-byte x-coordinate always precedes it
        x_int = read_big_int(stream, BYTE_LEN, "pubkey_x")

        # Get temp_y val based on x
        temp_y = curve.find_y_from_x(x_int)

        # Find y based on type byte
        if type_byte == b'\x02':
            y_int = temp_y if temp_y % 2 == 0 else curve.p - temp_y
            instance.is_even_y = temp_y % 2 == 0  # Track if we have even y
        elif type_byte == b'\x03':
            y_int = temp_y if temp_y % 2 == 1 else curve.p - temp_y
            instance.is_even_y = temp_y % 2 != 1  # Track if we have even y
        elif type_byte == b'\x04':
            y_int = read_big_int(stream, BYTE_LEN, "pubkey_y")
            instance.is_even_y = y_int % 2 == 0  # Track if we have even y
        else:
            raise ECCError("Unidentified type byte for Public Key")

        instance.pub_key = Point(x_int, y_int)
        return instance

    def _x_bytes(self):
        """Returns x coordinate as byte stream"""
        return self.pub_key.x.to_bytes(length=ECC.COORD_BYTES, byteorder='big')

    def _y_bytes(self):
        """Returns y coordinate as byte stream"""
        return self.pub_key.y.to_bytes(length=ECC.COORD_BYTES, byteorder='big')

    def serial_pubkey(self) -> bytes:
        """Return the serialized 65-byte pubkey"""
        return b''.join([b'\x04', self._x_bytes(), self._y_bytes()])

    def serial_compressed(self) -> bytes:
        """Returns the serialized compressed pubkey"""
        init_byte = b'\x02' if self.pub_key.y % 2 == 0 else b'\x03'
        return b''.join([init_byte, self._x_bytes()])

    def serial_xonly(self) -> bytes:
        """Returns the serialized x-only pubkey"""
        if not self.is_even_y:
            raise ECCError("Cannot use x-only pubkey for odd y coordinate")
        return self._x_bytes()

    def key_dict(self):
        """
        For display, we return a dictionary of all public key serial types
        """
        pkx, pky = self.pub_key.tuple
        return {
            "pubkey_point": (hex(pkx), hex(pky)),
            "uncompressed": self.serial_pubkey().hex(),
            "compressed": self.serial_compressed().hex(),
            "x-only": self.serial_xonly().hex() if self.is_even_y else ""
        }

    def to_json(self):
        return json.dumps(self.key_dict())


# -- TESTING
if __name__ == "__main__":
    known_key_int = int.from_bytes(bytes.fromhex("d304a45c06695532363b675c228b55e98729509ef8c1c5770dff6487a07d800d"),
                                   "big")
    known_key = PubKey(known_key_int, is_even_y=True)
    print(f"UNCOMPRESSED PUBKEY: {known_key.serial_pubkey().hex()}")
    print(f"COMPRESSED PUBKEY  : {known_key.serial_compressed().hex()}")
    print(f"XONLY PUBKEY       : {known_key.serial_xonly().hex()}")

    test_key1 = PubKey.from_bytes(known_key.serial_xonly())
    test_key2 = PubKey.from_bytes(known_key.serial_pubkey())
    test_key3 = PubKey.from_bytes(known_key.serial_compressed())

    print(f"RECOVERED XONLY PUBKEY       : {test_key1.serial_xonly().hex()}")
    print(f"RECOVERED UNCOMPRESSED PUBKEY: {test_key2.serial_pubkey().hex()}")
    print(f"RECOVERED COMPRESSED PUBKEY  : {test_key3.serial_compressed().hex()}")

    print(f"KEYS EQUAL: {test_key1 == known_key}")
    print(f"KEYS EQUAL: {test_key2 == known_key}")
    print(f"KEYS EQUAL: {test_key3 == known_key}")
