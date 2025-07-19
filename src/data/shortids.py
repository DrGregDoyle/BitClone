"""
The ShortID class
"""
import json
from io import BytesIO

from src.data.byte_stream import get_stream, read_little_int

__all__ = ["ShortID"]


class ShortID:
    """
    A 6-byte integer, padded with 2 null-bytes so it can be read as an 8-byte integer
    """
    SHORTID_BYTES = 8
    MAX_PAYLOAD_BYTES = SHORTID_BYTES - 2

    def __init__(self, short_id: int | bytes):
        # short_id as integer
        if isinstance(short_id, int):
            # Error checking
            int_byte_length = (short_id.bit_length() + 7) // 8
            if int_byte_length > self.MAX_PAYLOAD_BYTES:
                raise ValueError(f"Given integer {short_id} has byte length greater than {self.MAX_PAYLOAD_BYTES}")
            self.short_id = short_id.to_bytes(self.SHORTID_BYTES, "little")
        elif isinstance(short_id, bytes):
            # Error checking
            if len(short_id) > self.MAX_PAYLOAD_BYTES:
                raise ValueError(
                    f"Given bytes object {short_id.hex()} has byte length greater than {self.MAX_PAYLOAD_BYTES}")
            self.short_id = short_id + b'\x00' * (self.SHORTID_BYTES - len(short_id))
        else:
            raise ValueError("Incorrect short_id type")

        # Underlying integer
        self.int_value = int.from_bytes(self.short_id, "little")

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        stream = get_stream(byte_stream)

        int_val = read_little_int(stream, cls.SHORTID_BYTES, "short_id")
        return cls(int_val)

    def to_bytes(self):
        return self.short_id

    def to_dict(self):
        return {
            "short_id": self.short_id.hex(),
            "int_value": self.int_value
        }

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)


# --- TESTING
if __name__ == "__main__":
    test_id = ShortID(bytes.fromhex("deadbeefaadd"))
    print(f"TEST ID: {test_id.short_id.hex()}")
    test_id2 = ShortID(0xaabbccddeeff)
    print(f"TEST ID 2: {test_id2.short_id.hex()}")
    print(f"TEST ID INT: {test_id2.int_value}")

    test_id3 = ShortID(41)
    print(f"TEST ID3: {test_id3.short_id.hex()}")
    print(f"TEST ID3 INT: {test_id3.int_value}")
