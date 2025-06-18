"""
The Header and Payload classes
"""
import json
from io import BytesIO

from src.crypto import hash256
from src.data import get_stream, read_stream, read_little_int


class Header:
    """
    -----------------------------------------
    |   Name        | Format        | Size  |
    -----------------------------------------
    |   Magic Bytes | Bytes         | 4     |
    |   Command     | Ascii bytes   | 12    |
    |   Size        | little-endian | 4     |
    |   Checksum    | bytes         | 4     |
    -----------------------------------------
    """
    # MagicBytes
    MB_MAINNET = bytes.fromhex("f9beb4d9")
    MB_TESTNET = bytes.fromhex("0b110907")
    MB_REGTEST = bytes.fromhex("fabfb5da")

    # Byte Sizes
    MB_BYTES = SIZE_BYTES = CHECKSUM_BYTES = 4
    COMMAND_BYTES = 12

    def __init__(self, magic_bytes: bytes, command: str, size: int, checksum: bytes):
        self.magic_bytes = magic_bytes
        self.command = command
        self.size = size
        self.checksum = checksum

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        # Get byte stream
        stream = get_stream(byte_stream)

        # Get byte data
        magic_bytes = read_stream(stream, cls.MB_BYTES, "magic_bytes")
        command = read_stream(stream, cls.COMMAND_BYTES, "command").decode("ascii")
        size = read_little_int(stream, cls.SIZE_BYTES, "size")
        checksum = read_stream(stream, cls.CHECKSUM_BYTES, "checksum")

        return cls(magic_bytes, command, size, checksum)

    @classmethod
    def from_payload(cls, payload: bytes, command: str = "version", magic_bytes: bytes = MB_MAINNET):
        size = len(payload)
        checksum = hash256(payload)
        return cls(magic_bytes, command, size, checksum)

    def to_bytes(self) -> bytes:
        """
        Serialization of the header | 24 bytes
        """
        command_bytes = self.command.encode("ascii")
        command_bytes = command_bytes.ljust(12, b'\x00')[:12]
        header_bytes = (
                self.magic_bytes
                + command_bytes
                + self.size.to_bytes(self.SIZE_BYTES, "little")
                + self.checksum
        )
        return header_bytes

    def to_dict(self) -> dict:
        """
        Returns display dict with instance values
        """
        header_dict = {
            "magic_bytes": self.magic_bytes.hex(),
            "command": self.command.rstrip('\x00'),
            "size": self.size,
            "checksum": self.checksum.hex()
        }
        return header_dict

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)


# --- TESTING
if __name__ == "__main__":
    test_header_bytes = bytes.fromhex("F9BEB4D976657273696F6E0000000000550000002C2F86F3")
    test_header = Header.from_bytes(test_header_bytes)
    print(f"TEST HEADER: {test_header.to_json()}")
    header_from_bytes = Header.from_bytes(test_header.to_bytes())
    print(f"HEADER FROM BYTES: {header_from_bytes.to_json()}")
