"""
The class file for communication between Bitcoin nodes
"""
import io
import json

from src.crypto import hash256
from src.data import check_length, Serializable


class Header(Serializable):
    """
    Header class used for sending messages in BitClone
    -------------------------------------
    |   Name    | Format    | Byte size |
    -------------------------------------
    |   Magic Bytes | bytes         | 4 |
    | command       | ascii bytes   | 12|
    | size          | little-endian | 4 |
    | checksum      | bytes         | 4 |
    -------------------------------------
    """
    # --- MAGIC BYTES
    MAINNET_MB = bytes.fromhex("f9beb4d9")
    TESTNET_MB = bytes.fromhex("0b110907")
    REGTEST_MB = bytes.fromhex("fabfb5da")

    def __init__(self, magic_bytes: bytes, command: str, size: int, checksum: bytes):
        self.magic_bytes = magic_bytes
        self.command = command
        self.size = size
        self.checksum = checksum

    @classmethod
    def from_bytes(cls, byte_stream: bytes | io.BytesIO):
        """
        Deserialize header
        -----------------------------------------
        |   Name        |   Format      | Size  |
        -----------------------------------------
        |   Magic Bytes | bytes         | 4     |
        |   Command     | ascii bytes   | 12    |
        |   Size        | little-endian | 4     |
        |   Checksum    | bytes         | 4     |
        -----------------------------------------
        """
        # Setup stream
        if not isinstance(byte_stream, (bytes, io.BytesIO)):
            raise ValueError(f"Expected byte data stream, received {type(byte_stream)}")

        stream = io.BytesIO(byte_stream) if isinstance(byte_stream, bytes) else byte_stream

        # magic_bytes
        magic_bytes = stream.read(4)
        check_length(magic_bytes, 4, "magic_bytes")

        # command
        command_bytes = stream.read(12)
        check_length(command_bytes, 12, "command")
        command = command_bytes.decode("ascii").rstrip("\x00")

        # size
        size_bytes = stream.read(4)
        check_length(size_bytes, 4, "size")
        size = int.from_bytes(size_bytes, "little")

        # checksum
        checksum = stream.read(4)
        check_length(checksum, 4, "checksum")

        return cls(magic_bytes, command, size, checksum)

    @classmethod
    def from_payload(cls, payload: bytes, command: str = "version", magic_bytes: bytes = MAINNET_MB):
        size = len(payload)
        checksum = hash256(payload)[:4]
        return cls(magic_bytes, command, size, checksum)

    def to_bytes(self):
        # Encode command as ASCII and pad/truncate to 12 bytes
        command_bytes = self.command.encode("ascii").ljust(12, b'\x00')[:12]
        return self.magic_bytes + command_bytes + self.size.to_bytes(4, "little") + self.checksum

    def to_dict(self):
        header_dict = {
            "magic_bytes": self.magic_bytes.hex(),
            "command": self.command,
            "size": self.size,
            "checksum": self.checksum.hex()
        }
        return header_dict

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)

    def verify_payload(self, payload: bytes) -> bool:
        """
        Verifies the first 4 bytes of the hash256 of the payload agree with the checksum
        """
        return hash256(payload)[:4] == self.checksum


# --- TESTING
if __name__ == "__main__":
    test_header_bytes = bytes.fromhex("F9BEB4D976657273696F6E0000000000550000002C2F86F3")
    test_payload_bytes = bytes.fromhex(
        "7E1101000000000000000000C515CF6100000000000000000000000000000000000000000000FFFF2E13894A208D000000000000000000000000000000000000FFFF7F000001208D00000000000000000000000000")
    _header = Header.from_bytes(test_header_bytes)
    print(_header.to_json())
    print(f"PAYLOAD PASSES CHECKSUM: {_header.verify_payload(test_payload_bytes)}")

    _fp_header = Header.from_payload(test_payload_bytes)
    print(f"FROM PAYLOAD HEDER: {_fp_header.to_json()}")

    _tobytesfrom_header = Header.from_bytes(_header.to_bytes())
    print(f"FROM BYTES TO BYTES HEADER: {_tobytesfrom_header.to_json()}")
