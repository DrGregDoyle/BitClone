"""
The Header class which will be prepended to each network message
"""

from src.core import Serializable, SERIALIZED, get_stream, MAGICBYTES, NETWORK, NetworkError, read_stream, \
    read_little_int
from src.cryptography import hash256


class Header(Serializable):
    """
    =============================================================================
    |   name            |   datatype    |   serialzed format    |   byte size   |
    =============================================================================
    |   magic_byttes    |   bytes       |   natural byte order  |   4           |
    |   command         |   str         |   ascii bytes         |   12          |
    |   size            |   int         |   little-endian       |   4           |
    |   checksum        |   bytes       |   natural byte order  |   4           |
    =============================================================================
    """

    def __init__(self, command: str, size: int, checksum: bytes, magic_bytes: bytes = MAGICBYTES.MAINNET):
        self._validate_header(magic_bytes, command.lower(), size, checksum)
        self.command = command.lower()
        self.size = size
        self.checksum = checksum
        self.magic_bytes = magic_bytes

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # Magic bytes = 4 bytes
        magic_bytes = read_stream(stream, NETWORK.MAGIC_LENGTH)

        # Command = 12 encoded ascii bytes, padded with zero bytes
        command = read_stream(stream, NETWORK.COMMAND_LENGTH).strip(b'\x00').decode("ascii")

        # size = 4 byte little-endian
        size = read_little_int(stream, NETWORK.PAYLOAD_SIZE_LENGTH)

        # checksum = 4 bytes
        checksum = read_stream(stream, NETWORK.CHECKSUM_LENGTH)

        return cls(command, size, checksum, magic_bytes)

    @classmethod
    def from_payload(cls, payload: bytes, command: str, magic_bytes: bytes = MAGICBYTES.MAINNET):
        size = len(payload)
        checksum = hash256(payload)[:NETWORK.CHECKSUM_LENGTH]
        return cls(command, size, checksum, magic_bytes)

    def to_bytes(self) -> bytes:
        parts = [
            self.magic_bytes,
            self.command.encode("ascii").ljust(NETWORK.COMMAND_LENGTH, b'\x00')[:NETWORK.COMMAND_LENGTH],
            self.size.to_bytes(NETWORK.PAYLOAD_SIZE_LENGTH, "little"),
            self.checksum
        ]
        return b''.join(parts)

    def to_dict(self) -> dict:
        return {
            "magic_bytes": self.magic_bytes.hex(),
            "command": self.command.encode("ascii").ljust(
                NETWORK.COMMAND_LENGTH, b'\x00'
            )[:NETWORK.COMMAND_LENGTH].hex(),
            "size": self.size.to_bytes(NETWORK.PAYLOAD_SIZE_LENGTH, "little").hex(),
            "checksum": self.checksum.hex(),
        }

    def to_data(self) -> dict:
        return {
            "magic_bytes": self.magic_bytes.hex(),
            "command": self.command,
            "size": self.size,
            "checksum": self.checksum.hex(),
        }

    def _validate_header(self, magic_bytes: bytes, command: str, size: int, checksum: bytes, ):
        self._validate_magic_bytes(magic_bytes)
        self._validate_command(command)
        self._validate_size(size)
        self._validate_checksum(checksum)

    def _validate_command(self, command: str):
        """Verify the command is in the list of allowed commands."""
        if command in NETWORK.DEPRECATED_COMMANDS:
            raise NetworkError(f"Command '{command}' has been deprecated")
        if command not in NETWORK.ALLOWED_COMMANDS:
            raise NetworkError(f"Unknown command: '{command}'")

    def _validate_magic_bytes(self, magic_bytes: bytes):
        """Verify the magic bytes is in the list of allowed magic bytes"""
        if magic_bytes not in MAGICBYTES.ALLOWED_MAGIC:
            raise NetworkError(f"Unknown magic bytes: {magic_bytes.hex()} ")

    def _validate_size(self, size: int):
        max_size = (1 << (8 * NETWORK.PAYLOAD_SIZE_LENGTH)) - 1
        if size < 0 or size > max_size:
            raise NetworkError(f"Invalid size value: {size}")

    def _validate_checksum(self, checksum: bytes):
        if len(checksum) != NETWORK.CHECKSUM_LENGTH:
            raise NetworkError(f"Incorrect bytes size for checksum: {checksum.hex()}")


# --- TESTING ---#
if __name__ == "__main__":
    known_verack_header_bytes = bytes.fromhex("f9beb4d976657261636b000000000000000000005df6e0e2")
    test_header = Header.from_bytes(known_verack_header_bytes)
    print(f"TEST HEADER: {test_header.to_json()}")
    print("===" * 60)
    print(f"TEST HEADER NO FORMATTING: {test_header.to_json()}")
