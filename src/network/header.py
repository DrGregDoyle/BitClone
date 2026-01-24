"""
The Header class which will be prepended to each network message
"""

from src.core import Serializable, SERIALIZED, get_stream, MAGICBYTES, NETWORK, NetworkError, read_stream, \
    read_little_int
from src.cryptography import hash256

DEFAULT_MAGIC = MAGICBYTES.MAINNET
ALLOWED_COMMANDS = NETWORK.ALLOWED_COMMANDS
ALLOWED_MAGIC = [DEFAULT_MAGIC, MAGICBYTES.REGTEST, MAGICBYTES.TESTNET]


class Header(Serializable):

    def __init__(self, command: str, size: int, checksum: bytes, magic_bytes: bytes = DEFAULT_MAGIC):
        self._validate_header(magic_bytes, command.lower(), size, checksum)
        self.command = command.lower()
        self.size = size
        self.checksum = checksum
        self.magic_bytes = magic_bytes

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # Magic bytes = 4 bytes
        magic_bytes = read_stream(stream, 4)

        # Command = 12 encoded ascii bytes, padded with zero bytes
        command = (read_stream(stream, 12)).strip(b'\x00').decode("ascii")

        # size = 4 byte little-endian
        size = read_little_int(stream, 4)

        # checksum = 4 bytes
        checksum = read_stream(stream, 4)

        return cls(command, size, checksum, magic_bytes)

    @classmethod
    def from_payload(cls, payload: bytes, command: str, magic_bytes: bytes = DEFAULT_MAGIC):
        size = len(payload)
        checksum = hash256(payload)[:4]
        return cls(command, size, checksum, magic_bytes)

    def to_bytes(self) -> bytes:
        parts = [
            self.magic_bytes,
            self.command.encode("ascii").ljust(12, b'\x00')[:12],
            self.size.to_bytes(4, "little"),
            self.checksum
        ]
        return b''.join(parts)

    def to_dict(self, formatted: bool = True) -> dict:
        return {
            "magic_bytes": self.magic_bytes.hex(),
            "command": self.command.encode("ascii").ljust(12, b'\x00')[:12].hex() if formatted else self.command,
            "size": self.size.to_bytes(4, "little").hex() if formatted else self.size,
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
        if magic_bytes not in ALLOWED_MAGIC:
            raise NetworkError(f"Unknown magic bytes: {magic_bytes.hex()} ")

    def _validate_size(self, size: int):
        if size < 0 or size > 0xffff:
            raise NetworkError(f"Invalid size value: {size}")

    def _validate_checksum(self, checksum: bytes):
        if len(checksum) != 4:
            raise NetworkError(f"Incorrect bytes size for checksum: {checksum.hex()}")
