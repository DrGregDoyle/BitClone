from typing import Union

BTCDataType = Union[str, int, bytes]
HEX_ALPHABET = "0123456789abcdef"


class BTCData:
    """
    A utility class for handling Bitcoin-related data with representations in bytes, hex, and int.
    """

    def __init__(self, data: BTCDataType, size: int = None, endian: str = "big"):
        """
        Initialize BTCData object.

        Args:
            data (BTCDataType): The input data as a string, integer, or bytes.
            size (int, optional): Expected size of the data in bytes. If None, the size is derived from the data.
            endian (str, optional): Byte order, either "big" or "little". Default is "big".

        Raises:
            ValueError: If the input data type is unsupported or the size is invalid.
            ValueError: If endian is not "big" or "little".
        """
        if endian not in ("big", "little"):
            raise ValueError("Endian must be 'big' or 'little'.")

        self._endian = endian
        self._byte_data = self._parse_data(data, size)
        self._size = size if size is not None else len(self._byte_data)

        if self._size != len(self._byte_data):
            raise ValueError(f"Specified size {self._size} does not match data length {len(self._byte_data)}.")

    @property
    def bytes(self) -> bytes:
        """Return the data as bytes, adjusted for endianness."""
        return self._byte_data if self._endian == "big" else self._byte_data[::-1]

    @property
    def hex(self) -> str:
        """Return the data as a hexadecimal string, adjusted for endianness."""
        byte_data = self.bytes
        return byte_data.hex()

    @property
    def int(self) -> int:
        """Return the data as an integer, adjusted for endianness."""
        return int.from_bytes(self._byte_data, byteorder=self._endian)  # type: ignore

    def compact_size(self) -> bytes:
        """
        Return the CompactSize encoding of the size instance variable.

        Returns:
            bytes: CompactSize encoding of the size.
        """
        if self._size < 0xfd:
            return self._size.to_bytes(1, "little")
        elif self._size <= 0xffff:
            return b"\xfd" + self._size.to_bytes(2, "little")
        elif self._size <= 0xffffffff:
            return b"\xfe" + self._size.to_bytes(4, "little")
        else:
            return b"\xff" + self._size.to_bytes(8, "little")

    def _parse_data(self, raw_data: BTCDataType, size: int = None) -> bytes:
        """
        Convert the input data into a byte array, respecting size. We force the data to be returned in natural byte
        order.

        Args:
            raw_data (BTCDataType): Input data to be parsed.
            size (int, optional): Expected size of the data in bytes. Default is None.

        Returns:
            bytes: Parsed byte representation of the data.

        Raises:
            ValueError: If the input data type is unsupported or cannot be parsed.
        """
        if isinstance(raw_data, bytes):
            return self._pad_or_trim(raw_data, size)

        if isinstance(raw_data, int):
            byte_length = (raw_data.bit_length() + 7) // 8
            if size is not None and size > byte_length:
                byte_length = size
            return raw_data.to_bytes(byte_length, byteorder="big")

        if isinstance(raw_data, str):
            raw_data = raw_data.lower().lstrip("0x")
            try:
                parsed_bytes = bytes.fromhex(raw_data)
                return self._pad_or_trim(parsed_bytes, size)
            except ValueError:
                return self._pad_or_trim(raw_data.encode("ascii"), size)

        raise ValueError(f"Unsupported data type: {type(raw_data)}")

    def _pad_or_trim(self, data: bytes, size: int = None) -> bytes:
        """
        Adjust the byte array to match the specified size.

        Args:
            data (bytes): Input byte data.
            size (int, optional): Desired size in bytes. Default is None.

        Returns:
            bytes: Padded or trimmed byte data.

        Raises:
            ValueError: If the data needs to be trimmed but contains too many bytes.
        """
        if size is None:
            return data

        if len(data) > size:
            return data[:size]  # Trim excess bytes
        elif len(data) < size:
            padding = b"\x00" * (size - len(data))
            return padding + data if self._endian == "big" else data + padding

        return data
