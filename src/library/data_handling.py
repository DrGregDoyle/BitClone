"""
Methods for managing data

"""

import json
import re
from typing import Any, Union, Literal

from src.logger import get_logger

logger = get_logger(__name__)


# --- DATA FORMATS --- #
class Data:
    """
    A class for all atomic level data. Data is assumed to be a hexadecimal string. Data will be kept as integer
    values and accessed as different types as necessary.
    """

    def __init__(self, data: Union[int, bytes, str], byteorder: Literal["big", "little"] = "big"):
        # Handle data types | int, bytes, str
        if isinstance(data, int):
            self.num = data
        elif isinstance(data, bytes):
            self.num = int.from_bytes(data, byteorder)
        elif isinstance(data, str):
            # Take int values of bytes encoding if data is not a hexadecimal string
            self.num = int(data, 16) if is_hex(data) else int.from_bytes(data.encode(), byteorder)
        else:
            # Raise error for unknown type
            raise ValueError(f"Incorrect type used for data object: {type(data)}")

        # Save byteorder
        self.byteorder = byteorder

        # Internal variables
        self._length = (self.num.bit_length() + 7) // 8

    def __repr__(self):
        var_dict = {
            "int": self.num,
            "hex": self.hex,
            "byteorder": self.byteorder,
            "bytes": self.bytes.hex(),
            "reverse_byte_order": self.reverse_byte_order.hex(),
            "compact_size": self.compact_size.hex()
        }
        return json.dumps(var_dict, indent=3)

    @property
    def bytes(self):
        return self.num.to_bytes(length=self._length, byteorder=self.byteorder)

    @property
    def hex(self):
        return self.bytes.hex()

    @property
    def is_little_endian(self):
        return self.byteorder == "little"

    @property
    def reverse_byte_order(self):
        return self.bytes[::-1]

    @property
    def compact_size(self):
        if self.num > 0xffffffffffffffff:
            return None
        return self._get_bytes(self.num)

    @staticmethod
    def _get_bytes(num: int):
        if 0 <= num <= 0xfc:
            return num.to_bytes(length=1, byteorder="little")
        elif 0xfd <= num <= 0xffff:
            b1 = 0xfd.to_bytes(length=1, byteorder="big")
            b2 = num.to_bytes(length=2, byteorder="little")
            return b1 + b2
        elif 0x10000 <= num <= 0xffffffff:
            b1 = 0xfe.to_bytes(length=1, byteorder="big")
            b2 = num.to_bytes(length=4, byteorder="little")
            return b1 + b2
        elif 0x100000000 <= num <= 0xffffffffffffffff:
            b1 = 0xff.to_bytes(length=1, byteorder="big")
            b2 = num.to_bytes(length=8, byteorder="little")
            return b1 + b2
        else:
            raise ValueError("Number is too big to be CompactSize encoded.")


# --- VERIFY FUNCTIONS --- #

def is_hex(data: Any) -> bool:
    # Verify if data is a str
    if not isinstance(data, str):
        logger.debug(f"Data {data} is not of str type: {type(data)}")
        return False

    # Verify hex values in str
    hex_pattern = r'^(0x)?[0-9a-fA-F]+$'
    return bool(re.match(hex_pattern, data))


if __name__ == "__main__":
    v1 = 0xffeeccdd
    # v2 = 41
    # v3 = "0x41"
    # v4 = "Hello world"
    d1 = Data(v1)
    # d2 = Data(v2)
    # d3 = Data(v3)
    # d4 = Data(v4)

    print(d1)
    # print(d2)
    # print(d3)
    # print(d4)
