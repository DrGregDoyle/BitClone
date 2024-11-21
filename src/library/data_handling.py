"""
Methods for managing data

"""

import json
import re
from typing import Any, Union, Literal, Optional

from src.logger import get_logger

logger = get_logger(__name__)


# --- DATA FORMATS --- #
class Data:
    """
    A class for all atomic level data. Data is assumed to be a hexadecimal string. Data will be kept as integer
    values and accessed as different types as necessary.
    """

    def __init__(self, data: Union[int, bytes, str, 'Data'], bytesize: int | None = None,
                 byteorder: Literal["big", "little"] = "big"):
        # Handle data types | int, bytes, str
        if isinstance(data, int):
            self.num = data
        elif isinstance(data, bytes):
            self.num = int.from_bytes(data, byteorder)
        elif isinstance(data, str):
            if is_hex(data):
                self.num = int(data[::-2], 16) if byteorder == "little" else int(data, 16)
            else:
                self.num = int.from_bytes(data.encode(), byteorder)
        elif isinstance(data, Data):
            self.num = data.num  # Redundant case
        else:
            # Raise error for unknown type
            raise ValueError(f"Incorrect type used for data object: {type(data)}")

        # Save byteorder
        self.byteorder = byteorder

        # Internal variables
        self._length = (self.num.bit_length() + 7) // 8 if bytesize is None else bytesize

    def __repr__(self):
        var_dict = {
            "int": self.num,
            "hex": self.hex,
            "byteorder": self.byteorder,
            "bytes": self.bytes.hex(),
            "reverse_byte_order": self.reverse_byte_order.hex(),
            "compact_size": self.compact_size.hex() if self.compact_size is not None else ""
        }
        return json.dumps(var_dict, indent=3)

    def __add__(self, other):
        if isinstance(other, Data):
            return Data(self.num + other.num)
        elif isinstance(other, int):
            return Data(self.num + other)
        elif isinstance(other, bytes):
            return Data(self.num + int.from_bytes(other, byteorder="big"))
        elif isinstance(other, str):
            if is_hex(other):
                return Data(self.num + int(other, 16))
            else:
                return Data(self.num + int.from_bytes(other.encode(), byteorder="big"))
        else:
            raise ValueError(f"Incorrect type to be added to Data class: {type(other)}")

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

def get_data(data: Any) -> Optional[Data]:
    # Return data if it's Data type
    if isinstance(data, Data):
        return data
    # Try returning Data formatted data
    try:
        return Data(data)
    except ValueError:
        logger.error(f"Incorrect data type used in function: {type(data)}")
        return None


def is_hex(data: Any) -> bool:
    # Verify if data is a str
    if not isinstance(data, str):
        logger.debug(f"Data {data} is not of str type: {type(data)}")
        return False

    # Verify hex values in str
    hex_pattern = r'^(0x)?[0-9a-fA-F]+$'
    return bool(re.match(hex_pattern, data))


if __name__ == "__main__":
    test_hex = "0100"
    d1 = Data(test_hex, bytesize=2, byteorder="little")
    d2 = Data(test_hex, bytesize=2)
    d3 = Data(test_hex, byteorder="little")
    print(d1)
    print(d2)
    print(d3)
