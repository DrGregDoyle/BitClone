"""
Methods for managing data

"""

import re
from typing import Any

from src.logger import get_logger

logger = get_logger(__name__)


# --- VERIFY FUNCTIONS --- #

def is_hex(data: Any) -> bool:
    # Verify if data is a str
    if not isinstance(data, str):
        logger.debug(f"Data {data} is not of str type: {type(data)}")
        return False

    # Verify hex values in str
    hex_pattern = r'^(0x)?[0-9a-fA-F]+$'
    return bool(re.match(hex_pattern, data))
