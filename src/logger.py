"""
File for logging
"""
import logging
import sys
from typing import Literal


def get_logger(name: str, log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "DEBUG"):
    # Setup
    logger = logging.getLogger(name)
    
    logger.setLevel(log_level)

    # Format
    handler = logging.StreamHandler(stream=sys.stdout)
    formatter = logging.Formatter('%(asctime)s [%(name)s] [%(levelname)s]: %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger
