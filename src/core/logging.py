"""
File for logging
"""
import logging
import sys
from pathlib import Path
from typing import Optional

__all__ = ["get_logger"]


def get_logger(name: str, log_level: str = "DEBUG", log_file: Optional[Path] = None,
               format_string: Optional[str] = None) -> logging.Logger:
    """
    Get or create a logger with the specified configuration.

    Args:
        name: Logger name (typically __name__ from calling module)
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file for persistent logging
        format_string: Optional custom format string

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    # Prevent adding duplicate handlers
    if logger.handlers:
        return logger

    logger.setLevel(getattr(logging, log_level.upper()))

    # Default format
    if format_string is None:
        format_string = '%(asctime)s [%(name)s] [%(levelname)s]: %(message)s'

    formatter = logging.Formatter(format_string)

    # Console handler
    console_handler = logging.StreamHandler(stream=sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Optional file handler
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger
