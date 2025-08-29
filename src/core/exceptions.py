"""
The custom exceptions used throughout BitClone
"""
__all__ = ["ReadError", "StreamError", "ECDSAError"]


class StreamError(Exception):
    """
    Catchall for stream errors
    """
    pass


class ReadError(StreamError):
    """
    For when trying to read data of length n from the stream and receiving data of length < b
    """
    pass


class ECDSAError(Exception):
    """
    Raised during ECDSA operations for out of bounds values
    """
    pass
