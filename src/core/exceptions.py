"""
The custom exceptions used throughout BitClone
"""
__all__ = ["ReadError"]


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
