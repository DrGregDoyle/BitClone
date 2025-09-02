"""
The custom exceptions used throughout BitClone
"""
__all__ = ["ReadError", "StreamError", "ECDSAError", "SchnorrError", "ECCPrivateKeyError", "ECCError"]


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


class ECCError(StreamError):
    """
    For use when deserializing pubkeys
    """
    pass


class ECCPrivateKeyError(Exception):
    """
    For if the private key is out of bounds
    """
    pass


class ECDSAError(Exception):
    """
    Raised during ECDSA operations for out of bounds values
    """
    pass


class SchnorrError(Exception):
    """
    Raised during Schnorr signatures for out of bound values
    """
    pass
