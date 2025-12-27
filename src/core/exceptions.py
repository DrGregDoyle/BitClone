"""
The custom exceptions used throughout BitClone
"""
__all__ = ["ReadError", "StreamError", "ECDSAError", "SchnorrError", "ECCPrivateKeyError", "ECCError", "WalletError",
           "ExtendedKeyError", "PubKeyError", "WriteError", "BitNumError", "BitStackError", "OpCodeError",
           "ScriptPubKeyError", "ScriptSigError", "TargetBitsError", "MerkleError", "SignatureError",
           "ScriptEngineError", "DataEncodingError", "TaprootError", "CoinbaseError"]


class DataEncodingError(Exception):
    """
    For use in encoding/decoding algorithms
    """
    pass


class CoinbaseError(Exception):
    """
    For use in Coinbase class validation
    """
    pass


class ScriptEngineError(Exception):
    """
    For use in the script engine, when missing context items, etc...
    """
    pass


class SignatureError(Exception):
    """
    For use in the Signature Engine
    """
    pass


class MerkleError(Exception):
    """
    For use in the MerkleTree class
    """
    pass


class TargetBitsError(Exception):
    """
    For use in target bit encoding and decoding
    """
    pass


class BitNumError(Exception):
    """
    For use in the BitNum class
    """
    pass


class BitStackError(Exception):
    """
    For use in the BitStack class
    """
    pass


class ScriptPubKeyError(Exception):
    """
    For use in ScriptPubKey class and its children
    """
    pass


class ScriptSigError(Exception):
    """
    For use in ScriptSig class and its children
    """
    pass


class OpCodeError(Exception):
    """
    For use in various script elements
    """
    pass


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


class WriteError(StreamError):
    """
    For when writing data that would be otherwise out of bounds
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


class WalletError(Exception):
    """
    Parent class for Wallet errors
    """
    pass


class ExtendedKeyError(Exception):
    """Custom exception for extended key operations"""
    pass


class PubKeyError(Exception):
    """
    Used for Pubkey errors
    """
    pass


class TaprootError(Exception):
    """
    For use in Taproot elements
    """
    pass
