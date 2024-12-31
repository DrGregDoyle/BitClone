"""
Methods for Schnorr signatures
"""

from src.library.ecc import secp256k1
from src.library.hash_functions import tagged_hash_function, HashType
from src.logger import get_logger

logger = get_logger(__name__)

HASHTYPE = HashType.SHA256


# TODO: add verification in each function so that hex strings are always even before being sent to a bytes object


def hex_to_bytes(*args) -> bytes:
    """
    Converts multiple hexadecimal strings into a concatenated bytes object.

    :param args: Hexadecimal string arguments.
    :return: A bytes representation of the concatenated hexadecimal string.
    :raises ValueError: If any argument is not a valid hexadecimal string.
    """
    concatenated_hex = ""

    for arg in args:
        if not isinstance(arg, str):
            raise ValueError(f"All arguments must be strings. Invalid argument: {arg}")

        # Remove optional "0x" prefix
        hex_string = arg.lower().removeprefix("0x")

        # Verify the string is valid hexadecimal
        if not all(c in "0123456789abcdef" for c in hex_string):
            raise ValueError(f"Invalid hexadecimal string: {arg}")

        # Concatenate the valid hexadecimal string
        concatenated_hex += hex_string

    # Ensure the concatenated string is of even length
    if len(concatenated_hex) % 2 != 0:
        concatenated_hex = "0" + concatenated_hex

    # Convert to bytes and return
    return bytes.fromhex(concatenated_hex)


def schnorr_signature(private_key: int, message: bytes, auxiliary_bits: bytes):
    # Curve setup
    curve = secp256k1()
    n = curve.order

    # Check that private key is < n
    if private_key >= n:
        raise ValueError("Given private key must be less than number of rational points on the curve")

    # Calculate public key - Negate private_key if necessary
    x, y = curve.multiply_generator(private_key)
    if y % 2 != 0:
        private_key = n - private_key

    logger.debug(f"Private key: {hex(private_key)}")
    logger.debug(f"Public key x: {hex(x)}")
    logger.debug(f"Public key y: {hex(y)}")

    # Create private nonce
    aux_rand_hash = tagged_hash_function(encoded_data=auxiliary_bits, tag=b"BIP0340/aux", function_type=HASHTYPE)
    logger.debug(f"Aux Rand Hash: 0x{aux_rand_hash.hex()}")

    # XOR private key with aux_rand_hash
    t = private_key ^ int.from_bytes(aux_rand_hash, byteorder="big")
    logger.debug(f"Private key XOR aux_rand_hash: {hex(t)}")

    # Create final private nonce
    hex_data = hex_to_bytes(hex(t), hex(x), message.hex())
    private_nonce_bytes = tagged_hash_function(encoded_data=hex_data, tag=b"BIP0340/nonce", function_type=HASHTYPE)
    private_nonce = int.from_bytes(private_nonce_bytes, byteorder="big") % n
    logger.debug(f"Private Nonce: {hex(private_nonce)}")

    # Calculate public nonce - Negate private_nonce if necessary
    px, py = curve.multiply_generator(private_nonce)
    if py % 2 != 0:
        private_nonce = n - private_nonce
    logger.debug(f"Public nonce x: {hex(px)}")
    logger.debug(f"Public nonce y: {hex(py)}")
    logger.debug(f"Private nonce after negation if necessary: {hex(private_nonce)}")

    # Calculate the challenge
    challenge_data = hex_to_bytes(hex(px), hex(x), message.hex())
    challenge_bytes = tagged_hash_function(encoded_data=challenge_data, tag=b"BIP0340/challenge",
                                           function_type=HASHTYPE)
    challenge = int.from_bytes(challenge_bytes, byteorder="big") % n
    logger.debug(f"CHALLENGE: {hex(challenge)}")

    # Construct signature
    r = px
    s = (private_nonce + challenge * private_key) % n

    # Return 64 byte hex string composed of two 32 byte hex strings from r and s
    return format(r, "064x") + format(s, "064x")  # 64 hex chars = 32 bytes


def verify_schnorr_signature(public_key_x: int, message: bytes, signature: str) -> bool:
    # Verify signature is 128 characters == 64 bytes
    if len(signature) != 128:
        raise ValueError("Given signature is not 64 bytes.")

    # Curve Setup
    curve = secp256k1()
    n = curve.order
    p = curve.p

    # Convenience
    x = public_key_x

    # Verify x value restrictions
    if x > p:
        raise ValueError("Given x coordinate doesn't satisfy value restrictions")

    # Calculate even y point
    y = curve.find_y_from_x(x)
    if y % 2 != 0:
        y = p - y
    public_key = (x, y)

    # Extract signature parts
    r, s = signature[:64], signature[64:]
    num_r, num_s = int(r, 16), int(s, 16)

    logger.debug(f"Recovered R: {r}")
    logger.debug(f"Recovered S: {s}")

    # Verify signatures values
    errors = {
        "r < p": num_r < p,
        "s < n": num_s < n
    }

    if not all(errors.values()):
        raise ValueError(f"One or more signature values is invalid: {errors}")

    # Calculate the challenge

    challenge_data = hex_to_bytes(r, hex(x), message.hex())
    challenge_bytes = tagged_hash_function(encoded_data=challenge_data, tag=b"BIP0340/challenge",
                                           function_type=HASHTYPE)
    challenge = int.from_bytes(challenge_bytes, byteorder="big") % n

    # Verify the signature
    point1 = curve.multiply_generator(num_s)
    point2 = curve.scalar_multiplication((n - challenge), public_key)
    point3 = curve.add_points(point1, point2)
    return point3[0] == num_r


if __name__ == "__main__":
    _priv_key = int("e8b28eb5e32d31e3ae83031654f08cf3cf9872c9391a2f45978f6e2d9ec49031", 16)
    _message = "f4bd04500ae5c08f89ea4fd130279bcd7624890ae3bb963e8290559c6285357d"
    _x, _ = secp256k1().multiply_generator(_priv_key)
    aux = "7c575049d9c4188b3d3fe7f8d672ccd45f0b9795df29810c0f584e23b0d15909"
    sig = schnorr_signature(_priv_key, bytes.fromhex(_message), bytes.fromhex(aux))
    print(f"SCHNORR SIGNATURE: {sig}")
    print(f"BYTES: {len(sig) // 2}")
    verified = verify_schnorr_signature(_x, bytes.fromhex(_message), sig)
    print(f"SIGNATURE VERIFIED: {verified}")
