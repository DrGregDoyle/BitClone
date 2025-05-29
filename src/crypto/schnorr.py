"""
Methods for Schnorr signatures
"""

from src.crypto.curve_utils import ORDER, PRIME, generator_exponent, scalar_multiplication, add_points, \
    get_pt_from_x
from src.crypto.hash_functions import tagged_hash_function, HashType
from src.logger import get_logger

logger = get_logger(__name__)

HASHTYPE = HashType.SHA256


def schnorr_signature(private_key: int, message: bytes, auxiliary_bits: bytes):
    # Check that private key is < ORDER
    if private_key >= ORDER:
        raise ValueError("Given private key must be less than number of rational points on the curve")

    # Calculate public key - Negate private_key if necessary
    x, y = generator_exponent(private_key)
    if y % 2 != 0:
        private_key = ORDER - private_key

    # Create private nonce
    aux_rand_hash = tagged_hash_function(encoded_data=auxiliary_bits, tag=b"BIP0340/aux", function_type=HASHTYPE)

    # XOR private key with aux_rand_hash
    nonce_input_value = private_key ^ int.from_bytes(aux_rand_hash, byteorder="big")

    # Create final private nonce
    nonce_input_bytes = nonce_input_value.to_bytes(32, "big") + x.to_bytes(32, "big") + message
    private_nonce_bytes = tagged_hash_function(encoded_data=nonce_input_bytes, tag=b"BIP0340/nonce",
                                               function_type=HASHTYPE)
    private_nonce = int.from_bytes(private_nonce_bytes, byteorder="big") % ORDER

    # Calculate public nonce - Negate private_nonce if necessary
    px, py = generator_exponent(private_nonce)  # curve.multiply_generator(private_nonce)
    if py % 2 != 0:
        private_nonce = ORDER - private_nonce

    # Calculate the challenge
    challenge_input_bytes = px.to_bytes(32, "big") + x.to_bytes(32, "big") + message
    challenge_bytes = tagged_hash_function(encoded_data=challenge_input_bytes, tag=b"BIP0340/challenge",
                                           function_type=HASHTYPE)
    challenge = int.from_bytes(challenge_bytes, byteorder="big") % ORDER

    # Construct signature
    r = px
    s = (private_nonce + challenge * private_key) % ORDER

    # Return 64 byte signature
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_schnorr_signature(public_key_x: int, message: bytes, signature: bytes) -> bool:
    # Verify signature is 64 bytes
    if len(signature) != 64:
        raise ValueError("Given signature is not 64 bytes.")

    # Convenience
    x = public_key_x

    # Verify x value restrictions
    if x > PRIME:
        raise ValueError("Given x coordinate doesn't satisfy value restrictions")

    # Calculate even y point
    public_key = get_pt_from_x(x)  # Will return even y coordinate by default

    # Extract signature parts
    r, s = signature[:32], signature[32:]
    num_r, num_s = int.from_bytes(r, "big"), int.from_bytes(s, "big")

    logger.debug(f"Recovered R: {r.hex()}")
    logger.debug(f"Recovered S: {s.hex()}")

    # Verify signatures values
    errors = {
        "r < p": num_r < PRIME,
        "s < n": num_s < ORDER
    }

    if not all(errors.values()):
        raise ValueError(f"One or more signature values is invalid: {errors}")

    # Calculate the challenge
    challenge_data = num_r.to_bytes(32, "big") + x.to_bytes(32, "big") + message

    # hex_to_bytes(r, hex(x), message.hex())
    challenge_bytes = tagged_hash_function(encoded_data=challenge_data, tag=b"BIP0340/challenge",
                                           function_type=HASHTYPE)
    challenge = int.from_bytes(challenge_bytes, byteorder="big") % ORDER

    # Verify the signature
    point1 = generator_exponent(num_s)
    point2 = scalar_multiplication((ORDER - challenge), public_key)
    point3 = add_points(point1, point2)
    return point3[0] == num_r
