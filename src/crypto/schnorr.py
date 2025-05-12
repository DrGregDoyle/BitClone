"""
Methods for Schnorr signatures
"""

from src.crypto.ecc import secp256k1
from src.crypto.hash_functions import tagged_hash_function, HashType
from src.logger import get_logger

logger = get_logger(__name__)

HASHTYPE = HashType.SHA256


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

    # Create private nonce
    aux_rand_hash = tagged_hash_function(encoded_data=auxiliary_bits, tag=b"BIP0340/aux", function_type=HASHTYPE)

    # XOR private key with aux_rand_hash
    nonce_input_value = private_key ^ int.from_bytes(aux_rand_hash, byteorder="big")

    # Create final private nonce
    nonce_input_bytes = nonce_input_value.to_bytes(32, "big") + x.to_bytes(32, "big") + message
    private_nonce_bytes = tagged_hash_function(encoded_data=nonce_input_bytes, tag=b"BIP0340/nonce",
                                               function_type=HASHTYPE)
    private_nonce = int.from_bytes(private_nonce_bytes, byteorder="big") % n

    # Calculate public nonce - Negate private_nonce if necessary
    px, py = curve.multiply_generator(private_nonce)
    if py % 2 != 0:
        private_nonce = n - private_nonce

    # Calculate the challenge
    challenge_input_bytes = px.to_bytes(32, "big") + x.to_bytes(32, "big") + message
    challenge_bytes = tagged_hash_function(encoded_data=challenge_input_bytes, tag=b"BIP0340/challenge",
                                           function_type=HASHTYPE)
    challenge = int.from_bytes(challenge_bytes, byteorder="big") % n

    # Construct signature
    r = px
    s = (private_nonce + challenge * private_key) % n

    # Return 64 byte signature
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_schnorr_signature(public_key_x: int, message: bytes, signature: bytes) -> bool:
    # Verify signature is 64 bytes
    if len(signature) != 64:
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
    r, s = signature[:32], signature[32:]
    num_r, num_s = int.from_bytes(r, "big"), int.from_bytes(s, "big")

    logger.debug(f"Recovered R: {r.hex()}")
    logger.debug(f"Recovered S: {s.hex()}")

    # Verify signatures values
    errors = {
        "r < p": num_r < p,
        "s < n": num_s < n
    }

    if not all(errors.values()):
        raise ValueError(f"One or more signature values is invalid: {errors}")

    # Calculate the challenge
    challenge_data = num_r.to_bytes(32, "big") + x.to_bytes(32, "big") + message

    # hex_to_bytes(r, hex(x), message.hex())
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
