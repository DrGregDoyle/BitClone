"""
Elliptic Curve Class

NIST Elliptic Curves - See https://www.secg.org/sec2-v2.pdf for constants.
All groups of rational points have prime order, hence all curves are suitable for use in ECDSA.
"""
import json
import secrets

from src.crypto.ecc_math import tonelli_shanks, legendre_symbol


class EllipticCurve:

    def __init__(self, a: int, b: int, p: int, order: int, generator: tuple):
        """
        We instantiate an elliptic curve E of the form

            y^2 = x^3 + ax + b (mod p).

        We let E(F_p) denote the corresponding cyclic abelian group, comprised of the rational points of E and the
        point at infinity. The order variable refers to the order of this group. As the group is cyclic,
        it will contain a generator point, which can be specified during instantiation.

        """
        # Get curve values
        self.a = a
        self.b = b
        self.p = p

        # Get group values
        self.order = order
        self.generator = generator

    def __repr__(self):
        gx, gy = self.generator
        hex_dict = {
            'a': hex(self.a),
            'b': hex(self.b),
            'p': hex(self.p),
            'order': hex(self.order),
            'generator': (hex(gx), hex(gy))
        }
        return json.dumps(hex_dict)

    # --- Right Hand Side --- #

    def x_terms(self, x: int) -> int:
        """Compute x^3 + ax + b mod p."""
        return (pow(x, 3, self.p) + self.a * x + self.b) % self.p

    # --- Points on curve --- #

    def random_point(self) -> tuple:
        """
        Returns a cryptographically secure random point on the curve.
        """
        # Find a random x-coordinate that is on the curve
        x = next(
            x for x in (secrets.randbelow(self.p - 1) for _ in iter(int, 1))
            if self.is_x_on_curve(x)
        )
        # Compute corresponding y-coordinate
        return x, self.find_y_from_x(x)

    def is_point_on_curve(self, point: tuple) -> bool:
        """
        Returns true if the given point is on the curve, false otherwise
        """
        # Point at infinity case first
        if point is None:
            return True

        # Return True if y^2 = x^3 + ax +b (mod p) and False otherwise
        x, y = point
        return (self.x_terms(x) - pow(y, 2)) % self.p == 0

    def is_x_on_curve(self, x: int) -> bool:
        """
        A residue x is on the curve E iff x^3 + ax + b is a quadratic residue modulo p.
        This includes the trivial case x^3 + ax + b = 0 (mod p). Hence, by Euler's criterion, if
            ((x^3+ax+b) | p) != 1 (mod p),
        then x is a point on the curve.
        """
        return legendre_symbol(self.x_terms(x), self.p) != -1

    def find_y_from_x(self, x: int):
        """
        Using Tonelli-Shanks, return the smaller y such that E(x, y) = 0 if x is on the curve.
        Note that if (x, y) is a point, then (x, p-y) is also a point.
        """

        # Verify x is on curve
        if not self.is_x_on_curve(x):
            raise ValueError(f"Given x coordinate {x} is not on the curve.")

        # Find the two possible y values
        y = tonelli_shanks(self.x_terms(x), self.p)
        neg_y = -y % self.p

        # Get two points for convenience
        p1, p2 = (x, y), (x, neg_y)

        # Check y values
        verification_list = [
            self.is_point_on_curve(p1),
            self.is_point_on_curve(p2),
            self.add_points(p1, p2) is None
        ]
        if not all(verification_list):
            raise ValueError(f"SERIOUS ERROR: Calculated y value(s) not on curve: {p1}, {p2}")

        # Return y
        return min(y, neg_y)

    # --- Group operations --- #

    def add_points(self, point1: tuple, point2: tuple):
        """
        Adding points using the elliptic curve addition rules.
        """

        # Verify points exist
        points = [point1, point2]
        errors = {f"point{i + 1}": self.is_point_on_curve(p) for i, p in enumerate(points)}

        if not all(errors.values()):
            raise ValueError(f"One or more points are not on the curve: {errors}")

        # Point at infinity cases
        if point1 is None:
            return point2
        if point2 is None:
            return point1

        # Get coordinates
        x1, y1 = point1
        x2, y2 = point2

        # Get slope if it exists
        if x1 == x2:
            if y1 != y2:  # Points are inverses
                return None
            elif y1 == 0:  # Point is its own inverse when lying on the x-axis
                return None
            else:  # Points are the same
                m = ((3 * x1 * x1 + self.a) * pow(2 * y1, -1, self.p)) % self.p
        else:  # Points are distinct
            m = ((y2 - y1) * pow(x2 - x1, -1, self.p)) % self.p

        # Use the addition formulas
        x3 = (m * m - x1 - x2) % self.p
        y3 = (m * (x1 - x3) - y1) % self.p
        point = (x3, y3)

        # Verify result
        if not self.is_point_on_curve(point):
            raise ValueError("Serious error. Calculated point not on curve.")

        # Return sum of points
        return point

    def scalar_multiplication(self, n: int, point: tuple):
        """
        We use the double-and-add algorithm to add a point P with itself n times.

        Algorithm:
        ---------
        Break n into a binary representation (big-endian).
        Then iterate over each bit in the representation as follows:
            1) If it's the first bit, ignore;
            2) double the previous result (starting with P)
            3) if the bit = 1, add a copy of P to the result.

        Ex: n = 26. Binary representation = 11010
            bit     | action        | result
            --------------------------------
            1       | ignore        | P
            1       | double/add    | 2P + P = 3P
            0       | double        | 6P
            1       | double/add    | 12P + P = 13P
            0       | double        | 26P
        """
        # Point at infinity case
        if point is None:
            return None

        # Take residue of n modulo the group order
        n = n % self.order

        # Handle zero residue case
        if n == 0:
            return None

        # Initialize result to point at infinity and temp_point to the given point
        result = None
        temp_point = point
        # Iterate over the bits of n, from least significant to most significant
        while n > 0:
            # If the least significant bit is 1, add temp_point to result
            if n & 1:
                result = self.add_points(result, temp_point)

            # Double temp_point
            temp_point = self.add_points(temp_point, temp_point)

            # Right-shift n to process the next bit
            n >>= 1

        # Verify results
        if not self.is_point_on_curve(result):
            raise ValueError("Serious error. Calculated point not on curve.")

        return result

    def multiply_generator(self, n: int):
        return self.scalar_multiplication(n, self.generator)


# --- NIST CURVES --- #
def secp192k1():
    # Constants
    a = 0x0
    b = 0x3
    p = pow(2, 192) - pow(2, 32) - pow(2, 12) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 3) - 1
    order = 0xfffffffffffffffffffffffe26f2fc170f69466a74defd8d
    generator = (0xdb4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d, 0x9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d)

    # Return curve object
    return EllipticCurve(a, b, p, order, generator)


def secp192r1():
    # Constants
    a = 0xfffffffffffffffffffffffffffffffefffffffffffffffc
    b = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
    p = pow(2, 192) - pow(2, 64) - 1
    order = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831
    generator = (0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012, 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811)

    # Return curve object
    return EllipticCurve(a, b, p, order, generator)


def secp224k1():
    # Constants
    a = 0x0
    b = 0x5
    p = pow(2, 224) - pow(2, 32) - pow(2, 12) - pow(2, 11) - pow(2, 9) - pow(2, 7) - pow(2, 4) - pow(2, 1) - 1
    order = 0x010000000000000000000000000001dce8d2ec6184caf0a971769fb1f7
    generator = (
        0xa1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c,
        0x7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5)

    # Return curve object
    return EllipticCurve(a, b, p, order, generator)


def secp224r1():
    # Constants
    a = 0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe
    b = 0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4
    p = pow(2, 224) - pow(2, 96) + 1
    order = 0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d
    generator = (
        0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21,
        0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34)

    # Return curve object
    return EllipticCurve(a, b, p, order, generator)


def secp256k1():
    # Constants
    a = 0
    b = 7
    p = pow(2, 256) - pow(2, 32) - pow(2, 9) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 4) - 1
    order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
    generator = (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
                 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)

    # Return curve object
    return EllipticCurve(a, b, p, order, generator)


def secp256r1():
    # Constants
    a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
    b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    p = pow(2, 224) * (pow(2, 32) - 1) + pow(2, 192) + pow(2, 96) - 1
    order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    generator = (
        0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

    # Return curve object
    return EllipticCurve(a, b, p, order, generator)


def secp384r1():
    # Constants
    a = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc
    b = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef
    p = pow(2, 384) - pow(2, 128) - pow(2, 96) + pow(2, 32) - 1
    order = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973
    generator = (
        0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
        0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f)

    # Return curve object
    return EllipticCurve(a, b, p, order, generator)


def secp521r1():
    # Constants
    a = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc  # noqa: E501
    b = 0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00  # noqa: E501
    p = pow(2, 521) - 1  # 13th Mersenne prime
    order = \
        0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409  # noqa: E501
    generator = (
        0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
        # noqa: E501
        0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650)  # noqa: E501

    # Return curve object
    return EllipticCurve(a, b, p, order, generator)
