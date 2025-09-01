"""
Optimized Elliptic Curve Class with performance improvements
"""
import json
from dataclasses import dataclass
from typing import Optional, Tuple

from .ecc_math import is_quadratic_residue, tonelli_shanks

__all__ = ["EllipticCurve", "Point", "SECP256K1", "add_points", "multiply_generator",
           "scalar_multiplication", "is_point_on_curve", "find_y_from_x"]


# Import optimized math functions


@dataclass(frozen=True)
class Point:
    """Immutable point representation for better memory efficiency"""
    x: Optional[int] = None
    y: Optional[int] = None

    def __post_init__(self):
        """Ensure point at infinity is always (None, None)"""
        if (self.x is None) != (self.y is None):
            raise ValueError("Point at infinity must have both coordinates as None")

    def __bool__(self) -> bool:
        """Point at infinity is falsy"""
        return self.x is not None and self.y is not None

    def __iter__(self):
        """Allow tuple unpacking: x, y = point"""
        return iter((self.x, self.y))

    @property
    def tuple(self):
        return self.x, self.y


class EllipticCurve:
    """Optimized elliptic curve implementation"""

    def __init__(self, a: int, b: int, p: int, order: int, generator: Tuple[int, int] | Point,
                 curve: Optional[str] = None):
        """
        We instantiate an elliptic curve E of the form

            y^2 = x^3 + ax + b (mod p).

        We let E(F_p) denote the corresponding cyclic abelian group, comprised of the rational points of E and the
        point at infinity. The order variable refers to the order of this group. As the group is cyclic,
        it will contain a generator point, which can be specified during instantiation.
        """
        # Verify non-singular
        disc = (4 * pow(a, 3) + 27 * pow(b, 2)) % p
        if disc == 0:
            raise ValueError("Cannot use Singular curve in ECC")

        # Curve values
        self.a = a
        self.b = b
        self.p = p
        self.order = order
        self.generator = Point(*generator) if isinstance(generator, tuple) else generator
        self.curve = curve

        # Cache for precomputed points (optional optimization)
        self._point_cache = {}

        # Precompute some multiples of generator for faster operations
        self._precomputed_generator = self._precompute_generator_multiples()

    def __repr__(self):
        gx, gy = self.generator.x, self.generator.y
        hex_dict = {
            'a': hex(self.a),
            'b': hex(self.b),
            'p': hex(self.p),
            'order': hex(self.order),
            'generator': (hex(gx), hex(gy)),
        }
        if self.curve:
            hex_dict.update({'curve': self.curve})
        return json.dumps(hex_dict)

    def _precompute_generator_multiples(self) -> dict:
        """Precompute powers of 2 times generator for faster scalar multiplication"""
        precomputed = {}
        current = self.generator
        power = 1

        # Precompute G, 2G, 4G, 8G, ... up to reasonable limit
        for i in range(256):  # Covers up to 2^32
            if current:
                precomputed[power] = current
                current = self._double_point(current)
                power <<= 1
            else:
                break

        return precomputed

    def x_terms(self, x: int) -> int:
        """Compute x^3 + ax + b mod p with reduced modular operations"""
        x_mod = x % self.p
        # Use Horner's method if a is non-zero: x(x^2 + a) + b
        if self.a != 0:
            return (x_mod * ((x_mod * x_mod + self.a) % self.p) + self.b) % self.p
        else:
            # For a=0 (like secp256k1): x^3 + b
            return (pow(x_mod, 3, self.p) + self.b) % self.p

    def is_point_on_curve(self, point: Point) -> bool:
        """Returns true if the given point is on the curve"""
        if not point:  # Point at infinity
            return True

        x, y = point.x, point.y
        # Optimize: avoid creating temporary values
        left = (y * y) % self.p
        right = self.x_terms(x)
        return left == right

    def is_x_on_curve(self, x: int) -> bool:
        """Check if x-coordinate is on curve using optimized Legendre symbol"""
        rhs = self.x_terms(x)
        return is_quadratic_residue(rhs, self.p)

    def find_y_from_x(self, x: int) -> int:
        """Find y-coordinate from x using optimized square root"""
        if not self.is_x_on_curve(x):
            raise ValueError(f"Given x coordinate {x} is not on the curve.")

        rhs = self.x_terms(x)

        # Use cached/optimized Tonelli-Shanks
        y = tonelli_shanks(rhs, self.p)

        # Return the smaller y value (lexicographically)
        neg_y = (-y) % self.p
        return min(y, neg_y)

    def _double_point(self, point: Point) -> Point:
        """Optimized point doubling"""
        if not point:
            return Point()  # Point at infinity

        x, y = point.x, point.y

        if y == 0:  # Point is its own inverse
            return Point()

        # Compute slope: m = (3x² + a) / (2y)
        numerator = (3 * x * x + self.a) % self.p
        denominator_inv = pow(2 * y, -1, self.p)
        m = (numerator * denominator_inv) % self.p

        # Compute new coordinates
        x3 = (m * m - 2 * x) % self.p
        y3 = (m * (x - x3) - y) % self.p

        return Point(x3, y3)

    def add_points(self, point1: Point, point2: Point) -> Point:
        """Optimized point addition with early returns"""
        # Handle point at infinity cases first
        if not point1:
            return point2
        if not point2:
            return point1

        x1, y1 = point1.tuple
        x2, y2 = point2.tuple

        # Check if points are the same
        if x1 == x2:
            if y1 == y2:
                return self._double_point(point1)
            else:
                return Point()  # Points are inverses

        # Points are distinct - compute slope
        dx = (x2 - x1) % self.p
        dy = (y2 - y1) % self.p
        dx_inv = pow(dx, -1, self.p)
        m = (dy * dx_inv) % self.p

        # Compute result
        x3 = (m * m - x1 - x2) % self.p
        y3 = (m * (x1 - x3) - y1) % self.p

        return Point(x3, y3)

    def scalar_multiplication(self, n: int, point: Point) -> Point:
        """
        Optimized scalar multiplication using windowing method and precomputed values
        """
        # Point at infinity
        if not point:
            return Point()

        n = n % self.order
        if n == 0:
            return Point()
        if n == 1:
            return point

        # For generator, use precomputed values
        if point == self.generator:
            return self._scalar_mult_generator(n)

        # Binary method with optimizations
        result = Point()  # Point at infinity
        addend = point

        while n > 0:
            if n & 1:  # If bit is set
                result = self.add_points(result, addend)
            addend = self._double_point(addend)
            n >>= 1

        return result

    def _scalar_mult_generator(self, n: int) -> Point:
        """
        Optimized scalar multiplication specifically for the generator.
        We assume 1 < n < ORDER
        """
        result = Point()
        remaining = n

        # Use precomputed powers of 2
        for power, precomputed_point in self._precomputed_generator.items():
            if remaining & power:
                result = self.add_points(result, precomputed_point)
                remaining &= ~power  # Clear this bit

            if remaining == 0:
                break

        return result

    def multiply_generator(self, n: int) -> Point:
        """Multiply generator by scalar n"""
        return self._scalar_mult_generator(n % self.order)


# --- SINGLETON INSTANCE --- #
# Create the singleton instance once at module load time
_secp256k1_params = {
    'a': 0,
    'b': 7,
    'p': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    'order': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    'generator': (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
                  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    'curve': "secp256k1"
}

# Create singleton instance - this happens once when module is imported
SECP256K1 = EllipticCurve(**_secp256k1_params)


# --- CONVENIENCE FUNCTIONS --- #
# These act as a functional interface to the singleton instance

def add_points(point1: Point, point2: Point) -> Point:
    """Add two points on the secp256k1 curve"""
    return SECP256K1.add_points(point1, point2)


def multiply_generator(n: int) -> Point:
    """Multiply the secp256k1 generator by scalar n"""
    return SECP256K1.multiply_generator(n)


def scalar_multiplication(n: int, point: Point) -> Point:
    """Multiply any point by scalar n on secp256k1 curve"""
    return SECP256K1.scalar_multiplication(n, point)


def is_point_on_curve(point: Point) -> bool:
    """Check if point is on secp256k1 curve"""
    return SECP256K1.is_point_on_curve(point)


def find_y_from_x(x: int) -> int:
    """Find y coordinate from x on secp256k1 curve"""
    return SECP256K1.find_y_from_x(x)
