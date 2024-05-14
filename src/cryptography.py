"""
A module for dealing with elliptic curve cryptography (ecc)

"""
# --- IMPORTS --- #
import logging
import sys

from src.utility import is_quadratic_residue, tonelli_shanks

# --- CONSTANTS --- #
log_level = logging.DEBUG

# --- LOGGING --- #
logger = logging.getLogger(__name__)
logger.setLevel(log_level)
handler = logging.StreamHandler(sys.stdout)
logger.addHandler(handler)


# --- CLASSES --- #

class Point:
    """
    A class to handle cryptographic points for use in ecc. We adopt the convention that if either of the initial x or
    y values is equal to None, then this becomes the point at infinity.
    """

    def __init__(self, x=None, y=None):
        poi = (x is None or y is None)
        self.x = x if not poi else None
        self.y = y if not poi else None

    def __repr__(self):
        return f"({self.x},{self.y})"

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

    @property
    def is_point_at_infinity(self) -> bool:
        return True if self.x is None and self.y is None else False

    @property
    def coords(self):
        return self.x, self.y


class EllipticCurve:
    """
    We let E = E(a,b;p) denote the elliptic curve over F_p given by
        y^2 = x^3 + ax + b (mod p).
    """
    MAX_PRIME = pow(2, 19) - 1  # 7th Mersenne prime

    def __init__(self, a: int, b: int, p: int, generator: Point | None = None, order: int | None = None):
        # Curve constants
        self.a = a
        self.b = b
        self.p = p
        self.g = generator
        self.order = order
        if self.order is None and self.p < self.MAX_PRIME:
            self.order = self.get_order()

    def rhs(self, x: int):
        return pow(x, 3) + self.a * x + self.b

    def is_x_on_curve(self, x: int) -> bool:
        '''
        A residue x is on the curve E iff x^3 + ax + b is a quadratic residue modulo p.
        '''
        temp = self.rhs(x)
        return is_quadratic_residue(self.rhs(x), self.p)

    def is_point_on_curve(self, point: Point) -> bool:
        '''
        Returns true if the given point is on the curve, false otherwise
        '''
        # Point at infinity case first
        if point.is_point_at_infinity:
            return True

        # Return True if y^2 = x^3 + ax +b (mod p) and False otherwise
        return (self.rhs(point.x) - pow(point.y, 2)) % self.p == 0

    def find_y_from_x(self, x: int):
        '''
        Using tonelli shanks, we return y such that E(x,y) = 0, if x is on the curve.
        Note that if (x,y) is a point then (x,p-y) will be a point as well.
        '''

        # Verify x is on curve
        try:
            assert self.is_x_on_curve(x), \
                f"The value of x^3 + {self.a}x + {self.b} is not a quadratic residue for x = {x}"
        except AssertionError:
            return None

        # Find the two possible y values
        y = tonelli_shanks(self.rhs(x), self.p)
        neg_y = -y % self.p

        # Create points
        point = Point(x, y)
        neg_point = Point(x, neg_y)

        # Check y values
        try:
            assert self.is_point_on_curve(point)
            assert self.add_points(point, neg_point) is None
        except AssertionError:
            return None

        # Return y
        return y

    # --- Group operations --- #

    def add_points(self, point1: Point | tuple, point2: Point | tuple):
        '''
        Adding points using the elliptic curve addition rules.
        '''
        # Change tuples to points if necessary
        if isinstance(point1, tuple):
            temp_x, temp_y = point1
            point1 = Point(temp_x, temp_y)
        if isinstance(point2, tuple):
            temp_x, temp_y = point2
            point2 = Point(temp_x, temp_y)

        # Verify points exist
        try:
            assert self.is_point_on_curve(point1), f"{point1} is not on the curve."
            assert self.is_point_on_curve(point2), f"{point2} is not on the curve."
        except AssertionError:
            return None

        # Point at infinity cases
        if point1 is None:
            return point2
        if point2 is None:
            return point1

        # Get coordinates
        x1, y1 = point1.coords
        x2, y2 = point2.coords

        # Get slope if it exists
        if x1 == x2:
            if y1 != y2:  # Points are inverses
                return Point(None)
            elif y1 == 0:  # Point is its own inverse when lying on the x-axis
                return Point(None)
            else:  # Points are the same
                m = ((3 * x1 * x1 + self.a) * pow(2 * y1, -1, self.p)) % self.p
        else:  # Points are distinct
            m = ((y2 - y1) * pow(x2 - x1, -1, self.p)) % self.p

        # Use the addition formulas
        x3 = (m * m - x1 - x2) % self.p
        y3 = (m * (x1 - x3) - y1) % self.p
        point = Point(x3, y3)

        # Verify result
        try:
            assert self.is_point_on_curve(point), f"Calculated point {point} is not on the curve. Serious error."
        except AssertionError:
            return None

        # Return sum of points
        return point

    def scalar_multiplication(self, n: int, point: Point | tuple):
        '''
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
        '''

        # Retrieve order if it's None - only for small primes
        if self.order is None:
            self.order = self.get_order()

        # Point at infinity case
        if point is None:
            return None

        # Scalar multiple divides group order
        if n % self.order == 0:
            return None

        # Take residue of n modulo the group order
        n = n % self.order

        # Proceed with algorithm
        bitstring = bin(n)[2:]
        temp_point = point
        for x in range(1, len(bitstring)):
            temp_point = self.add_points(temp_point, temp_point)  # Double regardless of bit
            bit = int(bitstring[x:x + 1], 2)
            if bit == 1:
                temp_point = self.add_points(temp_point, point)  # Add to the doubling if bit == 1

        # Verify results
        try:
            assert self.is_point_on_curve(temp_point)
        except AssertionError:
            return None

        # Return point
        return temp_point

    def get_order(self):
        '''
        We naively calculate the order by iterating over all x in F_p. If x is on the curve we
        obtain y. If y is not zero, then we know (x,y) and (x,p-y) are two points on the curve. Otherwise, (x,
        0) is a point on the curve (on the x-axis). Hence, we sum up these values and add the point at infinity to
        return the order.

        NOTE: This should only be used for small primes.
        '''

        # Get all x values on the curve
        x_vals_on_curve = []
        for x in range(0, self.p):
            if self.is_x_on_curve(x):
                x_vals_on_curve.append(x)
        logger.debug(f"Total number of x-coordinates: {len(x_vals_on_curve)}")
        logger.debug(f"List of x-values on the curve: {x_vals_on_curve}")

        # Extract all x values which have self.rhs(x) == 0
        x_vals_with_zero_y = []
        temp_index = x_vals_on_curve.copy()
        for t in temp_index:
            temp_y = self.rhs(t)
            if temp_y % self.p == 0:
                x_vals_on_curve.remove(t)
                x_vals_with_zero_y.append(t)
        logger.debug(f"Total number of x-coordinates on the axis: {len(x_vals_with_zero_y)}")
        logger.debug(f"List of x-coordinates on the axis: {x_vals_with_zero_y}")

        # Calculate order
        return 2 * len(x_vals_on_curve) + 1 * len(x_vals_with_zero_y) + 1  # Add 1 for point at infinity


# --- MAIN --- #
if __name__ == "__main__":
    # curve = EllipticCurve(a=0, b=7, p=11)
    point = Point(None)
    print(f"POINT: {point}")
