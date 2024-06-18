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


class EllipticCurve:
    """
    We let E = E(a,b;p) denote the elliptic curve over F_p given by
        y^2 = x^3 + ax + b (mod p).
    """
    MAX_PRIME = pow(2, 19) - 1  # 7th Mersenne prime

    def __init__(self, a: int, b: int, p: int, generator: tuple | None = None, order: int | None = None):
        # Curve constants
        self.a = a
        self.b = b
        self.p = p
        self.g = generator
        self.order = order
        if self.order is None and self.p < self.MAX_PRIME:
            self.order = self.get_order()

    def rhs(self, x: int):
        return (pow(x, 3) + self.a * x + self.b) % self.p

    def is_x_on_curve(self, x: int) -> bool:
        """
        A residue x is on the curve E iff x^3 + ax + b is a quadratic residue modulo p.
        """
        return is_quadratic_residue(self.rhs(x), self.p)

    def is_point_on_curve(self, pt: tuple | None) -> bool:
        """
        Returns true if the given point is on the curve, false otherwise
        """
        # Point at infinity case first
        if pt is None:
            return True

        # Verify tuple
        try:
            assert isinstance(pt, tuple)
        except AssertionError:
            logger.error(f"Given point {pt} is not a tuple. Enter a point of the form (x,y).")

        # Return True if y^2 = x^3 + ax +b (mod p) and False otherwise
        x, y = pt
        return (self.rhs(x) - pow(y, 2)) % self.p == 0

    def get_y_from_x(self, x: int):
        """
        Using tonelli shanks, we return y such that E(x,y) = 0, if x is on the curve.
        Note that if (x,y) is a point then (x,p-y) will be a point as well.
        """

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
        pt = (x, y)
        neg_pt = (x, neg_y)

        # Check y values
        try:
            assert self.is_point_on_curve(pt)
            assert self.add_points(pt, neg_pt) is None
        except AssertionError:
            return None

        # Return y
        return y

    # --- Group operations --- #

    def add_points(self, point1: tuple | None, point2: tuple | None):
        """
        Adding points using the elliptic curve addition rules.
        """
        # Point at infinity cases
        if point1 is None:
            return point2
        if point2 is None:
            return point1

        # Verify points exist
        try:
            assert self.is_point_on_curve(point1), f"{point1} is not on the curve."
            assert self.is_point_on_curve(point2), f"{point2} is not on the curve."
        except AssertionError:
            return None

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
        point = x3, y3

        # Verify result
        try:
            assert self.is_point_on_curve(point), f"Calculated point {point} is not on the curve. Serious error."
        except AssertionError:
            return None

        # Return sum of points
        return point

    def scalar_multiplication(self, n: int, pt: tuple | None):
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

        # Retrieve order if it's None - only for small primes
        if self.order is None:
            self.order = self.get_order()

        # Point at infinity case
        if pt is None:
            return None

        # Scalar multiple divides group order
        if n % self.order == 0:
            return None

        # Take residue of n modulo the group order
        n = n % self.order

        # Proceed with algorithm
        bitstring = bin(n)[2:]
        temp_pt = pt
        for x in range(1, len(bitstring)):
            temp_pt = self.add_points(temp_pt, temp_pt)  # Double regardless of bit
            bit = int(bitstring[x:x + 1], 2)
            if bit == 1:
                temp_pt = self.add_points(temp_pt, pt)  # Add to the doubling if bit == 1

        # Verify results
        try:
            assert self.is_point_on_curve(temp_pt)
        except AssertionError:
            return None

        # Return point
        return temp_pt

    def get_order(self):
        """
        We naively calculate the order by iterating over all x in F_p. If x is on the curve we
        obtain y. If y is not zero, then we know (x,y) and (x,p-y) are two points on the curve. Otherwise, (x,
        0) is a point on the curve (on the x-axis). Hence, we sum up these values and add the point at infinity to
        return the order.

        NOTE: This should only be used for small primes.
        """

        sum = 1  # Start with point of infinity
        for x in range(0, self.p):
            if self.is_x_on_curve(x):  # If x is on the curve
                y = self.get_y_from_x(x)  # Find corresponding y
                if y == 0:
                    sum += 1  # Only 1 pt if x is on the y-axis
                else:
                    sum += 2  # Symmetric points if y is non-zero
        return sum

    def get_list_of_points(self):
        """
        Used for debugging
        :return:
        """
        if self.order is None:
            return []
        point_list = [None]
        for x in range(self.p):
            if self.is_x_on_curve(x):
                y = self.get_y_from_x(x)  # Find corresponding y
                if y == 0:
                    point_list.append((x, y))
                else:
                    neg_y = -y % self.p
                    point_list.extend([(x, y), (x, neg_y)])
        return point_list


class SECP256K1(EllipticCurve):
    A = 0
    B = 7
    P = pow(2, 256) - pow(2, 32) - pow(2, 9) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 4) - 1
    GENERATOR = (
        55066263022277343669578718895168534326250603453777594175500187360389116729240,  # G_x
        32670510020758816978083085130507043184471273380659243275938904335757337482424  # G_y
    )
    ORDER = 115792089237316195423570985008687907852837564279074904382605163141518161494337

    def __init__(self):
        super().__init__(self.A, self.B, self.P, self.GENERATOR, self.ORDER)


# --- TESTING --- #
if __name__ == "__main__":
    test_curve = EllipticCurve(
        a=7,
        b=13,
        p=17
    )
    list_of_points = test_curve.get_list_of_points()
    print(f"Calculated order: {test_curve.order}")
    print(f"List of point: {list_of_points}")
    print(f"Number of points + 1: {len(list_of_points)}")

    for known_pt in list_of_points:
        print(f"Initial point: {known_pt}")
        temp_pt = None
        for y in range(test_curve.order):
            temp_pt = test_curve.add_points(temp_pt, known_pt)
            scalar_multiple = test_curve.scalar_multiplication(y + 1, known_pt)
            print(f"Temp point after {y} iterations: {temp_pt}")
            print(f"Scalar multiplication using {y + 1} multiplier: {scalar_multiple}")
