"""
Provide common utility functions for curve secp256k1
"""
from src.backup.crypto.ecc import secp256k1

SECP256K1 = secp256k1()
ORDER = SECP256K1.order
PRIME = SECP256K1.p

__all__ = ["scalar_multiplication", "generator_exponent", "ORDER", "PRIME", "add_points", "is_x_on_curve",
           "is_pt_on_curve", "get_y_from_x", "get_pt_from_x"]


# --- BOOLEAN FUNCTIONS --- #

def is_x_on_curve(x: int) -> bool:
    """
    Returns True/False depending on if the points is on the curve
    """
    return SECP256K1.is_x_on_curve(x)


def is_pt_on_curve(pt: tuple) -> bool:
    """
    Returns True/False depending on whether the pt is on the curve
    """
    return SECP256K1.is_point_on_curve(pt)


# --- RATIONAL POINTS --- #

def scalar_multiplication(n: int, point: tuple) -> tuple:
    """
    Returns n*point for n an integer and point a rational point
    """
    return SECP256K1.scalar_multiplication(n, point)


def generator_exponent(n: int) -> tuple:
    """
    Return the point associated with g^n, where g is the generator point of the group of rational points
    """
    return SECP256K1.multiply_generator(n)


def add_points(p1: tuple, p2: tuple) -> tuple:
    """
    Returns the corresponding point if both p1 and p2 are on the curve
    """
    if not is_pt_on_curve(p1) or not is_pt_on_curve(p2):
        raise ValueError("One or more points not on curve")
    return SECP256K1.add_points(p1, p2)


def get_y_from_x(x: int) -> int:
    """
    Returns a y value if the x coordinate is on the curve
    """
    if not is_x_on_curve(x):
        raise ValueError("Given x value not on curve")
    return SECP256K1.find_y_from_x(x)


def get_pt_from_x(x: int, parity: int = 0) -> tuple:
    """
    Returns a pt on the curve with parity y-coordinate if x is on the curve. Default is even for ease of use.
    """
    y = get_y_from_x(x)
    y = PRIME - y if y % 2 != (parity % 2) else y
    return x, y
