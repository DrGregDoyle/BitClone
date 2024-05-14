"""
Testing the Point and EllipticCurve classes and methods
"""
from src.cryptography import Point, EllipticCurve


def test_infinity_point():
    point_at_infinity_1 = Point()
    point_at_infinity_2 = Point(x=1)
    point_at_infinity_3 = Point(y=1)
    point_at_infinity_4 = Point(x=None, y=None)

    assert point_at_infinity_1.is_point_at_infinity
    assert point_at_infinity_2.is_point_at_infinity
    assert point_at_infinity_3.is_point_at_infinity
    assert point_at_infinity_4.is_point_at_infinity


def test_elliptic_curve_functions():
    """
    We use the values of the known elliptic curve:
        y^2 = x^3 + 7 (mod 11)

    order = 17
    points = {
        (2,2), (2,9), (3,1), (3,10),
        (4,5), (4,6), (6,4), (6,7),
        (7,1), (7,10), (8,1), (8,10),
        (9,1), (9,10), (10,5), (10,6)
    } and the point at infinity.
    (2,2) + (2,9) = point at infinity
    (2,2) + (3,1) = (7.3)
    """
    KNOWN_ORDER = 12
    KNOWN_POINT = Point(7, 3)
    INFINITY_POINT = Point(None)
    test_curve = EllipticCurve(a=0, b=7, p=11)

    # Verify order calculation
    assert test_curve.order == KNOWN_ORDER

    # Verify point addition
    p1 = Point(2, 2)
    p2 = Point(2, 9)
    p3 = Point(3, 1)
    assert test_curve.add_points(p1, p2) == INFINITY_POINT
    assert test_curve.add_points(p2, p1) == INFINITY_POINT
    assert test_curve.add_points(p1, p3) == KNOWN_POINT
    assert test_curve.add_points(p3, p1) == KNOWN_POINT
