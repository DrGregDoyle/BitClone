"""
Testing the Point and EllipticCurve classes and methods
"""
from src.cryptography import Point


def test_infinity_point():
    point_at_infinity_1 = Point()
    point_at_infinity_2 = Point(x=1)
    point_at_infinity_3 = Point(y=1)
    point_at_infinity_4 = Point(x=None, y=None)

    assert point_at_infinity_1.is_point_at_infinity
    assert point_at_infinity_2.is_point_at_infinity
    assert point_at_infinity_3.is_point_at_infinity
    assert point_at_infinity_4.is_point_at_infinity
