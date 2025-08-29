"""
Testing the Point and EllipticCurve classes and methods
"""
import random
from secrets import randbits

from src.cryptography import Point, EllipticCurve

MIN_RAND = 0
MAX_RAND = 0xffff


def test_point_at_infinity(curve):
    """
    We test aspects of the point at infinity, represented by Point() = (None, None)
    We also verify (None, x) and (x, None) yield value errors when constructed
    """
    # Get point at infinity in two ways
    inf_pt1 = Point()
    inf_pt2 = Point(x=None, y=None)

    # Test equality
    assert inf_pt1 == inf_pt2, "Point at infinity construction mismatch."

    # Test on curve
    assert curve.is_point_on_curve(inf_pt1), "Point at infinity not on curve error"

    # Verify ValueErrors during invalid construction
    try:
        bad_pt1 = Point(x=random.randint(MIN_RAND, MAX_RAND), y=None)
        assert False, "Created point at infinity with one integer coordinate"
    except ValueError as e:
        assert True

    try:
        bad_pt2 = Point(x=None, y=random.randint(MIN_RAND, MAX_RAND))
        assert False, "Created point at infinity with one integer coordinate"
    except ValueError as e:
        assert True


def test_elliptic_curve_functions(curve):
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
    points = [(2, 2), (2, 9), (3, 1), (3, 10), (4, 5), (4, 6), (6, 4), (6, 7), (7, 1), (7, 10), (8, 1), (8, 10),
              (9, 1), (9, 10), (10, 5), (10, 6)]
    generator = Point(*random.choice(points))
    known_order = 12
    known_point = Point(7, 3)
    inverse_point = Point(7, 8)
    infinity_point = Point()
    test_curve = EllipticCurve(a=0, b=7, p=11, order=12, generator=generator)

    # Verify order calculation
    assert test_curve.order == known_order
    assert test_curve.scalar_multiplication(known_order - 1, known_point) == inverse_point

    # Verify scalar multiplication
    temp_point = None
    for x in range(1, known_order):
        assert test_curve.add_points(temp_point, known_point) == test_curve.scalar_multiplication(x, known_point)
        temp_point = test_curve.add_points(temp_point, known_point)

    # Verify point addition
    p1 = Point(2, 2)
    p2 = Point(2, 9)
    p3 = Point(3, 1)
    assert test_curve.add_points(p1, p2) == infinity_point
    assert test_curve.add_points(p2, p1) == infinity_point
    assert test_curve.add_points(p1, p3) == known_point
    assert test_curve.add_points(p3, p1) == known_point

    # def test_secp256k1():

    random_256_bit_integer = randbits(256)
    random_point = curve.multiply_generator(random_256_bit_integer)
    (t_x, t_y) = random_point
    inverse_random_point = Point(t_x, -t_y % curve.p)
    assert curve.scalar_multiplication(curve.order - 1, random_point) == inverse_random_point
