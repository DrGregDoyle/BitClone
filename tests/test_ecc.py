"""
Testing the Point and EllipticCurve classes and methods
"""
import random
import secrets

from src.crypto.ecc import EllipticCurve, secp256k1


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
    points = [(2, 2), (2, 9), (3, 1), (3, 10), (4, 5), (4, 6), (6, 4), (6, 7), (7, 1), (7, 10), (8, 1), (8, 10), (9, 1),
              (9, 10), (10, 5), (10, 6)]
    generator = random.choice(points)
    known_order = 12
    known_point = (7, 3)
    inverse_point = (7, 8)
    infinity_point = None
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
    p1 = (2, 2)
    p2 = (2, 9)
    p3 = (3, 1)
    assert test_curve.add_points(p1, p2) == infinity_point
    assert test_curve.add_points(p2, p1) == infinity_point
    assert test_curve.add_points(p1, p3) == known_point
    assert test_curve.add_points(p3, p1) == known_point

    # def test_secp256k1():
    nist_curve = secp256k1()
    random_256_bit_integer = secrets.randbits(256)
    random_point = nist_curve.multiply_generator(random_256_bit_integer)
    (t_x, t_y) = random_point
    inverse_random_point = (t_x, -t_y % nist_curve.p)
    assert nist_curve.scalar_multiplication(nist_curve.order - 1, random_point) == inverse_random_point
