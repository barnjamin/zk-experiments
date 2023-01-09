from fp import Elem, ExtElem, ExtElemZero, ExtElemOne


def test_linear():

    x = ExtElem(
        [Elem.from_int(e) for e in [1880084280, 1788985953, 1273325207, 277471107]]
    )
    c0 = ExtElem(
        [Elem.from_int(e) for e in [1582815482, 2011839994, 589901, 698998108]]
    )
    c1 = ExtElem(
        [Elem.from_int(e) for e in [1262573828, 1903841444, 1738307519, 100967278]]
    )

    mul_expect = ExtElem(
        [Elem.from_int(e) for e in [876029217, 1948387849, 498773186, 1997003991]]
    )
    assert x * c1 == mul_expect

    mul_add_expect = ExtElem(
        [Elem.from_int(e) for e in [445578778, 1946961922, 499363087, 682736178]]
    )
    assert c0 + x * c1 == mul_add_expect


def test_mul():
    a = ExtElem.from_ints([1, 0, 0, 0])
    b = ExtElem.from_encoded_ints([1756890006, 401896608, 614202924, 296483633])
    assert a * b == b

    assert ExtElemOne * b == b
