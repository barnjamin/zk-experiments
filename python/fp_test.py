from fp import Elem, ExtElem, ExtElemOne


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


def test_pow():
    a = ExtElem.from_encoded_ints([1298130879, 1237127185, 792820356, 669179997])
    i = Elem.from_int(0)
    assert a**i == ExtElem.from_ints([1, 0, 0, 0])


def test_inv():
    e = Elem(607474065)
    assert e.inv() == Elem(1701327315)
    assert e.inv() * e == Elem.from_int(1)

    d = ExtElem.from_encoded_ints([1263613623, 776138736, 1220445565, 1344085924])
    assert d.inv() == ExtElem.from_encoded_ints(
        [206674255, 1748250245, 237184905, 423455910]
    )
