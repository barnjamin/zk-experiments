from util import add, mul, sub, to_elem, pow
from consts import PRIME


class Elem:
    def __init__(self, n: int):
        self.n = n

    def __mul__(self, other: "Elem | int") -> "Elem":
        if type(other) is int:
            return Elem(mul(self.n, other))

        assert isinstance(other, Elem)

        return Elem(mul(self.n, other.n))

    def __add__(self, other: "Elem") -> "Elem":
        return Elem(add(self.n, other.n))

    def __sub__(self, other: "Elem") -> "Elem":
        return Elem(sub(self.n, other.n))

    def __pow__(self, other: "Elem | int") -> "Elem":
        match other:
            case int():
                return Elem(pow(self.n, other))
            case Elem():
                return Elem(pow(self.n, other.n))
            case _:
                raise Exception("??")

    def __neg__(self) -> "Elem":
        return Elem(0) - self

    def __str__(self) -> str:
        return f"Elem({self.n})"

    def __eq__(self, other) -> bool:
        return self.n == other.n

    def inv(self) -> "Elem":
        return Elem.from_int(pow(self.n, PRIME - 2))

    @staticmethod
    def from_int(n: int) -> "Elem":
        return Elem(to_elem(n))


class ExtElem:
    def __init__(self, e: list[Elem]):
        assert len(e) == 4
        self.e = e

    def inv(self) -> "ExtElem":
        a = self.e
        # Compute the multiplicative inverse by looking at `ExtElem` as a composite
        # field and using the same basic methods used to invert complex
        # numbers. We imagine that initially we have a numerator of `1`, and a
        # denominator of `a`. `out = 1 / a`; We set `a'` to be a with the first
        # and third components negated. We then multiply the numerator and the
        # denominator by `a'`, producing `out = a' / (a * a')`. By construction
        # `(a * a')` has `0`s in its first and third elements. We call this
        # number, `b` and compute it as follows.

        b0 = a[0] * a[0] + BETA * (a[1] * (a[3] + a[3]) - a[2] * a[2])
        b2 = a[0] * (a[2] + a[2]) - a[1] * a[1] + BETA * (a[3] * a[3])

        # Now, we make `b'` by inverting `b2`. When we muliply both sizes by `b'`, we
        # get `out = (a' * b') / (b * b')`.  But by construction `b * b'` is in
        # fact an element of `Elem`, call it `c`.

        c = b0 * b0 + BETA * b2 * b2
        # But we can now invert `C` direcly, and multiply by `a' * b'`:
        # `out = a' * b' * inv(c)`
        ic = c.inv()

        # Note: if c == 0 (really should only happen if in == 0), our
        # 'safe' version of inverse results in ic == 0, and thus out
        # = 0, so we have the same 'safe' behavior for ExtElem.  Oh,
        # and since we want to multiply everything by ic, it's
        # slightly faster to pre-multiply the two parts of b by ic (2
        # multiplies instead of 4).

        b0 *= ic
        b2 *= ic
        return ExtElem(
            [
                a[0] * b0 + BETA * a[2] * b2,
                -a[1] * b0 + NBETA * a[3] * b2,
                -a[0] * b2 + a[2] * b0,
                a[1] * b2 - a[3] * b0,
            ]
        )

    def __add__(self, other: "ExtElem") -> "ExtElem":
        return ExtElem([self.e[idx] + other.e[idx] for idx in range(len(self.e))])

    def __sub__(self, other: "ExtElem") -> "ExtElem":
        return ExtElem([self.e[idx] - other.e[idx] for idx in range(len(self.e))])

    def __mul__(self, other: "ExtElem | Elem | int") -> "ExtElem":

        if isinstance(other, Elem):
            return ExtElem([e * other for e in self.e])
        if type(other) is int:
            return ExtElem([e * other for e in self.e])

        assert isinstance(other, ExtElem)

        a = self.e
        b = other.e
        return ExtElem(
            [
                a[0] * b[0] + NBETA * (a[1] * b[3] + a[2] * b[2] + a[3] * b[1]),
                a[0] * b[1] + a[1] * b[0] + NBETA * (a[2] * b[3] + a[3] * b[2]),
                a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + NBETA * (a[3] * b[3]),
                a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0],
            ]
        )

    def __pow__(self, other: Elem | int) -> "ExtElem":

        n: int
        match other:
            case int():
                n = other
            case Elem():
                n = other.n
            case _:
                raise Exception("??")

        tot = ExtElemOne
        x = self
        while n != 0:
            if n % 2 == 1:
                tot *= x
            n = int(n / 2)
            x *= x
        return tot

    def __str__(self) -> str:
        x = ",".join([str(e) for e in self.e])
        return f"ExtElem([{x}])"

    def __eq__(self, other) -> bool:
        return all([self.e[idx] == other.e[idx] for idx in range(len(self.e))])

    @staticmethod
    def from_ints(e: list[int]) -> "ExtElem":
        return ExtElem([Elem.from_int(x) for x in e])

    @staticmethod
    def from_encoded_ints(e: list[int]) -> "ExtElem":
        return ExtElem([Elem(x) for x in e])

    @staticmethod
    def from_subfield(e: Elem) -> "ExtElem":
        return ExtElem([e, Elem(0), Elem(0), Elem(0)])


def poly_eval(coeffs: list[ExtElem], x: ExtElem) -> ExtElem:
    mul_x = ExtElemOne
    tot = ExtElemZero
    for i in range(len(coeffs)):
        tot += coeffs[i] * mul_x
        mul_x = mul_x * x
    return tot


ElemOne = Elem.from_int(1)
ElemZero = Elem(0)

ExtElemOne = ExtElem.from_ints([1, 0, 0, 0])
ExtElemZero = ExtElem.from_encoded_ints([0, 0, 0, 0])

NBETA = Elem.from_int(PRIME - 11)
BETA = Elem.from_int(11)
