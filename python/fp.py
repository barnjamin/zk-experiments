from util import add, mul, sub, to_elem, encode_mont
from consts import PRIME

NBETA = to_elem(PRIME - 11)


class Elem:
    def __init__(self, n: int):
        self.n = n

    def __mul__(self, other: "Elem") -> "Elem":
        return Elem(mul(self.n, other.n))

    def __add__(self, other: "Elem") -> "Elem":
        return Elem(add(self.n, other.n))

    def __sub__(self, other: "Elem") -> "Elem":
        return Elem(sub(self.n, other.n))

    # def __pow__(self, other: "Elem") -> "Elem":
    #    return Elem(pow(self.n, other.n))


class ExtElem:
    def __init__(self, e: list[Elem]):
        assert len(e) == 4
        self.e = e

    def __add__(self, other: "ExtElem") -> "ExtElem":
        pass

    def __mul__(self, other: "ExtElem") -> "ExtElem":
        a = self.e
        b = other.e
        return ExtElem(
            [
                a[0] * b[0] + Elem(NBETA) * (a[1] * b[3] + a[2] * b[2] + a[3] * b[1]),
                a[0] * b[1] + a[1] * b[0] + Elem(NBETA) * (a[2] * b[3] + a[3] * b[2]),
                a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + Elem(NBETA) * (a[3] * b[3]),
                a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0],
            ]
        )

    def __sub__(self, other: "ExtElem") -> "ExtElem":
        pass

    # def __pow__(self, other: "ExtElem")->"ExtElem":
    #    pass

    @staticmethod
    def from_ints(e: list[int]) -> "ExtElem":
        return ExtElem([Elem(x) for x in e])


ExtElemOne = ExtElem.from_ints([1, 0, 0, 0])
ExtElemZero = ExtElem.from_ints([0, 0, 0, 0])
