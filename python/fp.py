from util import add, mul, sub, to_elem, pow
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

    def __pow__(self, other: "Elem | int") -> "Elem":
        match other:
            case int():
                return Elem(pow(self.n, other))
            case Elem():
                return Elem(pow(self.n, other.n))
            case _:
                raise Exception("??")

    def __str__(self) -> str:
        return f"Elem({self.n})"

    def __eq__(self, other) -> bool:
        return self.n == other.n

    @staticmethod
    def from_int(n: int) -> "Elem":
        return Elem(to_elem(n))


class ExtElem:
    def __init__(self, e: list[Elem]):
        assert len(e) == 4
        self.e = e

    def __add__(self, other: "ExtElem") -> "ExtElem":
        return ExtElem([self.e[idx] + other.e[idx] for idx in range(len(self.e))])

    def __sub__(self, other: "ExtElem") -> "ExtElem":
        return ExtElem([self.e[idx] - other.e[idx] for idx in range(len(self.e))])

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

    def __div__(self, other: "ExtElem") -> "ExtElem":
        raise Exception("not implemented")

    def __truediv__(self, other: "ExtElem") -> "ExtElem":
        raise Exception("not implemented")

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
