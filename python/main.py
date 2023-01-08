from read_iop import ReadIOP
from merkle import MerkleVerifier
from method import Method
from consts import QUERIES, INV_RATE, MIN_CYCLES_PO2, PRIME
from util import (
    to_elem,
    ROU_REV,
    hash_raw_pod,
    wrapped_pow,
    wrapped_mul,
    wrapped_add,
    encode_mont,
    add,
    decode_mont,
    mul,
    swap32,
)
from taps import TAPSET, TapData
import galois as gf  # type: ignore


CIRCUIT_OUTPUT_SIZE = 18
CIRCUIT_MIX_SIZE = 36

CODE_TAP_SIZE = 15
DATA_TAP_SIZE = 212
ACCUM_TAP_SIZE = 36


# Extended field element size
EXT_SIZE = 4
CHECK_SIZE = INV_RATE * EXT_SIZE

NBETA = to_elem(PRIME - 11)


def main():

    with open("../trivial.seal", "rb") as f:
        seal = list(f.read())

    with open("../trivial.method", "rb") as f:
        method = Method.from_bytes(f.read())

    iop = ReadIOP(CIRCUIT_OUTPUT_SIZE, seal)

    po2 = iop.po2
    size = 1 << po2
    domain = INV_RATE * size

    code_merkle = MerkleVerifier(iop, domain, CODE_TAP_SIZE, QUERIES)
    # Assert known val from sample
    assert (
        code_merkle.root().hex()
        == "74c89f832ce09ae9ff2f74f5129425ed4469f8698858fd2793499015206aa9c4"
    )

    check_code_merkle(po2, method, code_merkle.root())

    data_merkle = MerkleVerifier(iop, domain, DATA_TAP_SIZE, QUERIES)

    # Assert known val from sample
    assert (
        data_merkle.root().hex()
        == "36a851ef72541689fd9537c5b3a01c75c66bccffef7871f9757ee664c0ef909d"
    )

    mix = iop.sample_elements(CIRCUIT_MIX_SIZE)
    assert mix[0] == 1374649985

    accum_merkle = MerkleVerifier(iop, domain, ACCUM_TAP_SIZE, QUERIES)
    assert (
        accum_merkle.root().hex()
        == "c0f53b6615c2ce2332f06386b72cd7f300d52684885c694cd903b599c915ba57"
    )

    poly_mix = iop.sample_elements(EXT_SIZE)
    assert poly_mix[0] == 143271204

    check_merkle = MerkleVerifier(iop, domain, CHECK_SIZE, QUERIES)
    assert (
        check_merkle.root().hex()
        == "b5b6727b0e71ff6c699c59f0ceb258805dc427b839f10052229dcecf7ab78d45"
    )

    z = iop.sample_elements(EXT_SIZE)
    assert z[0] == 1298130879

    back_one = ROU_REV[po2]
    assert back_one == 173369915

    num_taps = len(TAPSET.taps)

    coeff_u = iop.read_field_ext_elem_slice((num_taps + CHECK_SIZE))
    coeff_elems = [coeff_u[x * 4 : (x + 1) * 4] for x in range(int(len(coeff_u) / 4))]
    assert coeff_u[0] == 407240978

    hash_u = hash_raw_pod(coeff_u)
    assert (
        hash_u.hex()
        == "1e6142f8513eb63519f504ac6d872b03e56727ad514d99463d13202582cfbb70"
    )
    iop.commit(hash_u)

    ####

    eval_u: list[list[int]] = []

    cur_pos = 0
    for reg in register_taps():
        print(reg)
        for i in range(reg.skip):
            ml = wrapped_pow(back_one, reg.back + i)
            x = [mul(z[i], ml) for i in range(len(z))]
            coeffs = coeff_elems[cur_pos : cur_pos + reg.skip]
            fx = poly_eval(coeffs, x)
            eval_u.append(fx)
        cur_pos += reg.skip

    assert num_taps == len(eval_u), "???"


def register_taps() -> list[TapData]:
    cursor = 0
    taps: list[TapData] = []
    while cursor < len(TAPSET.taps):
        t = TAPSET.taps[cursor]
        taps.append(t)
        cursor += t.skip
    return taps

class Elem:
    def __init__(self, n: int):
        self.n = n

    def __mul__(self, other: "Elem") -> "Elem":
        return Elem(mul(self.n, other.n))

    def __add__(self, other: "Elem") -> "Elem":
        return Elem(add(self.n, other.n))


def mul_e(a: list[Elem], b: list[Elem]) -> list[Elem]:
    return [
        a[0] * b[0] + Elem(NBETA) * (a[1] * b[3] + a[2] * b[2] + a[3] * b[1]),
        a[0] * b[1] + a[1] * b[0] + Elem(NBETA) * (a[2] * b[3] + a[3] * b[2]),
        a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + Elem(NBETA) * (a[3] * b[3]),
        a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0],
    ]


def poly_eval(coeffs, x):
    mul_x = [Elem(q) for q in [1, 0, 0, 0]]
    tot = [Elem(q) for q in [0, 0, 0, 0]]
    x = [Elem(q) for q in x]

    for i in range(len(coeffs)):
        cc = [Elem(q) for q in coeffs[i]]
        product = mul_e(cc, mul_x)
        tot = [tot[idx] + product[idx] for idx in range(4)]
        mul_x = mul_e(mul_x, x)
    return [q.n for q in tot]


def check_code_merkle(po2: int, method: Method, merkle_root: bytes) -> bool:
    which = po2 - MIN_CYCLES_PO2
    assert which < len(method.table), "Method cycle error"
    assert method.table[which] == merkle_root, "Verify error"
    return True


if __name__ == "__main__":
    main()
