from read_iop import ReadIOP
from merkle import MerkleVerifier
from method import Method
from consts import QUERIES, INV_RATE, MIN_CYCLES_PO2
from util import (
    ROU_REV,
    hash_raw_pod,
    decode_mont,
    to_elem,
    mul,
    pow,
)

from poly_ext import MixState, get_def

from fp import Elem, ExtElem, ExtElemOne, ExtElemZero
from taps import TAPSET, get_register_taps


CIRCUIT_OUTPUT_SIZE = 18
CIRCUIT_MIX_SIZE = 36

CODE_TAP_SIZE = 15
DATA_TAP_SIZE = 212
ACCUM_TAP_SIZE = 36


# Extended field element size
EXT_SIZE = 4
CHECK_SIZE = INV_RATE * EXT_SIZE


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

    mix = [Elem(e) for e in iop.sample_elements(CIRCUIT_MIX_SIZE)]
    assert mix[0].n == 1374649985

    accum_merkle = MerkleVerifier(iop, domain, ACCUM_TAP_SIZE, QUERIES)
    assert (
        accum_merkle.root().hex()
        == "c0f53b6615c2ce2332f06386b72cd7f300d52684885c694cd903b599c915ba57"
    )

    _poly_mix = iop.sample_elements(EXT_SIZE)
    assert _poly_mix[0] == 143271204
    poly_mix = ExtElem.from_encoded_ints(_poly_mix)

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
    assert coeff_u[0] == 407240978

    coeff_elems: list[ExtElem] = [
        ExtElem.from_encoded_ints(coeff_u[x * 4 : (x + 1) * 4])
        for x in range(int(len(coeff_u) / 4))
    ]

    hash_u = hash_raw_pod(coeff_u)
    assert (
        hash_u.hex()
        == "1e6142f8513eb63519f504ac6d872b03e56727ad514d99463d13202582cfbb70"
    )
    iop.commit(hash_u)

    cur_pos: int = 0
    eval_u: list[ExtElem] = []
    for (idx, reg) in get_register_taps():
        for i in range(reg.skip):
            # Make sure its encoded properly
            ml: int = to_elem(pow(back_one, TAPSET.taps[idx + i].back))
            x: ExtElem = ExtElem.from_encoded_ints([mul(ze, ml) for ze in z])
            fx: ExtElem = poly_eval(coeff_elems[cur_pos : cur_pos + reg.skip], x)

            eval_u.append(fx)

        cur_pos += reg.skip
    assert eval_u[-1].e[0].n == 286370341
    assert num_taps == len(eval_u), "???"

    ###### TODO #####
    result = compute_poly(eval_u, poly_mix, iop.out, mix)
    print([e.n for e in result.tot.e])


def compute_poly(
    u: list[ExtElem], poly_mix: ExtElem, out: list[Elem], mix: list[Elem]
) -> MixState:
    poly_step_def = get_def()
    return poly_step_def.step(poly_mix, u, (out, mix))


def poly_eval(coeffs: list[ExtElem], x: ExtElem) -> ExtElem:
    mul_x = ExtElemOne
    tot = ExtElemZero
    for i in range(len(coeffs)):
        tot += coeffs[i] * mul_x
        mul_x = mul_x * x
    return tot


def check_code_merkle(po2: int, method: Method, merkle_root: bytes) -> bool:
    which = po2 - MIN_CYCLES_PO2
    assert which < len(method.table), "Method cycle error"
    assert method.table[which] == merkle_root, "Verify error"
    return True


if __name__ == "__main__":
    main()
