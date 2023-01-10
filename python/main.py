from math import log2
from read_iop import ReadIOP
from merkle import MerkleVerifier
from method import Method
from consts import (
    QUERIES,
    INV_RATE,
    MIN_CYCLES_PO2,
    CHECK_SIZE,
    EXT_SIZE,
)
from util import ROU_REV, ROU_FWD, hash_raw_data, to_elem, mul, pow

from poly_ext import get_def
from fri import fri_eval_taps, fri_verify
from fp import poly_eval, Elem, ExtElem, ElemOne, ElemZero, ExtElemOne, ExtElemZero
from taps import TAPSET, get_register_taps


CIRCUIT_OUTPUT_SIZE = 18
CIRCUIT_MIX_SIZE = 36

CODE_TAP_SIZE = 15
DATA_TAP_SIZE = 212
ACCUM_TAP_SIZE = 36


def verify(seal: list[int], method: Method):

    iop = ReadIOP(CIRCUIT_OUTPUT_SIZE, seal)

    po2 = iop.po2
    size = 1 << po2
    domain = INV_RATE * size

    code_merkle = MerkleVerifier(iop, domain, CODE_TAP_SIZE, QUERIES)

    check_code_merkle(po2, method, code_merkle.root())

    data_merkle = MerkleVerifier(iop, domain, DATA_TAP_SIZE, QUERIES)

    mix = [Elem(e) for e in iop.sample_elements(CIRCUIT_MIX_SIZE)]

    accum_merkle = MerkleVerifier(iop, domain, ACCUM_TAP_SIZE, QUERIES)

    poly_mix = ExtElem.from_encoded_ints(iop.sample_elements(EXT_SIZE))

    check_merkle = MerkleVerifier(iop, domain, CHECK_SIZE, QUERIES)

    _z = iop.sample_elements(EXT_SIZE)
    z = ExtElem.from_encoded_ints(_z)

    back_one = ROU_REV[po2]

    num_taps = len(TAPSET.taps)

    coeff_u = iop.read_field_ext_elem_slice((num_taps + CHECK_SIZE))
    coeff_elems: list[ExtElem] = [
        ExtElem.from_encoded_ints(coeff_u[x * 4 : (x + 1) * 4])
        for x in range(int(len(coeff_u) / 4))
    ]

    hash_u = hash_raw_data(coeff_u)
    iop.commit(hash_u)

    cur_pos: int = 0
    eval_u: list[ExtElem] = []
    for (idx, reg) in get_register_taps():
        for i in range(reg.skip):
            # Make sure its encoded properly
            ml: int = to_elem(pow(back_one, TAPSET.taps[idx + i].back))
            x: ExtElem = ExtElem.from_encoded_ints([mul(ze, ml) for ze in _z])
            fx: ExtElem = poly_eval(coeff_elems[cur_pos : cur_pos + reg.skip], x)

            eval_u.append(fx)

        cur_pos += reg.skip

    assert num_taps == len(eval_u)

    result = compute_poly(eval_u, poly_mix, iop.out, mix)

    check = ExtElem.from_encoded_ints([0, 0, 0, 0])
    remap = [0, 2, 1, 3]
    fp0 = ElemZero
    fp1 = ElemOne
    for i, rmi in enumerate(remap):
        check += (
            coeff_elems[num_taps + rmi + 0] * z**i * ExtElem([fp1, fp0, fp0, fp0])
        )
        check += (
            coeff_elems[num_taps + rmi + 4] * z**i * ExtElem([fp0, fp1, fp0, fp0])
        )
        check += (
            coeff_elems[num_taps + rmi + 8] * z**i * ExtElem([fp0, fp0, fp1, fp0])
        )
        check += (
            coeff_elems[num_taps + rmi + 12] * z**i * ExtElem([fp0, fp0, fp0, fp1])
        )

    three = Elem.from_int(3)
    check *= (ExtElem.from_subfield(three) * z) ** size - ExtElemOne

    assert check == result, "Invalid proof"

    ext_mix = ExtElem.from_encoded_ints(iop.sample_elements(4))

    combo_u = [ExtElemZero] * (TAPSET.tot_combo_backs + 1)
    cur_mix = ExtElemOne
    cur_pos = 0
    tap_mix_pows = []
    for (idx, reg) in get_register_taps():
        for i in range(reg.skip):
            combo_u[TAPSET.combo_begin[reg.combo] + i] += (
                cur_mix * coeff_elems[cur_pos + i]
            )

        tap_mix_pows.append(cur_mix)
        cur_mix *= ext_mix
        cur_pos += reg.skip

    assert len(tap_mix_pows) == TAPSET.reg_count

    check_mix_pows = []
    for _ in range(CHECK_SIZE):
        combo_u[TAPSET.tot_combo_backs] += cur_mix * coeff_elems[cur_pos]
        cur_pos += 1
        check_mix_pows.append(cur_mix)
        cur_mix *= ext_mix

    gen = ROU_FWD[int(log2(domain))]

    def inner(iop: ReadIOP, idx: int) -> ExtElem:
        x = Elem.from_int(pow(gen, idx))
        rows = (
            accum_merkle.verify(iop, idx),
            code_merkle.verify(iop, idx),
            data_merkle.verify(iop, idx),
        )
        check_row = check_merkle.verify(iop, idx)
        res = fri_eval_taps(ext_mix, combo_u, check_row, back_one, x, z, rows)
        return res

    fri_verify(iop, size, inner)

    print("got here? valid proof!")


def compute_poly(
    u: list[ExtElem], poly_mix: ExtElem, out: list[Elem], mix: list[Elem]
) -> ExtElem:
    poly_step_def = get_def()
    return poly_step_def.step(poly_mix, u, (out, mix)).tot


def check_code_merkle(po2: int, method: Method, merkle_root: bytes) -> bool:
    which = po2 - MIN_CYCLES_PO2
    assert which < len(method.table), "Method cycle error"
    assert method.table[which] == merkle_root, "Verify error"
    return True


if __name__ == "__main__":

    with open("../trivial.seal", "rb") as f:
        seal = list(f.read())

    with open("../trivial.method", "rb") as f:
        method = Method.from_bytes(f.read())

    verify(seal, method)
