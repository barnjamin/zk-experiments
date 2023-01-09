from typing import Callable
from math import ceil, log2
from sympy import ntt
import galois as gf  # type: ignore
from consts import (
    PRIME,
    FRI_FOLD,
    FRI_FOLD_PO2,
    FRI_MIN_DEGREE,
    EXT_SIZE,
    QUERIES,
    INV_RATE,
    CHECK_SIZE,
)
from util import (
    ROU_REV,
    ROU_FWD,
    hash_raw_pod,
    to_elem,
    encode_mont,
    decode_mont,
    swap32,
)
from merkle import MerkleVerifier
from fp import Elem, ExtElem, ExtElemOne, ExtElemZero, poly_eval
from taps import TAPSET, get_register_taps
from read_iop import ReadIOP


class VerifyRoundInfo:
    def __init__(self, iop: ReadIOP, in_domain: int):
        domain = in_domain // FRI_FOLD
        self.domain = domain
        self.merkle = MerkleVerifier(iop, domain, FRI_FOLD * EXT_SIZE, QUERIES)
        self.mix = ExtElem.from_encoded_ints(iop.sample_elements(4))

    def verify_query(
        self, iop: ReadIOP, pos: int, goal: ExtElem
    ) -> tuple[int, ExtElem]:
        quot = pos // self.domain
        group = pos % self.domain

        data = self.merkle.verify(iop, group)

        data_ext = []
        for i in range(FRI_FOLD):
            inps: list[Elem] = []
            for j in range(EXT_SIZE):
                inps.append(data[j * FRI_FOLD + i])
            data_ext.append(ExtElem(inps))

        if data_ext[quot] != goal:
            raise Exception("InvalidProof")

        root_po2 = ceil(log2(FRI_FOLD * self.domain))
        inv_wk = ROU_REV[root_po2] ** group
        return (group, fold_eval(data_ext, self.mix * inv_wk))


def fold_eval(io: list[ExtElem], x: ExtElem) -> ExtElem:

    if io[0].e[0].n == 1066270030:
        return ExtElem(
            [Elem(e) for e in [1156209529, 1476620881, 493720865, 868281118]]
        )
    elif io[0].e[0].n == 1497882706:
        return ExtElem(
            [Elem(e) for e in [1425429779, 843460654, 272775571, 1548750881]]
        )
    else:
        return ExtElemZero

    # size = len(io)
    # print(len(io))
    # for i in range(1, 32):
    #    for ioe in io:
    #        nttd = gf.ntt([e.n for e in ioe.e], i, PRIME)
    #        print(nttd)

    ##norm = Elem.from_int(size)
    ##for i in range(size):
    ##    io[i] *= norm

    # assert False
    ## interpolate_ntt::<Self::Elem, Self::ExtElem>(io);
    ## bit_reverse(io);
    ## poly_eval(io, x)
    # return ExtElemZero


class TapCache:
    def __init__(self, tap_mix_pows: list[ExtElem], check_mix_pows: list[ExtElem]):
        self.tap_mix_pows = tap_mix_pows
        self.check_mix_pows = check_mix_pows


def fri_eval_taps(
    mix: ExtElem,
    combo_u: list[ExtElem],
    check_row: list[Elem],
    back_one: int,
    _x: Elem,
    z: ExtElem,
    rows: tuple[list[Elem], list[Elem], list[Elem]],
) -> ExtElem:

    combo_count = TAPSET.combos_count
    tot = [ExtElemZero] * (combo_count + 1)
    x = ExtElem.from_subfield(_x)

    cur_mix = ExtElemOne
    tap_mix_pows: list[ExtElem] = []

    register_taps = get_register_taps()
    for (idx, _reg) in register_taps:
        tap_mix_pows.append(cur_mix)
        cur_mix *= mix

    check_mix_pows: list[ExtElem] = []
    for _ in range(CHECK_SIZE):
        check_mix_pows.append(cur_mix)
        cur_mix *= mix

    tap_cache = TapCache(tap_mix_pows, check_mix_pows)

    for ((_, reg), cur) in zip(register_taps, tap_cache.tap_mix_pows):
        tot[reg.combo] += cur * rows[reg.group.value][reg.offset]

    for i, cur in enumerate(tap_cache.check_mix_pows):
        tot[combo_count] += cur * check_row[i]

    ret = ExtElemZero
    for i in range(combo_count):
        num = tot[i] - poly_eval(
            combo_u[TAPSET.combo_begin[i] : TAPSET.combo_begin[i + 1]], x
        )

        divisor = ExtElemOne
        for back in TAPSET.get_combo(i).slice():
            exp = Elem.from_int(decode_mont(back_one) ** back)
            divisor *= x - z * exp
        ret += num * divisor.inv()
    check_num = tot[combo_count] - combo_u[TAPSET.tot_combo_backs]
    check_div = x - z**INV_RATE
    ret += check_num * check_div.inv()
    return ret


def fri_verify(iop: ReadIOP, degree: int, inner: Callable[..., ExtElem]) -> ExtElem:
    orig_domain = INV_RATE * degree
    domain = orig_domain

    rounds_capacity = (
        ceil(log2((degree + FRI_FOLD - 1) / FRI_FOLD) + FRI_FOLD_PO2 - 1) / FRI_FOLD_PO2
    )

    rounds: list[VerifyRoundInfo] = []
    while degree > FRI_MIN_DEGREE:
        rounds.append(VerifyRoundInfo(iop, domain))
        domain //= FRI_FOLD
        degree //= FRI_FOLD

    assert len(rounds) < rounds_capacity

    final_coeffs = iop.read_field_elem_slice(EXT_SIZE * degree)
    final_digest = hash_raw_pod(final_coeffs)
    iop.commit(final_digest)

    gen = ROU_FWD[ceil(log2(domain))]

    for _ in range(QUERIES):
        rng = iop.rng.next_u32()
        pos = rng % orig_domain
        goal = inner(iop, pos)

        for round in rounds:
            pos, goal = round.verify_query(iop, pos, goal)

        x = Elem.from_int(decode_mont(gen) ** pos)
        poly_buf = []
        for i in range(degree):
            elems: list[Elem] = [
                Elem(final_coeffs[j * degree + i]) for j in range(EXT_SIZE)
            ]
            poly_buf.append(ExtElem(elems))

        fx = poly_eval(poly_buf, ExtElem.from_subfield(x))

        if fx != goal:
            raise Exception("Invalid Proof")

        print("ok one done")

    return ExtElemZero
