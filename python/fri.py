from typing import Callable
from math import ceil, log2
from consts import (
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
    hash_raw_data,
    to_elem,
    decode_mont,
)
from merkle import MerkleVerifier
from fp import Elem, ExtElem, ExtElemOne, ExtElemZero, poly_eval, ElemOne
from taps import TAPSET, get_register_taps, TapCache
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
        inv_wk = to_elem(decode_mont(ROU_REV[root_po2]) ** group)
        return (group, fold_eval(data_ext, self.mix * inv_wk))


def reverse_butterfly(io: list[ExtElem], n: int) -> list[ExtElem]:
    half = 1 << (n - 1)

    step = ROU_REV[n]
    cur = ElemOne
    for i in range(half):
        a = io[i]
        b = io[i + half]
        io[i] = a + b
        io[i + half] = (a - b) * cur
        cur *= step

    if n > 1:
        io[half:] = reverse_butterfly(io[half:], n - 1)
        io[:half] = reverse_butterfly(io[:half], n - 1)

    return io


def bit_rev_32(x: int) -> int:
    x = ((x & 0xAAAAAAAA) >> 1) | ((x & 0x55555555) << 1)
    x = ((x & 0xCCCCCCCC) >> 2) | ((x & 0x33333333) << 2)
    x = ((x & 0xF0F0F0F0) >> 4) | ((x & 0x0F0F0F0F) << 4)
    x = ((x & 0xFF00FF00) >> 8) | ((x & 0x00FF00FF) << 8)
    return (x >> 16) | (x << 16)


def bitreverse(io: list[ExtElem]) -> list[ExtElem]:
    n = ceil(log2(len(io)))
    for i in range(len(io)):
        rev_idx = bit_rev_32(i) >> (32 - n)
        if i < rev_idx:
            io[rev_idx], io[i] = io[i], io[rev_idx]

    return io


def fold_eval(io: list[ExtElem], x: ExtElem) -> ExtElem:
    size = len(io)
    N = ceil(log2(len(io)))

    norm = Elem.from_int(size).inv()
    newio = reverse_butterfly(io, N)

    for idx in range(len(newio)):
        newio[idx] = newio[idx] * norm

    newio = bitreverse(newio)
    res = poly_eval(newio, x)
    return res


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
    for _ in range(len(register_taps)):
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
    final_digest = hash_raw_data(final_coeffs)
    iop.commit(final_digest)

    gen = ROU_FWD[ceil(log2(domain))]

    for query_idx in range(QUERIES):
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

        print(f"query {query_idx} passed")

    return ExtElemZero
