from read_iop import ReadIOP
from merkle import MerkleVerifier
from method import Method
from consts import QUERIES, INV_RATE, MIN_CYCLES_PO2, PRIME
from util import (
    to_elem,
    ROU_REV,
    hash_raw_pod,
    generate_hash,
    u8_to_u32,
    swap_endian,
)
from sha256 import IV


CIRCUIT_OUTPUT_SIZE = 18
CIRCUIT_MIX_SIZE = 36

CODE_TAP_SIZE = 15
DATA_TAP_SIZE = 212
ACCUM_TAP_SIZE = 36

NUM_TAPS = 781

# Extended field element size
EXT_SIZE = 4
CHECK_SIZE = INV_RATE * EXT_SIZE


def main():

    dummy = bytearray([0] * 64)
    result = u8_to_u32(generate_hash(dummy, compress_only=True, initial_state=IV))
    print(swap_endian(result))
    # matches
    # [3663108286, 398046313, 1647531929, 2006957770, 2363872401, 3235013187, 3137272298, 406301144]

    result = u8_to_u32(generate_hash(dummy, compress_only=True, initial_state=result))
    print(swap_endian(result))
    # doesnt match
    # [1753322530, 427712285, 3703720195, 2823132263, 2087222896, 476200146, 2194495960, 3856981803]

    return

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

    mix = sample_random_elements(iop, CIRCUIT_MIX_SIZE)
    assert mix[0] == 1374649985

    accum_merkle = MerkleVerifier(iop, domain, ACCUM_TAP_SIZE, QUERIES)
    assert (
        accum_merkle.root().hex()
        == "c0f53b6615c2ce2332f06386b72cd7f300d52684885c694cd903b599c915ba57"
    )

    poly_mix = sample_random_elements(iop, EXT_SIZE)
    assert poly_mix[0] == 143271204

    check_merkle = MerkleVerifier(iop, domain, CHECK_SIZE, QUERIES)
    assert (
        check_merkle.root().hex()
        == "b5b6727b0e71ff6c699c59f0ceb258805dc427b839f10052229dcecf7ab78d45"
    )

    z = sample_random_elements(iop, EXT_SIZE)
    assert z[0] == 1298130879

    back_one = ROU_REV[po2]
    assert back_one == 173369915

    num_taps = NUM_TAPS

    # TODO: This does _not_ produce a list of lists since we hash it and want u8s anyway
    coeff_u = iop.read_field_elem_slice(num_taps + CHECK_SIZE)
    # coeff_u = [
    #    _coeff_u[x*4:(x+1)*4]
    #    for x in range(int(len(_coeff_u)/4))
    # ]
    assert coeff_u[0] == 407240978

    hash_u = hash_raw_pod(coeff_u)
    print(hash_u.hex())
    # assert (
    #    hash_u.hex()
    #    == "1e6142f8513eb63519f504ac6d872b03e56727ad514d99463d13202582cfbb70"
    # )

    # eval_u = [[0]*4]*num_taps


def sample(iop: ReadIOP):
    val = 0
    for _ in range(6):
        val <<= 32
        val %= 2**64
        val += iop.rng.next_u32()
        val %= PRIME
    return val


def sample_random_elements(iop: ReadIOP, num: int):
    return [to_elem(sample(iop)) for _ in range(num)]


def check_code_merkle(po2: int, method: Method, merkle_root: bytes) -> bool:
    which = po2 - MIN_CYCLES_PO2
    assert which < len(method.table), "Method cycle error"
    assert method.table[which] == merkle_root, "Verify error"
    return True


if __name__ == "__main__":
    main()
