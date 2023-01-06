from read_iop import ReadIOP
from merkle import MerkleVerifier
from method import Method
from consts import QUERIES, INV_RATE, MIN_CYCLES_PO2


CIRCUIT_OUTPUT_SIZE = 18
CIRCUIT_MIX_SIZE = 36

CODE_TAP_SIZE = 15
DATA_TAP_SIZE = 212
ACCUM_TAP_SIZE = 36


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
    check_code_merkle(po2, method, code_merkle.root())

    data_merkle = MerkleVerifier(iop, domain, DATA_TAP_SIZE, QUERIES)
    print(data_merkle.root().hex())

    # TODO: adapter.accumulate?

    # accum_merkle = MerkleVerifier(iop, domain, ACCUM_TAP_SIZE, QUERIES)


def check_code_merkle(po2: int, method: Method, merkle_root: bytes) -> bool:
    which = po2 - MIN_CYCLES_PO2
    assert which < len(method.table), "Method cycle error"
    assert method.table[which] == merkle_root, "Verify error"
    return True


if __name__ == "__main__":
    main()
