from read_iop import ReadIOP
from merkle import MerkleVerifier
from method import Method
from consts import QUERIES, INV_RATE, MIN_CYCLES_PO2


def main():
    with open("../trivial.seal", "rb") as f:
        seal = list(f.read())

    with open("../trivial.method", "rb") as f:
        method = Method.from_bytes(f.read())

    for x in method.table:
        print(x.hex())
        print()

    circuit_output_size = 18
    circuit_mix_size = 36

    iop = ReadIOP(circuit_output_size, seal)

    po2 = iop.po2
    size = 1 << po2
    domain = INV_RATE * size
    code_size = 15

    code_merkle = MerkleVerifier(iop, domain, code_size, QUERIES)
    check_code_merkle(po2, method, code_merkle.root())


def check_code_merkle(po2: int, method: Method, merkle_root: bytes) -> bool:
    which = po2 - MIN_CYCLES_PO2
    assert which < len(method.table), "Method cycle error"
    assert method.table[which] == merkle_root, "Verify error"
    return True


if __name__ == "__main__":
    main()
