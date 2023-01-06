from read_iop import ReadIOP
from merkle import MerkleVerifier
from consts import QUERIES, INV_RATE, MIN_CYCLES_PO2


def main():
    with open("../trivial.seal", "rb") as f:
        seal = list(f.read())

    circuit_output_size = 18
    circuit_mix_size = 36

    iop = ReadIOP(circuit_output_size, seal)

    po2 = iop.po2
    size = 1 << po2
    domain = INV_RATE * size
    code_size = 15

    code_merkle = MerkleVerifier(iop, domain, code_size, QUERIES)
    # assert check_code_merkle(code_merkle)


def check_code_merkle(po2: int, merkle_root: bytes) -> bool:
    which = po2 - MIN_CYCLES_PO2

    #  if which >= method_id.table.len() {
    #      return Err(VerificationError::MethodCycleError { required: po2 });
    #  }

    #  if method_id.table[which] != *merkle_root {
    #      Err(VerificationError::MethodVerificationError)
    #  } else {
    #      Ok(())
    #  }

    return True


if __name__ == "__main__":
    main()
