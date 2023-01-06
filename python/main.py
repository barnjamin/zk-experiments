from read_iop import ReadIOP
from merkle import MerkleVerifier
from consts import QUERIES, INV_RATE


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
    print(iop.rng.pool0.hex())
    # print(code_merkle.params.__dict__)
    # print(code_merkle.root().hex())
    # assert check_code_merkle(code_merkle)


def check_code_merkle(po2: int, merkle_root: bytes) -> bool:

    #     let po2 = po2 as usize;
    #     let which = po2 - MIN_CYCLES_PO2;
    #     #[cfg(not(target_os = "zkvm"))]
    #     if log::log_enabled!(log::Level::Debug) {
    #         log::debug!("merkle_root: {merkle_root}");
    #         log::debug!("MethodId");
    #         for (i, entry) in method_id.table.iter().enumerate() {
    #             let marker = if i == which { "*" } else { "" };
    #             log::debug!("  {i}: {entry}{marker}");
    #         }
    #     }
    #     if which >= method_id.table.len() {
    #         return Err(VerificationError::MethodCycleError { required: po2 });
    #     }
    #     if method_id.table[which] != *merkle_root {
    #         Err(VerificationError::MethodVerificationError)
    #     } else {
    #         Ok(())
    #     }
    # };

    pass


if __name__ == "__main__":
    main()
