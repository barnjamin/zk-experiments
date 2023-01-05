from read_iop import ReadIOP
from merkle import MerkleVerifier
from field import encode_mont, decode_mont

# what is this?
INV_RATE = 4

# number of queries to make against iop
QUERIES = 50


# [2023-01-05T15:16:32Z DEBUG risc0_zkp::prove] Proof size = 44421
# [2023-01-05T15:16:32Z DEBUG risc0_zkp::verify::host] Some([391, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0])
# [2023-01-05T15:16:32Z DEBUG risc0_zkp::verify::host] out: 8
# [2023-01-05T15:16:32Z DEBUG risc0_zkp::verify::host] output size: 18
# [2023-01-05T15:16:32Z DEBUG risc0_zkp::verify::host] mix size: 36
# [2023-01-05T15:16:32Z DEBUG risc0_zkp::verify::host] po2: 13
# [2023-01-05T15:16:32Z DEBUG risc0_zkp::verify::host] size: 8192


def main():
    with open("../trivial.seal", "rb") as f:
        seal = list(f.read())

    output_size = 18
    mix_size = 36

    iop = ReadIOP(output_size, seal)
    # print(int.from_bytes(bytes(seal[:4]), 'little'))
    # print(encode_mont(391))
    # print(decode_mont(134217711))
    print(iop.out)
    print(len(iop.out))

    po2 = iop.po2
    size = 1 << po2
    domain = INV_RATE * size
    code_size = 15

    code_merkle = MerkleVerifier(iop, domain, code_size, QUERIES)
    print(code_merkle.params.__dict__)
    # assert check_code_merkle(code_merkle)


def check_code_merkle(m: MerkleVerifier) -> bool:
    # let check_code = |po2: u32, merkle_root: &Digest| -> Result<(), VerificationError> {
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
