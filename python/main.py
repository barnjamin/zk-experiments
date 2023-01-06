from read_iop import ReadIOP, u8_to_u32, u32_to_u8
from merkle import MerkleVerifier
from Crypto.Hash import SHA256
import struct
from sha256 import generate_hash

# what is this?
INV_RATE = 4

# number of queries to make against iop
QUERIES = 50


def swap32(i: int):
    return struct.unpack("<I", struct.pack(">I", i))[0]


initial_state = [
    int.from_bytes(bytes.fromhex(v[2:]), "big")
    for v in [
        "0x6a09e667",
        "0xbb67ae85",
        "0x3c6ef372",
        "0xa54ff53a",
        "0x510e527f",
        "0x9b05688c",
        "0x1f83d9ab",
        "0x5be0cd19",
    ]
]


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
