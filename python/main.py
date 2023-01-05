from read_iop import ReadIOP, u8_to_u32, u32_to_u8
from merkle import MerkleVerifier
from hashlib import sha256
from Crypto.Hash import SHA256
import struct

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


def sha_compress(a: list[int], b: list[int]):
    h = SHA256.new()

    block = [0] * 16
    for x in range(8):
        block[x] = a[x]
        block[x + 8] = b[x]
    block = u32_to_u8(block)

    h.update(bytes(block))

    return h.digest()


def main():
    # we should be able to assert hash(a,b) == val
    a = bytes.fromhex(
        "7b3c0a71671781f9d6851b97d92cbe10d36eca939a0334756e03f06b28c22585"
    )
    b = bytes.fromhex(
        "430bc748b6e13c43e48abe1b6e35cdec492e86bb901597810fc8f6831d5839ad"
    )
    val = bytes.fromhex(
        "e957cefae0bcb78d2e2c6728704cd03ff3522de1ee275b5d7022fb5d01944f60"
    )

    a = u8_to_u32(a)
    b = u8_to_u32(b)
    print(sha_compress(a, b).hex())

    # with open("../trivial.seal", "rb") as f:
    #    seal = list(f.read())

    # circuit_output_size = 18
    # circuit_mix_size = 36

    # iop = ReadIOP(circuit_output_size, seal)

    # po2 = iop.po2
    # size = 1 << po2
    # domain = INV_RATE * size
    # code_size = 15

    # code_merkle = MerkleVerifier(iop, domain, code_size, QUERIES)
    # print(code_merkle.params.__dict__)
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
