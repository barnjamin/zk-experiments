from read_iop import ReadIOP
from merkle import MerkleVerifier

# what is this?
INV_RATE = 4

# number of queries to make against iop
QUERIES = 50

def main():
    with open("../trivial.seal", "rb") as f:
        seal = f.read()

    iop = ReadIOP(seal)

    code_size = 100
    po2 = 10
    size = 1 << po2
    domain = INV_RATE * size

    code_merkle = MerkleVerifier(iop, domain, code_size, QUERIES)
    assert check_code_merkle(code_merkle)

def check_code_merkle(m: MerkleVerifier)->bool:
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