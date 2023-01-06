use std::{fs::File, io::Read};
use risc0_zkvm::Receipt;

// montgomery form constants
const M: u32 = 0x88000001;
const R2: u32 = 1172168163;
const P: u32 = 15 * (1 << 27) + 1;
const P_U64: u64 = P as u64;


fn main() {
    check_receipt().expect("FAILzore");
}

fn check_receipt()->std::io::Result<()> {
    env_logger::init();
    
    println!("{:?}", risc0_zkp::field::baby_bear::Elem::new(123));

    let mut jf = File::open("trivial.journal")?;
    let mut jbuf = Vec::new();
    jf.read_to_end(&mut jbuf)?;


    let mut sf = File::open("trivial.seal")?;
    let mut sbuf = Vec::new();
    sf.read_to_end(&mut sbuf)?;

    let jvec: &[u32] = bytemuck::cast_slice(jbuf.as_slice());
    let svec: &[u32] = bytemuck::cast_slice(sbuf.as_slice());

    println!("{:?}", &svec[1..10]);

    let receipt = Receipt::new(jvec, svec);

    println!("{:?}", methods::MULTIPLY_ID);
    receipt.verify(methods::MULTIPLY_ID).expect(
        "Code you have proven should successfully verify; did you specify the correct method ID?",
    );

    println!("it works?");


    return Ok(());
}

