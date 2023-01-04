use std::{fs::File, io::Read};
use risc0_zkvm::Receipt;


fn main() {
    read_receipt().expect("msg");
}

fn read_receipt()->std::io::Result<()> {
    let mut jf = File::open("trivial.journal")?;
    let mut jbuf = Vec::new();
    jf.read_to_end(&mut jbuf)?;


    let mut sf = File::open("trivial.seal")?;
    let mut sbuf = Vec::new();
    sf.read_to_end(&mut sbuf)?;

    let jvec: &[u32] = bytemuck::cast_slice(jbuf.as_slice());
    let svec: &[u32] = bytemuck::cast_slice(sbuf.as_slice());

    let receipt = Receipt::new(jvec, svec);

    println!("{:?}", methods::MULTIPLY_ID);
    receipt.verify(methods::MULTIPLY_ID).expect(
        "Code you have proven should successfully verify; did you specify the correct method ID?",
    );

    println!("it works?");


    return Ok(());
}