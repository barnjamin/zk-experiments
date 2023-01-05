use std::fs::File;
use std::io::prelude::*;

use methods::{MULTIPLY_ID, MULTIPLY_PATH};
use risc0_zkvm::{Prover, Receipt};
use risc0_zkvm::serde::{from_slice, to_vec};

fn main() {

    env_logger::init();

    let a: u64 = 17;
    let b: u64 = 23;

    // Make the prover.
    let method_code = std::fs::read(MULTIPLY_PATH)
        .expect("Method code should be present at the specified path; did you use the correct *_PATH constant?");
    let mut prover = Prover::new(&method_code, MULTIPLY_ID).expect(
        "Prover should be constructed from valid method source code and corresponding method ID",
    );

    prover.add_input_u32_slice(to_vec(&a).unwrap().as_slice());
    prover.add_input_u32_slice(to_vec(&b).unwrap().as_slice());


    // Run prover & generate receipt
    let receipt = prover.run()
        .expect("Code should be provable unless it 1) had an error or 2) overflowed the cycle limit. See `embed_methods_with_options` for information on adjusting maximum cycle count.");

    // Optional: Verify receipt to confirm that recipients will also be able to verify your receipt
    receipt.verify(MULTIPLY_ID).expect(
        "Code you have proven should successfully verify; did you specify the correct method ID?",
    );

    let c: u64 = from_slice(receipt.journal.as_slice()).unwrap();
    println!("Hello: {}", c);



    write_receipt(receipt).expect("Failed to write receipt");

    let meth: risc0_zkvm::MethodId = MULTIPLY_ID.into();
    write_method(meth).expect("Failed to write method");

}

fn write_method(m: risc0_zkvm::MethodId) ->std::io::Result<()> {
    let mut mfile = File::create("trivial.method")?;
    mfile.write_all(m.as_slice())?;
    Ok(())
}

fn write_receipt(r: Receipt) -> std::io::Result<()> {
    
    let mut jfile = File::create("trivial.journal")?;
    jfile.write_all(&r.get_journal_bytes())?;

    let mut sfile = File::create("trivial.seal")?;
    sfile.write_all(&r.get_seal_bytes())?;

    Ok(())
}