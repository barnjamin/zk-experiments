use std::{fs::File, io::Read};
use risc0_zkvm::Receipt;

// montgomery form constants
const M: u32 = 0x88000001;
const R2: u32 = 1172168163;
const P: u32 = 15 * (1 << 27) + 1;
const P_U64: u64 = P as u64;


fn main() {
    let result = muly(R2, 123);
    println!("Result: {}", result);
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

/// Wrapping multiplication of [Elem]  using Baby Bear field modulus
// Copied from the C++ implementation (fp.h)
fn muly(lhs: u32, rhs: u32) -> u32 {
    // uint64_t o64 = uint64_t(a) * uint64_t(b);
    let mut o64: u64 = (lhs as u64).wrapping_mul(rhs as u64);
    println!("lhs: {:?}, rhs: {:?}, o64: {:?}", lhs, rhs, o64);
    println!("castdown: {:?}", o64 as u32);
    // uint32_t low = -uint32_t(o64);
    let low: u32 = 0u32.wrapping_sub(o64 as u32);
    // uint32_t red = M * low;
    let red = M.wrapping_mul(low);
    println!("low: {:?} red:{:?}", low, red);
    // o64 += uint64_t(red) * uint64_t(P);
    o64 += (red as u64).wrapping_mul(P_U64);
    // uint32_t ret = o64 >> 32;
    let ret = (o64 >> 32) as u32;
    // return (ret >= P ? ret - P : ret);
    if ret >= P {
        ret - P
    } else {
        ret
    }
}
