# Compile circuit
circom tmp.circom --r1cs --wasm --sym

echo -n '{"a":"3","b":"11"}' > input.json

# Generate `wtns` file to be used for proofs later
node tmp_js/generate_witness.js tmp_js/tmp.wasm input.json witness.wtns

# Setup key from our ptau
snarkjs g16s tmp.r1cs ~/final.ptau tmp.zkey

# export vk to json
snarkjs zkey export verificationkey tmp.zkey verification_key.json

# create proof
snarkjs groth16 prove tmp.zkey witness.wtns proof.json public.json

# verify proof
snarkjs groth16 verify verification_key.json public.json proof.json 