#!/bin/bash

# compile
zokrates compile -i main.zok # --curve bls12_381
# perform the setup phase
zokrates setup # --proving-scheme g16
# execute the program
zokrates compute-witness -a 337 113569
# generate a proof of computation
zokrates generate-proof
# export a solidity verifier
zokrates export-verifier
# or verify natively
zokrates verify

# following are for circom, we can discard them any time, leave for reference.

# Compile circuit with wasm witness generator
# circom tmp.circom --r1cs --wasm --sym

# Write inputs to json file
# echo -n '{"a":"3","b":"11"}' > input.json

# Generate `wtns` file to be used for proofs later
# node tmp_js/generate_witness.js tmp_js/tmp.wasm input.json witness.wtns

# Setup key from our ptau
# snarkjs g16s tmp.r1cs ~/final.ptau tmp.zkey

# export vk to json
# snarkjs zkey export verificationkey tmp.zkey verification_key.json

# create proof
# snarkjs groth16 prove tmp.zkey witness.wtns proof.json public.json

# verify proof
# snarkjs groth16 verify verification_key.json public.json proof.json 
