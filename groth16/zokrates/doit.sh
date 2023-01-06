#!/bin/bash

COMPILATION="$1"
WITNESSES=$2

# Define the parse_inputs function
function report_proof_public_inputs {
  # Extract the inputs field from the JSON file
  inputs=$(jq -r '.inputs[]' proof.json)

  # Iterate over each input value
  echo "proof.json PUBLIC inputs:"
  for input in $inputs; do
    # Convert the hexadecimal string to a number and print it to the console
    printf "%d\n" "$input"
  done
}

echo "build zk-SNARK for $COMPILATION and witnesses $WITNESSES"

# bls12_377, bls12_381, bn128, bw6_761
CURVE=bls12_381

# compile 
# >--> abi.json, out, out.r1cs
zokrates compile -i "$COMPILATION" -c "$CURVE"

# perform the setup phase
# out --> proving.key, verification.key
zokrates setup

# create solidity verifier
# verification.key --> verifier.sol
# zokrates export-verifier # commented out as can't handle g16

# # execute the program
# abi.json, out --> out.wtns, witness
# zokrates compute-witness -a 337 113569

# shellcheck disable=SC2086
zokrates compute-witness -a $WITNESSES

# # generate a proof of computation
# out, proving.key, witness --> proof.json
zokrates generate-proof 

report_proof_public_inputs

# # and verify natively
# proof.json, verification.key -->> <NONE>
zokrates verify --verbose