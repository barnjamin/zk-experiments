#!/bin/bash

WITNESSES=$1

echo "HELLO FROM EVE!!!!!!!"

echo "build zk-SNARK proof for WITNESSES=$WITNESSES"

# Define the parse_inputs function
function report_proof_public_inputs {
  # Extract the inputs field from the JSON file
  inputs=$(jq -r '.inputs[]' proof.json)

  # Iterate over each input value
  printf "\nproof.json PUBLIC inputs:"
  for input in $inputs; do
    # Convert the hexadecimal string to a number and print it to the console
    python -c "print(int('$input', 16))"
  done
}

# # execute the program
# abi.json, out --> out.wtns, witness
printf "\nzokrates compute-witness -a %s" "$WITNESSES\n"
# shellcheck disable=SC2086
zokrates compute-witness -a $WITNESSES

# # generate a proof of computation
# out, proving.key, witness --> proof.json
printf "\nzokrates generate-proof\n"
zokrates generate-proof 

report_proof_public_inputs

# # and verify natively
# proof.json, verification.key -->> <NONE>
printf "\nzokrates verify --verbose"
zokrates verify --verbose