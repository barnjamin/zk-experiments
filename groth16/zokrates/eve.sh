#!/bin/bash

PROOF_PREFIX=$1
WITNESSES=$2

echo ""
echo ""
echo "################## HELLO FROM EVE!!!!!!! #######################"
echo "################## HELLO FROM EVE!!!!!!! #######################"
echo "################## HELLO FROM EVE!!!!!!! #######################"
echo ""

echo "build zk-SNARK proof for WITNESSES=$WITNESSES and PROOF_PREFIX=$PROOF_PREFIX"

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
printf "\nzokrates compute-witness -a %s\n" "$WITNESSES"
# shellcheck disable=SC2086
zokrates compute-witness -a $WITNESSES

# # generate a proof of computation
# out, proving.key, witness --> proof.json
printf "\nzokrates generate-proof\n"
zokrates generate-proof 

report_proof_public_inputs

# # and verify natively
# proof.json, ${PROOF_PREFIX}_verification.key -->> <NONE>
printf "\nzokrates verify -v %s_verification.key --verbose" "$PROOF_PREFIX"
zokrates verify -v "${PROOF_PREFIX}_verification.key" --verbose

cp proof.json "${PROOF_PREFIX}_proof.json"

printf "\neve.sh: COMPLETE. Look out for the following artifacts: \n4A) out.wtns\n4B) witness\n5)  %s_proof.json\n\n\n" "$PROOF_PREFIX"
