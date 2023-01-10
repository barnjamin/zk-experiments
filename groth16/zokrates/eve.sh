#!/bin/bash

source helpers.sh

ZOK=$1
# WITNESSES=$(echo "$2" | tr ',' ' ')
WITNESSES=$2

echo ""
echo ""
echo "################## HELLO FROM EVE!!!!!!! #######################"
echo "################## HELLO FROM EVE!!!!!!! #######################"
echo "################## HELLO FROM EVE!!!!!!! #######################"
echo ""

# echo "\$2=$2"

echo "build zk-SNARK proof for WITNESSES=$WITNESSES and ZOK=$ZOK"

# Define the parse_inputs function
report_proof_public_inputs() {
  # Extract the inputs field from the JSON file
  inputs=$(jq -r '.inputs[]' "$@")

  # Iterate over each input value
  printf "\nproof.json PUBLIC inputs:\n"
  for input in $inputs; do
    # Convert the hexadecimal string to a number and print it to the console
    python -c "print(int('$input', 16))"
  done
}

# # execute the program
# abi.json, out --> out.wtns, witness
ABI="${ZOK}_abi.json"
OUT="${ZOK}_out"
WIT="${ZOK}_witness"
printf "\nSTEP (2.A) EVE::WITNESSES: (%s, %s, %s) --> (out.wtns, %s)\n" "$WITNESSES" "$ABI" "$OUT" "$WIT"
# xc zokrates compute-witness -a $WITNESSES -s "ABI" -i "$OUT" --circom-witness out.wtns -o "$WIT"
echo "echo $WITNESSES | zokrates compute-witness -i $OUT -s $ABI --circom-witness out.wtns -o $WIT --stdin --abi --verbose"
echo "$WITNESSES" | zokrates compute-witness -i "$OUT" -s "$ABI" --circom-witness out.wtns -o "$WIT" --stdin --abi --verbose || echo "testing"


# # generate a proof of computation
# out, proving.key, witness --> proof.json
PROOFKEY="${ZOK}_proving.key"
PROOF="${ZOK}_proof.json"
printf "\nSTEP (2.B) EVE::PROVE: (%s, %s, %s) --> %s\n" "$OUT" "$PROOFKEY" "$WIT" "$PROOF"
xc zokrates generate-proof -i "$OUT" -p "$PROOFKEY" -w "$WIT" -j "$PROOF"

report_proof_public_inputs "$PROOF"


printf "\neve.sh: COMPLETE. Look out for the following artifacts: \n2.A.i)  out.wtns\n2.A.ii) %s\n2.B)    %s\n\n\n" "$WIT" "$PROOF"
