#!/bin/bash

CURVE="$1"
COMPILATION="$2"

echo ""
echo ""
echo "################## HELLO FROM ALICE!!!!!!! #######################"
echo "################## HELLO FROM ALICE!!!!!!! #######################"
echo "################## HELLO FROM ALICE!!!!!!! #######################"
echo ""

echo "build zk-SNARK verifier using CURVE=$CURVE ϵ {bls12_377, bls12_381, bn128, bw6_761} for COMPILATION=$COMPILATION"

# compile 
# >--> abi.json, out, out.r1cs
printf "\nzokrates compile -i %s -c %s\n" "$COMPILATION.zok" "$CURVE"
zokrates compile -i "$COMPILATION.zok" -c "$CURVE"

# perform the setup phase
# out --> proving.key, verification.key
printf "\nzokrates setup\n"
zokrates setup

# create solidity verifier
# verification.key --> verifier.sol
printf "\nzokrates export-verifier\n"
zokrates export-verifier || echo "couldn't export solidity; CONTINUE"

cp verification.key "${COMPILATION}_verification.key"

printf "\nalice.sh: COMPLETE. Look out for the following artifacts: \n1A) abi.json\n1B) out\n1C) out.r1cs\n2A) proving.key\n2B) %s_verification.key\n3)  verifier.sol\n\n" "$COMPILATION"
