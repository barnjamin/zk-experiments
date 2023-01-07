#!/bin/bash

CURVE="$1"
COMPILATION="$2"

echo "HELLO FROM ALICE!!!!!!!"

echo "build zk-SNARK verifier using CURVE=$CURVE ϵ {bls12_377, bls12_381, bn128, bw6_761} for COMPILATION=$COMPILATION"

# compile 
# >--> abi.json, out, out.r1cs
printf "\nzokrates compile -i %s -c %s\n" "$COMPILATION" "$CURVE"
zokrates compile -i "$COMPILATION" -c "$CURVE"

# perform the setup phase
# out --> proving.key, verification.key
printf "\nzokrates setup\n"
zokrates setup

# create solidity verifier
# verification.key --> verifier.sol
printf "\nzokrates export-verifier\n"
zokrates export-verifier || echo "couldn't export solidity; CONTINUE"
