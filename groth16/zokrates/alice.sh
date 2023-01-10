#!/bin/bash

source helpers.sh

CURVE="$1"
ZOK="$2"

echo ""
echo ""
echo "################## HELLO FROM ALICE!!!!!!! #######################"
echo "################## HELLO FROM ALICE!!!!!!! #######################"
echo "################## HELLO FROM ALICE!!!!!!! #######################"
echo ""

echo "build zk-SNARK verifier using CURVE=$CURVE ϵ {bls12_377, bls12_381, bn128, bw6_761} for ZOK=$ZOK"

# compile 
# circuit.zok --> abi.json, out, out.r1cs_out
ABI="${ZOK}_abi.json"
OUT="${ZOK}_out"
printf "\nSTEP (1.A) Alice::COMPILE: %s.zok --> (%s, %s, out.r1cs)\n"  "$ZOK" "$ABI" "$OUT"
xc zokrates compile -i "$ZOK.zok" -c "$CURVE" -s "$ABI" -o "$OUT" -r out.r1cs --debug --verbose


# perform the setup phase
# out --> proving.key, verification.key
PROOFKEY="${ZOK}_proving.key"
VERIFYKEY="${ZOK}_verification.key"
printf "\nSTEP (1.B) Alice::SETUP: %s --> (%s, %s)\n" "$OUT" "$PROOFKEY" "$VERIFYKEY"
xc zokrates setup -i "$OUT" -p "$PROOFKEY" -v "$VERIFYKEY"

# create solidity verifier
# verification.key --> verifier.sol
printf "\nSTEP (1.C) Alice::SOLIDITY: %s --> verifier.sol\n" "$VERIFYKEY"
xc zokrates export-verifier -i "$VERIFYKEY" || echo "couldn't export solidity; CONTINUE"


printf "\nalice.sh: COMPLETE. Look out for the following artifacts: \n1.A.i)   %s\n1.A.ii)  %s\n1.A.iii) out.r1cs\n1.B.i)   %s\n1.B.ii)  %s\n1.C)     verifier.sol\n\n" "$ABI" "$OUT" "$PROOFKEY" "$VERIFYKEY"
