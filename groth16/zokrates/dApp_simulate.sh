#!/bin/bash

source helpers.sh

ZOK=$1

echo ""
echo ""
echo "################## HELLO FROM dApp (simulation) !!!!!!! #######################"
echo "################## HELLO FROM dApp (simulation) !!!!!!! #######################"
echo "################## HELLO FROM dApp (simulation) !!!!!!! #######################"
echo ""

# # and verify natively
# verification.key, proof.json -->> ACCEPT/REJECT
VERIFYKEY="${ZOK}_verification.key"
PROOF="${ZOK}_proof.json"
printf "\nSTEP (3) dApp::VERIFY: (%s, %s) --> ACCEPT/REJECT\n"  "$VERIFYKEY" "$PROOF"
xc zokrates verify --verbose -v "$VERIFYKEY" -j "$PROOF"

echo "################## GOODBYE FROM dApp (simulation) !!!!!!! #######################"
echo "################## GOODBYE FROM dApp (simulation) !!!!!!! #######################"
echo "################## GOODBYE FROM dApp (simulation) !!!!!!! #######################"
echo ""
