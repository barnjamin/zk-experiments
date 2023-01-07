#!/bin/bash

CURVE=bls12_381

zokrates compile -i test_rng.zok -c $CURVE
zokrates setup
zokrates compute-witness
zokrates generate-proof
zokrates verify

rm abi.json
rm out
rm out.r1cs
rm out.wtns
rm proof.json
rm proving.key
rm verification.key
rm witness
