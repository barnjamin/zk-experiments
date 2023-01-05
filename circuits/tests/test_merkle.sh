#!/bin/bash

CURVE=bls12_381

zokrates compile -i test_merkle.zok -c $CURVE
zokrates setup
zokrates compute-witness -a 3663108286 398046313 1647531929 2006957770 2363872401 3235013187 3137272298 406301144 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
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
