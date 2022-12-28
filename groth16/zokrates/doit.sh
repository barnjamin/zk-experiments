#!/bin/bash

# bls12_377, bls12_381, bn128, bw6_761
CURVE=bls12_381

# compile
zokrates compile -i root.zok -c $CURVE

# perform the setup phase
zokrates setup

# execute the program
zokrates compute-witness -a 337 113569

# generate a proof of computation
zokrates generate-proof

# or verify natively
zokrates verify