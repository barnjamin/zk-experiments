#!/bin/bash

set -eu

#./reset.sh

# bls12_377, bls12_381, bn128, bw6_761
CURVE=bls12_381

# compile
zokrates compile -i record_vote.zok -c $CURVE --debug

# perform the setup phase
zokrates setup

