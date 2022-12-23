#!/bin/bash

CURVE=bls12_381
SCHEME=marlin

zokrates compile -c $CURVE --input root.zok

zokrates universal-setup -c $CURVE -s $SCHEME
 
zokrates setup -s $SCHEME

zokrates compute-witness -a 337 113569 113569

zokrates generate-proof -s $SCHEME

zokrates verify