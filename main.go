package main

import (
	"encoding/json"
	"io"
	"log"
	"math"
	"os"

	"github.com/barnjamin/zk-experiments/circuit"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type RawWriter interface {
	WriteRawTo(w io.Writer) (int64, error)
}

func main() {
	createProof(3, uint64(math.Pow(3, 3)+3+5))
}

func createProof(x, y uint64) {
	var cubicCircuit circuit.Circuit
	r1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &cubicCircuit)
	if err != nil {
		log.Fatalf("Failed to compile circuit")
	}

	assignment := &circuit.Circuit{X: x, Y: y}

	witness, err := frontend.NewWitness(assignment, ecc.BN254)
	if err != nil {
		log.Fatalf("Failed to create witness: %+v", err)
	}

	// WARNING: Completely insecure, pk should be treated as toxic waste
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		log.Fatalf("Failed to do setup: %+v", err)
	}
	writeToFile("circuit.pk", pk)
	writeToFile("circuit.vk", vk)

	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		log.Fatalf("Failed to proove: %+v", err)
	}
	b, _ := json.MarshalIndent(proof, "", " ")
	log.Printf("%s", string(b))
	writeToFile("circuit.proof", proof)

	// get proof bytes
	// const fpSize = 4 * 8
	// var buf bytes.Buffer
	// proof.WriteRawTo(&buf)
	// proofBytes := buf.Bytes()

	// // solidity contract inputs
	// var (
	// 	a     [2]*big.Int
	// 	b     [2][2]*big.Int
	// 	c     [2]*big.Int
	// 	input [1]*big.Int
	// )

	// //// proof.Ar, proof.Bs, proof.Krs
	// a[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	// a[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	// b[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	// b[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	// b[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	// b[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	// c[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	// c[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])

	//// public witness
	// input[0] = new(big.Int).SetUint64(y)

	//// call the contract
	//res, err := t.verifierContract.VerifyProof(nil, a, b, c, input)
	//t.NoError(err, "calling verifier on chain gave error")
	//t.True(res, "calling verifier on chain didn't succeed")

	//// (wrong) public witness
	//input[0] = new(big.Int).SetUint64(42)

	//// call the contract should fail
	//res, err = t.verifierContract.VerifyProof(nil, a, b, c, input)
	//t.NoError(err, "calling verifier on chain gave error")
	//t.False(res, "calling verifier on chain succeed, and shouldn't have")
}

func writeToFile(name string, rw RawWriter) {
	f, err := os.Create(name)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	_, err = rw.WriteRawTo(f)
	if err != nil {
		panic(err)
	}
}
