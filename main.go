package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"math"

	"github.com/barnjamin/zk-experiments/circuit"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	var cubicCircuit circuit.Circuit
	r1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &cubicCircuit)
	if err != nil {
		log.Fatalf("Failed to compile circuit")
	}

	var buf bytes.Buffer
	_, _ = r1cs.WriteTo(&buf)
	ioutil.WriteFile("r1cs.bin", buf.Bytes(), 0655)

	// x**3 + x + 5 == y
	assignment := &circuit.Circuit{
		X: 3,
		Y: int(math.Pow(3, 3) + 3 + 5),
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254)
	if err != nil {
		log.Fatalf("Failed to create widness: %+v", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatalf("Failed to create public thing: %+v", err)
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		log.Fatalf("Failed to do setup: %+v", err)
	}
	buf.Reset()
	_, _ = pk.WriteRawTo(&buf)
	ioutil.WriteFile("pk.bin", buf.Bytes(), 0655)

	buf.Reset()
	vk.WriteRawTo(&buf)
	ioutil.WriteFile("vk.bin", buf.Bytes(), 0655)

	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		log.Fatalf("Failed to proove: %+v", err)
	}
	buf.Reset()
	proof.WriteRawTo(&buf)
	ioutil.WriteFile("proof.bin", buf.Bytes(), 0655)

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Fatalf("Couldnt verify circuit: %+v", err)
	}
}
