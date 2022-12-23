package main

import (
	"log"
	"math"

	"github.com/barnjamin/zk-experiments/groth16/circuits"
	"github.com/barnjamin/zk-experiments/sandbox"
)

func main() {
	RunGrothProof()
}

func RunGrothProof() {
	// Create new proof
	circuits.CreateProofForCubic(3, uint64(math.Pow(3, 3)+3+5))

	// Read the proof from disk
	proof, vk, inputs := circuits.GetLastProof("cubic")

	// Check locally first
	ok, err := circuits.CheckProof(inputs, *proof, *vk)
	if err != nil || !ok {
		log.Fatalf("invalid proof:  %+v", err)
	}

	// Create a contract client
	cc := sandbox.NewClient("groth16/contract/artifacts/application.json", 0)
	cc.Create()
	cc.Fund(1_000_000_000)

	// Bootstrap with our VK
	cc.Bootstrap(vk.ToABITuple())

	// Verify the with the inputs && proof
	result := cc.Verify(circuits.InputsAsAbiTuple(inputs), proof.ToABITuple())
	log.Printf("Contract verified? %+v", result)
}
