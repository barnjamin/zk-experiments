package main

import (
	"log"
	"math"

	"github.com/barnjamin/zk-experiments/circuits"
	"github.com/barnjamin/zk-experiments/sandbox"
)

const AppID = 1416

func main() {
	// Create new proof
	circuits.CreateProofForCubic(3, uint64(math.Pow(3, 3)+3+5))

	// Read the proof from disk
	proof, vk, inputs := circuits.GetLastProof("cubic")

	// TODO: fix to not use pointers
	// Check locally
	// ok, err := circuit.CheckProof(inputs, proof, vk)
	// if err != nil || !ok {
	// 	log.Fatalf("invalid proof:  %+v", err)
	// }

	// Create a contract client
	cc := sandbox.NewClient(AppID, "contract/artifacts/contract.json")

	// Bootstrap with our VK
	cc.Bootstrap(vk.ToABITuple())

	// Verify the with the inputs && proof
	result := cc.Verify(circuits.InputsAsAbiTuple(inputs), proof.ToABITuple())
	log.Printf("Contract verified? %+v", result)
}
