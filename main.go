package main

import (
	"log"

	"github.com/barnjamin/zk-experiments/circuit"
	"github.com/barnjamin/zk-experiments/interact"
)

const AppID = 1416

func main() {
	// Create new proof
	// circuit.CreateProof(3, uint64(math.Pow(3, 3)+3+5))

	// Read the proof from disk
	proof, vk, inputs := circuit.GetLastProof()

	// TODO: fix to not use pointers
	// Check locally
	// ok, err := circuit.CheckValidPairing(proof, vk, inputs)
	// if err != nil || !ok {
	// 	log.Fatalf("invalid proof:  %+v", err)
	// }

	// Create a contract client
	cc := interact.NewClient(AppID, "contract/artifacts/contract.json")

	// Bootstrap with our VK
	cc.Bootstrap(vk.ToABITuple())

	// Verify the with the inputs && proof
	result := cc.Verify(circuit.InputsAsAbiTuple(inputs), proof.ToABITuple())
	log.Printf("Contract verified? %+v", result)
}
