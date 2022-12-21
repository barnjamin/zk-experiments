package main

import (
	"log"

	"github.com/barnjamin/zk-experiments/circuit"
	"github.com/barnjamin/zk-experiments/interact"
)

const AppID = 1416

func main() {
	// Uncomment for new proof
	// circuit.CreateProof(3, uint64(math.Pow(3, 3)+3+5))
	proof, vk, inputs := circuit.GetProof()

	cc := interact.NewClient(AppID, "contract/artifacts/contract.json")
	cc.Bootstrap(vk.ToABITuple())

	result := cc.Verify(circuit.InputsAsAbiTuple(inputs), proof.ToABITuple())
	log.Printf("Contract verified? %+v", result)
}
