package main

import (
	"log"

	"github.com/barnjamin/zk-experiments/circuit"
	"github.com/barnjamin/zk-experiments/interact"
)

func main() {
	// Uncomment for new proof
	// circuit.CreateProof(3, uint64(math.Pow(3, 3)+3+5))

	proof, vk, inputs := circuit.GetProof()

	cc := interact.NewClient(1416, "contract/artifacts/contract.json")
	cc.Bootstrap(circuit.VkAsABITuple(vk))
	verified := cc.Verify(
		circuit.InputsAsAbiTuple(inputs),
		circuit.ProofAsABITuple(proof),
	)
	log.Printf("Verify returned: %+v", verified)
}
