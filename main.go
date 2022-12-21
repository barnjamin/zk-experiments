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
	contract_vk_x := cc.CheckLinearCombination(circuit.InputsAsAbiTuple(inputs))
	log.Printf("Contract Linear combo returned: %+v", contract_vk_x)

	result := cc.Verify(circuit.InputsAsAbiTuple(inputs), proof.ToABITuple())
	log.Printf("Contract valid? %+v", result)

	vk_x := circuit.Linearize(inputs, vk)
	log.Printf("Local Linear combo returned: %+v", vk_x)

	ok, err := circuit.CheckValidPairing(proof, vk, vk_x)
	if err != nil {
		log.Fatalf("Failed to check pairing: %+v", err)
	}
	log.Printf("Valid?  %t", ok)
}
