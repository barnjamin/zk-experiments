package gnark

// WARNING: This code is completely insecure and written only for experimentation.
// The proving key (pk) should be treated as toxic waste and disposed of

import (
	"log"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

// Schemes
// Groth16 - pk/vk per circuit
// Plonk -
// Marlin -
// Sonic

func setupKeys(name string, r1cs frontend.CompiledConstraintSystem) (groth16.ProvingKey, groth16.VerifyingKey) {
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		log.Fatalf("Failed to do setup: %+v", err)
	}
	writeToFile(pkFile(name), pk)
	writeToFile(vkFile(name), vk)
	return pk, vk
}

func readLastKeys(name string) (groth16.ProvingKey, groth16.VerifyingKey) {

	// read proving and verifying keys
	pk := groth16.NewProvingKey(ecc.BN254)

	f, err := os.Open(pkFile(name))
	if err != nil {
		log.Fatalf("Failed to read pk: %+v", err)
	}
	_, err = pk.ReadFrom(f)
	if err != nil {
		log.Fatalf("Failed to read pk: %+v", err)
	}
	f.Close()

	vk := groth16.NewVerifyingKey(ecc.BN254)
	f, err = os.Open(vkFile(name))
	if err != nil {
		log.Fatalf("Failed to read vk: %+v", err)
	}

	_, err = vk.ReadFrom(f)
	if err != nil {
		log.Fatalf("Failed to read vk: %+v", err)
	}
	f.Close()

	return pk, vk
}
