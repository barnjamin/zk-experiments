package circuits

// WARNING: This code is completely insecure and written only for experimentation.
// The proving key (pk) should be treated as toxic waste and disposed of

import (
	"log"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func setupKeys(name string, r1cs frontend.CompiledConstraintSystem) (plonk.ProvingKey, plonk.VerifyingKey) {
	srs, err := test.NewKZGSRS(r1cs)
	if err != nil {
		log.Fatalf("Failed to create new SRS: %+v", err)
		panic(err)
	}

	pk, vk, err := plonk.Setup(r1cs, srs)
	if err != nil {
		log.Fatalf("Failed to do setup: %+v", err)
	}
	writeToFile(pkFile(name), pk)
	writeToFile(vkFile(name), vk)
	return pk, vk
}

func readLastKeys(name string) (plonk.ProvingKey, plonk.VerifyingKey) {

	// read proving and verifying keys
	pk := plonk.NewProvingKey(ecc.BN254)

	f, err := os.Open(pkFile(name))
	if err != nil {
		log.Fatalf("Failed to read pk: %+v", err)
	}
	_, err = pk.ReadFrom(f)
	if err != nil {
		log.Fatalf("Failed to read pk: %+v", err)
	}
	f.Close()

	vk := plonk.NewVerifyingKey(ecc.BN254)
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
