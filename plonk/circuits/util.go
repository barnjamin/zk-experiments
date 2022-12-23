package circuits

import (
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"

	"github.com/barnjamin/zk-experiments/plonk/circuits/cubic"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
)

func GetLastProof(name string) (*Proof, *VK, []*big.Int) {
	proof := NewProofFromFile(proofFile(name))
	vk := NewVKFromFile(vkFile(name))

	b, err := os.ReadFile(inputFile(name))
	if err != nil {
		log.Fatalf("Failed to read inputs: %+v", err)
	}

	var inputs []*big.Int
	for x := 0; x < len(b)/32; x += 1 {
		i := new(big.Int).SetBytes(b[x*32 : (x+1)*32])
		inputs = append(inputs, i)
	}

	return proof, vk, inputs
}

func WriteCircuit(name string, c frontend.Circuit, opts ...frontend.CompileOption) {
	var fname = name + ".r1cs"
	r1cs, err := frontend.Compile(ecc.BN254, scs.NewBuilder, c, opts...)
	if err != nil {
		log.Fatalf("failed to compile circuit")
	}

	f, err := os.Create(fname)
	if err != nil {
		log.Fatalf("failed to open file %s: %+v", fname, err)
	}

	_, err = r1cs.WriteTo(f)
	if err != nil {
		log.Fatalf("failed to write to file %s: %+v", fname, err)
	}
}

func ReadCircuit(name string) frontend.CompiledConstraintSystem {
	var fname = name + ".r1cs"
	f, err := os.Open(fname)
	if err != nil {
		log.Fatalf("failed to open %s: %+v", fname, err)
	}

	r1cs := plonk.NewCS(ecc.BN254)
	_, err = r1cs.ReadFrom(f)
	if err != nil {
		log.Fatalf("failed to read %s: %+v", fname, err)
	}

	return r1cs
}

func CreateProofForCubic(x, y uint64) {
	var name = "cubic"
	WriteCircuit(name, &cubic.Circuit{})

	witness, err := frontend.NewWitness(&cubic.Circuit{X: x, Y: y}, ecc.BN254)
	if err != nil {
		log.Fatalf("failed to create witness: %+v", err)
	}

	r1cs := ReadCircuit(name)

	pk, vk := setupKeys(name, r1cs)
	proof, err := plonk.Prove(r1cs, pk, witness)
	if err != nil {
		log.Fatalf("Failed to create proof: %+v", err)
	}
	writeToFile(proofFile(name), proof)

	pubWitness, err := witness.Public()
	if err != nil {
		log.Fatalf("couldnt create public proof: %+v", err)
	}

	err = plonk.Verify(proof, vk, pubWitness)
	if err != nil {
		log.Fatalf("invalid Proof: %+v", err)
	}

	input := new(big.Int).SetUint64(y)
	buf := make([]byte, 32)
	ioutil.WriteFile(inputFile(name), input.FillBytes(buf), 0655)
}

func inputFile(name string) string {
	return fmt.Sprintf("%s.inputs", name)
}
func proofFile(name string) string {
	return fmt.Sprintf("%s.proof", name)
}
func pkFile(name string) string {
	return fmt.Sprintf("%s.pk", name)
}
func vkFile(name string) string {
	return fmt.Sprintf("%s.vk", name)
}

func writeToFile(name string, w Writer) {
	f, err := os.Create(name)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	_, err = w.WriteTo(f)
	if err != nil {
		panic(err)
	}
}
