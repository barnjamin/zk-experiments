package circuits

import (
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"

	"github.com/barnjamin/zk-experiments/circuits/cubic"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func SumInputs(input []*big.Int, vk *VK) *bn254.G1Affine {
	vk_x := &bn254.G1Affine{}
	for idx := 0; idx < len(input); idx++ {
		ic := &bn254.G1Affine{}
		ic = ic.ScalarMultiplication(&vk.IC[idx+1], input[idx])

		vk_x = vk_x.Add(vk_x, ic)
	}
	return vk_x.Add(vk_x, &vk.IC[0])
}

func CheckProof(input []*big.Int, proof Proof, vk VK) (bool, error) {
	vk_x := SumInputs(input, &vk)

	negAr := &bn254.G1Affine{}
	negAr.Neg(proof.Ar)

	P := []bn254.G1Affine{
		*negAr,
		*vk.Alpha1,
		*vk_x,
		*proof.Krs,
	}

	Q := []bn254.G2Affine{
		*proof.Bs,
		*vk.Beta2,
		*vk.Gamma2,
		*vk.Delta2,
	}

	return bn254.PairingCheck(P, Q)
}

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
	r1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, c, opts...)
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

	r1cs := groth16.NewCS(ecc.BN254)
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
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		log.Fatalf("Failed to create proof: %+v", err)
	}
	writeToFile(proofFile(name), proof)

	pubWitness, err := witness.Public()
	if err != nil {
		log.Fatalf("couldnt create public proof: %+v", err)
	}

	err = groth16.Verify(proof, vk, pubWitness)
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

func writeToFile(name string, rw RawWriter) {
	f, err := os.Create(name)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	_, err = rw.WriteRawTo(f)
	if err != nil {
		panic(err)
	}
}
