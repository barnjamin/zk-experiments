package circuits

import (
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

const (
	PK_FILE    = "circuit.pk"
	VK_FILE    = "circuit.vk"
	PROOF_FILE = "circuit.proof"
	INPUT_FILE = "circuit.inputs"
)

func SumInputs(input []*big.Int, vk *VK) *bn254.G1Affine {
	vk_x := &bn254.G1Affine{}
	for idx := 0; idx < len(input); idx++ {
		ic := &vk.IC[idx+1]
		ic = ic.ScalarMultiplication(ic, input[idx])

		vk_x = vk_x.Add(vk_x, ic)
	}
	return vk_x.Add(vk_x, &vk.IC[0])
}

func CheckValidPairing(proof *Proof, vk *VK, input []*big.Int) (bool, error) {
	vk_x := SumInputs(input, vk)

	P := []bn254.G1Affine{
		*proof.Ar.Neg(proof.Ar),
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

func GetLastProof() (*Proof, *VK, []*big.Int) {
	proof := NewProofFromFile(PROOF_FILE)
	vk := NewVKFromFile(VK_FILE)

	b, err := os.ReadFile(INPUT_FILE)
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

func CompileCircuit(name string, c frontend.Circuit, opts ...frontend.CompileOption) {
	var fname = name + ".r1cs"
	r1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, c, opts...)
	if err != nil {
		log.Fatalf("Failed to compile circuit")
	}

	f, err := os.Open(fname)
	if err != nil {
		log.Fatalf("Failed to open file %s: %+v", fname, err)
	}

	_, err = r1cs.WriteTo(f)
	if err != nil {
		log.Fatalf("Failed to write to file %s: %+v", fname, err)
	}

}

func ReadCircuit(name string) frontend.CompiledConstraintSystem {
	var fname = name + ".r1cs"
	f, err := os.Open(fname)
	if err != nil {
		log.Fatalf("Failed to open %s: %+v", fname, err)
	}

	r1cs := groth16.NewCS(ecc.BN254)
	_, err = r1cs.ReadFrom(f)
	if err != nil {
		log.Fatalf("Failed to read %s: %+v", fname, err)
	}

	return r1cs
}

func CreateProofForCubic(x, y uint64) {
	var cubicCircuit cubic.Circuit
	r1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &cubicCircuit)
	if err != nil {
		log.Fatalf("Failed to compile circuit")
	}

	witness, err := frontend.NewWitness(&cubic.Circuit{X: x, Y: y}, ecc.BN254)
	if err != nil {
		log.Fatalf("Failed to create witness: %+v", err)
	}

	// Uncomment for a new set of keys
	//pk, vk := setupKeys(r1cs)
	pk, vk := readLastKeys()

	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		log.Fatalf("Failed to create proof: %+v", err)
	}
	writeToFile(PROOF_FILE, proof)

	pubWitness, err := witness.Public()
	if err != nil {
		log.Fatalf("couldnt create public proof: %+v", err)
	}

	err = groth16.Verify(proof, vk, pubWitness)
	if err != nil {
		log.Fatalf("Invalid Proof: %+v", err)
	}

	input := new(big.Int).SetUint64(y)
	buf := make([]byte, 32)
	ioutil.WriteFile(INPUT_FILE, input.FillBytes(buf), 0655)
}

func setupKeys(r1cs frontend.CompiledConstraintSystem) (groth16.ProvingKey, groth16.VerifyingKey) {
	// WARNING: Completely insecure, pk should be treated as toxic waste
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		log.Fatalf("Failed to do setup: %+v", err)
	}
	writeToFile(PK_FILE, pk)
	writeToFile(VK_FILE, vk)

	return pk, vk
}

func readLastKeys() (groth16.ProvingKey, groth16.VerifyingKey) {
	// read proving and verifying keys
	pk := groth16.NewProvingKey(ecc.BN254)
	vk := groth16.NewVerifyingKey(ecc.BN254)

	f, err := os.Open(PK_FILE)
	if err != nil {
		log.Fatalf("Failed to read pk: %+v", err)
	}
	_, err = pk.ReadFrom(f)
	if err != nil {
		log.Fatalf("Failed to read pk: %+v", err)
	}
	f.Close()

	f, err = os.Open(VK_FILE)
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
