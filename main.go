package main

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"

	"github.com/algorand/go-algorand-sdk/abi"
	"github.com/barnjamin/zk-experiments/circuit"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type RawWriter interface {
	WriteRawTo(w io.Writer) (int64, error)
}

func main() {
	//createProof(3, uint64(math.Pow(3, 3)+3+5))
	proof, vk, inputs := getProof()
	log.Printf("%+v", proof)
	log.Printf("%+v", vk)
	log.Printf("%+v", inputs)

	// TODO: Write abi arguments (vk, proof, inputs)  to file based on the type
	contract := getContract()
	method, _ := abi.GetMethodByName(contract.Methods, "bootstrap")
	log.Printf("%+v", method)
	for _, arg := range method.Args {
		log.Printf("%+v", arg)
	}

	method, _ = abi.GetMethodByName(contract.Methods, "verify")
	log.Printf("%+v", method)

}

func getProof() (groth16.Proof, groth16.VerifyingKey, [][]byte) {
	proof := groth16.NewProof(ecc.BN254)
	{
		f, _ := os.Open("circuit.proof")
		_, err := proof.ReadFrom(f)
		if err != nil {
			log.Fatalf("Failed to read circuit: %+v", err)
		}
		f.Close()
	}

	vk := groth16.NewVerifyingKey(ecc.BN254)
	{
		f, _ := os.Open("circuit.vk")
		_, err := vk.ReadFrom(f)
		if err != nil {
			log.Fatalf("Failed to read circuit: %+v", err)
		}
		f.Close()
	}

	var inputs [][]byte
	{
		b, err := os.ReadFile("circuit.input")
		if err != nil {
			log.Fatalf("Failed to read inputs: %+v", err)
		}
		for x := 0; x < len(b)/32; x += 1 {
			inputs = append(inputs, b[x*32:(x+1)*32])
		}
	}

	return proof, vk, inputs
}

func createProof(x, y uint64) {

	bi := new(big.Int).SetUint64(35)
	ioutil.WriteFile("circuit.input", bi.Bytes(), 0655)

	var cubicCircuit circuit.Circuit
	r1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &cubicCircuit)
	if err != nil {
		log.Fatalf("Failed to compile circuit")
	}
	pk, _ := setupKeys(r1cs)

	assignment := &circuit.Circuit{X: x, Y: y}

	witness, err := frontend.NewWitness(assignment, ecc.BN254)
	if err != nil {
		log.Fatalf("Failed to create witness: %+v", err)
	}

	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		log.Fatalf("Failed to proove: %+v", err)
	}

	b, _ := json.MarshalIndent(proof, "", " ")
	ioutil.WriteFile("proof.json", b, 0655)
	writeToFile("circuit.proof", proof)
}

func getContract() *abi.Contract {
	b, err := ioutil.ReadFile("contract/artifacts/contract.json")
	if err != nil {
		log.Fatalf("Failed to open contract file: %+v", err)
	}
	contract := &abi.Contract{}
	if err := json.Unmarshal(b, contract); err != nil {
		log.Fatalf("Failed to marshal contract: %+v", err)
	}
	return contract
}

func setupKeys(r1cs frontend.CompiledConstraintSystem) (groth16.ProvingKey, groth16.VerifyingKey) {
	// WARNING: Completely insecure, pk should be treated as toxic waste
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		log.Fatalf("Failed to do setup: %+v", err)
	}
	writeToFile("circuit.pk", pk)
	writeToFile("circuit.vk", vk)

	return pk, vk
}

func readKeys() (groth16.ProvingKey, groth16.VerifyingKey) {
	// read proving and verifying keys
	pk := groth16.NewProvingKey(ecc.BN254)
	vk := groth16.NewVerifyingKey(ecc.BN254)

	f, err := os.Open("./cubic.pk")
	if err != nil {
		log.Fatalf("Failed to read pk: %+v", err)
	}
	_, err = pk.ReadFrom(f)
	if err != nil {
		log.Fatalf("Failed to read pk: %+v", err)
	}
	f.Close()

	f, err = os.Open("./cubic.vk")
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
