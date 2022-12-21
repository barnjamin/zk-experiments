package circuit

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
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

type RawWriter interface {
	WriteRawTo(w io.Writer) (int64, error)
}

func InputsAsAbiTuple(inputs [][]byte) interface{} {
	return inputs
}

func ProofAsABITuple(proof groth16.Proof) interface{} {
	m := asMap(proof)

	tuple := []interface{}{}

	// Add A
	tuple = append(tuple, asg1([]interface{}{
		m["Ar"]["X"], m["Ar"]["Y"],
	}))

	// Add B
	bs_x := m["Bs"]["X"].(map[string]interface{})
	bs_y := m["Bs"]["Y"].(map[string]interface{})
	tuple = append(tuple, [2][2][32]byte{
		asg1([]interface{}{bs_x["A0"], bs_x["A1"]}),
		asg1([]interface{}{bs_y["A0"], bs_y["A1"]}),
	})

	// Add C
	tuple = append(tuple, asg1([]interface{}{
		m["Krs"]["X"], m["Krs"]["Y"],
	}))

	return tuple
}

func VkAsABITuple(vk groth16.VerifyingKey) interface{} {
	tuple := []interface{}{}

	m := asMap(vk)

	a1 := m["G1"]["Alpha"].(map[string]interface{})
	tuple = append(tuple, asg1([]interface{}{
		a1["X"], a1["Y"],
	}))

	b2 := m["G2"]["Beta"].(map[string]interface{})
	b2_x := b2["X"].(map[string]interface{})
	b2_y := b2["Y"].(map[string]interface{})
	tuple = append(tuple, [2][2][32]byte{
		asg1([]interface{}{b2_x["A0"], b2_x["A1"]}),
		asg1([]interface{}{b2_y["A0"], b2_y["A1"]}),
	})

	d2 := m["G2"]["Delta"].(map[string]interface{})
	d2_x := d2["X"].(map[string]interface{})
	d2_y := d2["Y"].(map[string]interface{})
	tuple = append(tuple, [2][2][32]byte{
		asg1([]interface{}{d2_x["A0"], d2_x["A1"]}),
		asg1([]interface{}{d2_y["A0"], d2_y["A1"]}),
	})

	g2 := m["G2"]["Gamma"].(map[string]interface{})
	g2_x := g2["X"].(map[string]interface{})
	g2_y := g2["Y"].(map[string]interface{})
	tuple = append(tuple, [2][2][32]byte{
		asg1([]interface{}{g2_x["A0"], g2_x["A1"]}),
		asg1([]interface{}{g2_y["A0"], g2_y["A1"]}),
	})

	ic := m["G1"]["K"].([]interface{})
	ic_arr := []interface{}{}
	for _, i := range ic {
		ig1 := i.(map[string]interface{})
		ic_arr = append(ic_arr, asg1([]interface{}{
			ig1["X"], ig1["Y"],
		}))
	}
	tuple = append(tuple, ic_arr)

	return tuple
}

// Hack because i cant access the `internal`
// package of gnark, and too lazy to figure out
// how the binary file is structured
func asMap(x interface{}) map[string]map[string]interface{} {
	b, err := json.Marshal(x)
	if err != nil {
		log.Fatalf("Failed to marshal to json: %+v", err)
	}

	m := map[string]map[string]interface{}{}
	json.Unmarshal(b, &m)
	return m
}

func GetProof() (groth16.Proof, groth16.VerifyingKey, [][]byte) {
	proof := groth16.NewProof(ecc.BN254)
	{
		f, _ := os.Open(PROOF_FILE)
		_, err := proof.ReadFrom(f)
		if err != nil {
			log.Fatalf("Failed to read circuit: %+v", err)
		}
		f.Close()
	}

	vk := groth16.NewVerifyingKey(ecc.BN254)
	{
		f, _ := os.Open(VK_FILE)
		_, err := vk.ReadFrom(f)
		if err != nil {
			log.Fatalf("Failed to read circuit: %+v", err)
		}
		f.Close()
	}

	var inputs [][]byte
	{
		b, err := os.ReadFile(INPUT_FILE)
		if err != nil {
			log.Fatalf("Failed to read inputs: %+v", err)
		}
		for x := 0; x < len(b)/32; x += 1 {
			inputs = append(inputs, b[x*32:(x+1)*32])
		}
	}

	return proof, vk, inputs
}

func asg1(pts []interface{}) [2][32]byte {
	n_x, _ := new(big.Int).SetString(pts[0].(string), 10)
	x := [32]byte{}
	copy(x[:], n_x.Bytes())

	n_y, _ := new(big.Int).SetString(pts[1].(string), 10)
	y := [32]byte{}
	copy(y[:], n_y.Bytes())

	v := [2][32]byte{x, y}
	return v
}

func CreateProof(x, y uint64) {
	var cubicCircuit Circuit
	r1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &cubicCircuit)
	if err != nil {
		log.Fatalf("Failed to compile circuit")
	}
	// pk, _ := setupKeys(r1cs)
	pk, _ := readKeys()

	witness, err := frontend.NewWitness(&Circuit{X: x, Y: y}, ecc.BN254)
	if err != nil {
		log.Fatalf("Failed to create witness: %+v", err)
	}

	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		log.Fatalf("Failed to create proof: %+v", err)
	}
	writeToFile(PROOF_FILE, proof)

	// TODO: idk if this actually writes 32 bytes?
	input := new(big.Int).SetUint64(x)
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

func readKeys() (groth16.ProvingKey, groth16.VerifyingKey) {
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
