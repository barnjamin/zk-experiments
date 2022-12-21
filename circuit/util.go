package circuit

import (
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"

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

type RawWriter interface {
	WriteRawTo(w io.Writer) (int64, error)
}

type VK struct {
	Alpha1 *bn254.G1Affine
	Beta1  *bn254.G1Affine
	Delta1 *bn254.G1Affine

	Beta2  *bn254.G2Affine
	Gamma2 *bn254.G2Affine
	Delta2 *bn254.G2Affine

	IC []bn254.G1Affine
}

func NewVKFromFile(path string) *VK {
	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("Failed to read file: %+v", err)
	}
	defer f.Close()

	dec := bn254.NewDecoder(f)

	a1 := &bn254.G1Affine{}
	err = dec.Decode(a1)
	if err != nil {
		log.Fatalf("Failed to decode a1: %+v", err)
	}

	b1 := &bn254.G1Affine{}
	err = dec.Decode(b1)
	if err != nil {
		log.Fatalf("Failed to decode b1: %+v", err)
	}

	b2 := &bn254.G2Affine{}
	err = dec.Decode(b2)
	if err != nil {
		log.Fatalf("Failed to decode b2: %+v", err)
	}

	g2 := &bn254.G2Affine{}
	err = dec.Decode(g2)
	if err != nil {
		log.Fatalf("Failed to decode g2: %+v", err)
	}

	d1 := &bn254.G1Affine{}
	err = dec.Decode(d1)
	if err != nil {
		log.Fatalf("Failed to decode d1: %+v", err)
	}

	d2 := &bn254.G2Affine{}
	err = dec.Decode(d2)
	if err != nil {
		log.Fatalf("Failed to decode d2: %+v", err)
	}

	ics := []bn254.G1Affine{}
	err = dec.Decode(&ics)
	if err != nil {
		log.Fatalf("Failed to decode ics: %+v", err)
	}

	return &VK{
		Alpha1: a1,
		Beta2:  b2,
		Gamma2: g2,
		Delta2: d2,
		IC:     ics,
	}

}

func (v *VK) ToABITuple() interface{} {
	tuple := []interface{}{}

	// A
	tuple = append(tuple, []interface{}{v.Alpha1.X.Bytes(), v.Alpha1.Y.Bytes()})

	// B
	tuple = append(tuple, [][]interface{}{
		{v.Beta2.X.A0.Bytes(), v.Beta2.X.A1.Bytes()},
		{v.Beta2.Y.A0.Bytes(), v.Beta2.Y.A1.Bytes()},
	})

	// D
	tuple = append(tuple, [][]interface{}{
		{v.Delta2.X.A0.Bytes(), v.Delta2.X.A1.Bytes()},
		{v.Delta2.Y.A0.Bytes(), v.Delta2.Y.A1.Bytes()},
	})

	// G
	tuple = append(tuple, [][]interface{}{
		{v.Gamma2.X.A0.Bytes(), v.Gamma2.X.A1.Bytes()},
		{v.Gamma2.Y.A0.Bytes(), v.Gamma2.Y.A1.Bytes()},
	})

	// IC
	ics := []interface{}{}
	for _, ic := range v.IC {
		ics = append(ics, []interface{}{ic.X.Bytes(), ic.Y.Bytes()})
	}
	tuple = append(tuple, ics)

	return tuple
}

type Proof struct {
	Ar, Krs *bn254.G1Affine
	Bs      *bn254.G2Affine
}

func NewProofFromFile(path string) *Proof {
	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("Failed to read file: %+v", err)
	}
	defer f.Close()

	dec := bn254.NewDecoder(f)

	ar := &bn254.G1Affine{}
	err = dec.Decode(ar)
	if err != nil {
		log.Fatalf("Failed to decode ar: %+v", err)
	}

	bs := &bn254.G2Affine{}
	err = dec.Decode(bs)
	if err != nil {
		log.Fatalf("Failed to decode bs: %+v", err)
	}

	kr := &bn254.G1Affine{}
	err = dec.Decode(kr)
	if err != nil {
		log.Fatalf("Failed to decode Krs: %+v", err)
	}

	return &Proof{
		Ar:  ar,
		Krs: kr,
		Bs:  bs,
	}

}

func (p *Proof) ToABITuple() interface{} {
	tuple := []interface{}{}

	// A
	tuple = append(tuple, []interface{}{p.Ar.X.Bytes(), p.Ar.Y.Bytes()})

	// Kr
	tuple = append(tuple, []interface{}{p.Krs.X.Bytes(), p.Krs.Y.Bytes()})

	// Bs
	tuple = append(tuple, [][]interface{}{
		{p.Bs.X.A0.Bytes(), p.Bs.X.A1.Bytes()},
		{p.Bs.Y.A0.Bytes(), p.Bs.Y.A1.Bytes()},
	})

	return tuple
}

func Linearize(input []*big.Int, vk *VK) *bn254.G1Affine {
	// Make sure that every input is less than the snark scalar field
	vk_x := &bn254.G1Affine{}
	for idx := 0; idx < len(input); idx++ {
		ic := &vk.IC[idx+1]
		ic = ic.ScalarMultiplication(ic, input[idx])

		vk_x = vk_x.Add(vk_x, ic)
	}
	return vk_x.Add(vk_x, &vk.IC[0])
}

func CheckValidPairing(proof *Proof, vk *VK, vk_x *bn254.G1Affine) (bool, error) {

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

	log.Printf("%+v", P)
	log.Printf("%+v", Q)

	return bn254.PairingCheck(P, Q)
}

func InputsAsAbiTuple(inputs []*big.Int) interface{} {
	tuple := make([]interface{}, len(inputs))
	for idx, i := range inputs {
		tuple[idx] = i.FillBytes(make([]byte, 32))
	}
	return tuple
}

func GetProof() (*Proof, *VK, []*big.Int) {
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
