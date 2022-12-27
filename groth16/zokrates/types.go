package zokrates

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"log"
	"math/big"
	"os"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

func InputsAsAbiTuple(inputs []*big.Int) interface{} {
	tuple := make([]interface{}, len(inputs))
	for idx, i := range inputs {
		tuple[idx] = i.FillBytes(make([]byte, 32))
	}
	return tuple
}

type VK struct {
	Alpha1 *bls12381.G1Affine
	Beta1  *bls12381.G1Affine
	Delta1 *bls12381.G1Affine

	Beta2  *bls12381.G2Affine
	Gamma2 *bls12381.G2Affine
	Delta2 *bls12381.G2Affine

	IC []bls12381.G1Affine
}

type zkvk struct {
	Scheme   string       `json:"scheme"`
	Curve    string       `json:"curve"`
	Alpha    [2]string    `json:"alpha"`
	Beta     [2][2]string `json:"beta"`
	Gamma    [2][2]string `json:"gamma"`
	Delta    [2][2]string `json:"delta"`
	GammaABC [][2]string  `json:"gamma_abc"`
}

func NewVKFromFile(path string) *VK {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read file: %+v", err)
	}

	z := &zkvk{}
	err = json.Unmarshal(b, z)
	if err != nil {
		log.Fatalf("Failed to unmarshal bytes: %+v", err)
	}

	ics := []bls12381.G1Affine{}
	for _, ic := range z.GammaABC {
		ics = append(ics, *decodeG1(ic))
	}

	vk := &VK{
		Alpha1: decodeG1(z.Alpha),
		Beta2:  decodeG2(z.Beta),
		Gamma2: decodeG2(z.Gamma),
		Delta2: decodeG2(z.Delta),
		IC:     ics,
	}

	return vk
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

	// G
	tuple = append(tuple, [][]interface{}{
		{v.Gamma2.X.A0.Bytes(), v.Gamma2.X.A1.Bytes()},
		{v.Gamma2.Y.A0.Bytes(), v.Gamma2.Y.A1.Bytes()},
	})

	// D
	tuple = append(tuple, [][]interface{}{
		{v.Delta2.X.A0.Bytes(), v.Delta2.X.A1.Bytes()},
		{v.Delta2.Y.A0.Bytes(), v.Delta2.Y.A1.Bytes()},
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
	Ar, Krs *bls12381.G1Affine
	Bs      *bls12381.G2Affine
	Inputs  []*big.Int
}

type zkp struct {
	Scheme string `json:"scheme"`
	Curve  string `json:"curve"`
	Proof  struct {
		A [2]string    `json:"a"`
		B [2][2]string `json:"b"`
		C [2]string    `json:"c"`
	} `json:"proof"`
	Inputs []string `json:"inputs"`
}

func NewProofFromFile(path string) *Proof {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read file: %+v", err)
	}

	z := &zkp{}
	err = json.Unmarshal(b, z)
	if err != nil {
		log.Fatalf("Failed to unmarshal proof: %+v", err)
	}

	inputs := []*big.Int{}
	for _, inp := range z.Inputs {
		decoded, _ := hex.DecodeString(inp[2:])
		inputs = append(inputs, new(big.Int).SetBytes(decoded))
	}

	p := &Proof{
		Ar:     decodeG1(z.Proof.A),
		Krs:    decodeG1(z.Proof.C),
		Bs:     decodeG2(z.Proof.B),
		Inputs: inputs,
	}
	return p
}

func (p *Proof) ToABITuple() interface{} {
	tuple := []interface{}{}

	// A
	tuple = append(tuple, []interface{}{p.Ar.X.Bytes(), p.Ar.Y.Bytes()})

	// B
	tuple = append(tuple, [][]interface{}{
		{p.Bs.X.A0.Bytes(), p.Bs.X.A1.Bytes()},
		{p.Bs.Y.A0.Bytes(), p.Bs.Y.A1.Bytes()},
	})

	// C
	tuple = append(tuple, []interface{}{p.Krs.X.Bytes(), p.Krs.Y.Bytes()})

	return tuple
}

type ProvingKey struct {
	G1 struct {
		Alpha, Beta, Delta bls12381.G1Affine
		A, B, Z            []bls12381.G1Affine
		K                  []bls12381.G1Affine // the indexes correspond to the private wires
	}

	G2 struct {
		Beta, Delta bls12381.G2Affine
		B           []bls12381.G2Affine
	}

	InfinityA, InfinityB     []bool
	NbInfinityA, NbInfinityB uint64
}

func NewProvingKeyFromFile(name string) *ProvingKey {

	pk := &ProvingKey{}
	f, err := os.Open(name)
	if err != nil {
		log.Fatalf("Failed to open file: %+v", err)
	}
	defer f.Close()

	var nbWires uint64

	dec := bls12381.NewDecoder(f)

	toDecode := []interface{}{
		&pk.G1.Alpha,
		&pk.G1.Beta,
		&pk.G1.Delta,
		&pk.G1.A,
		&pk.G1.B,
		&pk.G1.Z,
		&pk.G1.K,
		&pk.G2.Beta,
		&pk.G2.Delta,
		&pk.G2.B,
		&nbWires,
		&pk.NbInfinityA,
		&pk.NbInfinityB,
	}

	for _, v := range toDecode {
		if err := dec.Decode(v); err != nil {
			log.Fatalf("Failed to decode: %+v", err)
		}
	}
	pk.InfinityA = make([]bool, nbWires)
	pk.InfinityB = make([]bool, nbWires)

	if err := dec.Decode(&pk.InfinityA); err != nil {
		log.Fatalf("Failed to decode: %+v", err)
	}
	if err := dec.Decode(&pk.InfinityB); err != nil {
		log.Fatalf("Failed to decode: %+v", err)
	}

	return pk

}

func decodeG1(raw [2]string) *bls12381.G1Affine {
	pt := &bls12381.G1Affine{}

	x, err := hex.DecodeString(raw[0][2:])
	if err != nil {
		log.Fatalf("Failed to decode string: %+v", err)
	}
	pt.X.SetBytes(x)

	y, err := hex.DecodeString(raw[1][2:])
	if err != nil {
		log.Fatalf("Failed to decode string: %+v", err)
	}
	pt.Y.SetBytes(y)

	return pt
}

func decodeG2(raw [2][2]string) *bls12381.G2Affine {
	pt := &bls12381.G2Affine{}

	x1, err := hex.DecodeString(raw[0][0][2:])
	if err != nil {
		log.Fatalf("Failed to decode string: %+v", err)
	}
	pt.X.A0.SetBytes(x1)

	x2, err := hex.DecodeString(raw[0][1][2:])
	if err != nil {
		log.Fatalf("Failed to decode string: %+v", err)
	}
	pt.X.A1.SetBytes(x2)

	y1, err := hex.DecodeString(raw[1][0][2:])
	if err != nil {
		log.Fatalf("Failed to decode string: %+v", err)
	}
	pt.Y.A0.SetBytes(y1)

	y2, err := hex.DecodeString(raw[1][1][2:])
	if err != nil {
		log.Fatalf("Failed to decode string: %+v", err)
	}
	pt.Y.A1.SetBytes(y2)

	return pt
}
