package circuit

// The gnark library has curve specific types in an internal package
// so this is pmuch copy/paste from there

import (
	"io"
	"log"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
)

type RawWriter interface {
	WriteRawTo(w io.Writer) (int64, error)
}

func InputsAsAbiTuple(inputs []*big.Int) interface{} {
	tuple := make([]interface{}, len(inputs))
	for idx, i := range inputs {
		tuple[idx] = i.FillBytes(make([]byte, 32))
	}
	return tuple
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
	Domain fft.Domain
	G1     struct {
		Alpha, Beta, Delta bn254.G1Affine
		A, B, Z            []bn254.G1Affine
		K                  []bn254.G1Affine // the indexes correspond to the private wires
	}

	G2 struct {
		Beta, Delta bn254.G2Affine
		B           []bn254.G2Affine
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

	var domain fft.Domain
	domain.ReadFrom(f)

	var nbWires uint64

	dec := bn254.NewDecoder(f)

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
