package circuits

// The gnark library has curve specific types in an internal package
// so this is pmuch copy/paste from there

import (
	"io"
	"log"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
)

type Writer interface {
	WriteTo(w io.Writer) (int64, error)
}

func InputsAsAbiTuple(inputs []*big.Int) interface{} {
	tuple := make([]interface{}, len(inputs))
	for idx, i := range inputs {
		tuple[idx] = i.FillBytes(make([]byte, 32))
	}
	return tuple
}

type VK struct {
	// Size circuit
	Size              uint64
	SizeInv           fr.Element
	Generator         fr.Element
	NbPublicVariables uint64

	// Commitment scheme that is used for an instantiation of PLONK
	KZGSRS *kzg.SRS

	// cosetShift generator of the coset on the small domain
	CosetShift fr.Element

	// S commitments to S1, S2, S3
	S [3]kzg.Digest

	// Commitments to ql, qr, qm, qo prepended with as many zeroes (ones for l) as there are public inputs.
	// In particular Qk is not complete.
	Ql, Qr, Qm, Qo, Qk kzg.Digest
}

func (vk *VK) ReadFrom(r io.Reader) (int64, error) {
	dec := bn254.NewDecoder(r)
	toDecode := []interface{}{
		&vk.Size,
		&vk.SizeInv,
		&vk.Generator,
		&vk.NbPublicVariables,
		&vk.S[0],
		&vk.S[1],
		&vk.S[2],
		&vk.Ql,
		&vk.Qr,
		&vk.Qm,
		&vk.Qo,
		&vk.Qk,
	}

	for _, v := range toDecode {
		if err := dec.Decode(v); err != nil {
			return dec.BytesRead(), err
		}
	}

	return dec.BytesRead(), nil
}

func NewVKFromFile(path string) *VK {
	vk := &VK{}

	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("Failed to read file: %+v", err)
	}
	defer f.Close()

	_, err = vk.ReadFrom(f)
	if err != nil {
		log.Fatalf("Failed to read vk from file: %+v", err)
	}

	return vk
}

func (v *VK) ToABITuple() interface{} {
	tuple := []interface{}{}

	// A
	// tuple = append(tuple, []interface{}{v.Alpha1.X.Bytes(), v.Alpha1.Y.Bytes()})

	// // B
	// tuple = append(tuple, [][]interface{}{
	// 	{v.Beta2.X.A0.Bytes(), v.Beta2.X.A1.Bytes()},
	// 	{v.Beta2.Y.A0.Bytes(), v.Beta2.Y.A1.Bytes()},
	// })

	// // G
	// tuple = append(tuple, [][]interface{}{
	// 	{v.Gamma2.X.A0.Bytes(), v.Gamma2.X.A1.Bytes()},
	// 	{v.Gamma2.Y.A0.Bytes(), v.Gamma2.Y.A1.Bytes()},
	// })

	// // D
	// tuple = append(tuple, [][]interface{}{
	// 	{v.Delta2.X.A0.Bytes(), v.Delta2.X.A1.Bytes()},
	// 	{v.Delta2.Y.A0.Bytes(), v.Delta2.Y.A1.Bytes()},
	// })

	// // IC
	// ics := []interface{}{}
	// for _, ic := range v.IC {
	// 	ics = append(ics, []interface{}{ic.X.Bytes(), ic.Y.Bytes()})
	// }
	// tuple = append(tuple, ics)

	return tuple
}

type Proof struct {
	// Commitments to the solution vectors
	LRO [3]kzg.Digest

	// Commitment to Z, the permutation polynomial
	Z kzg.Digest

	// Commitments to h1, h2, h3 such that h = h1 + Xh2 + X**2h3 is the quotient polynomial
	H [3]kzg.Digest

	// Batch opening proof of h1 + zeta*h2 + zeta**2h3, linearizedPolynomial, l, r, o, s1, s2
	BatchedProof kzg.BatchOpeningProof

	// Opening proof of Z at zeta*mu
	ZShiftedOpening kzg.OpeningProof
}

func (proof *Proof) ReadFrom(r io.Reader) (int64, error) {
	dec := bn254.NewDecoder(r)
	toDecode := []interface{}{
		&proof.LRO[0],
		&proof.LRO[1],
		&proof.LRO[2],
		&proof.Z,
		&proof.H[0],
		&proof.H[1],
		&proof.H[2],
	}

	for _, v := range toDecode {
		if err := dec.Decode(v); err != nil {
			return dec.BytesRead(), err
		}
	}

	n, err := proof.BatchedProof.ReadFrom(r)
	if err != nil {
		return n + dec.BytesRead(), err
	}
	n2, err := proof.ZShiftedOpening.ReadFrom(r)
	return n + n2 + dec.BytesRead(), err
}

func NewProofFromFile(path string) *Proof {
	proof := &Proof{}

	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("Failed to read file: %+v", err)
	}
	defer f.Close()

	_, err = proof.ReadFrom(f)
	if err != nil {
		log.Fatalf("Failed to read from file: %+v", err)
	}

	return proof
}

func (p *Proof) ToABITuple() interface{} {
	tuple := []interface{}{}

	//// A
	//tuple = append(tuple, []interface{}{p.Ar.X.Bytes(), p.Ar.Y.Bytes()})

	//// B
	//tuple = append(tuple, [][]interface{}{
	//	{p.Bs.X.A0.Bytes(), p.Bs.X.A1.Bytes()},
	//	{p.Bs.Y.A0.Bytes(), p.Bs.Y.A1.Bytes()},
	//})

	//// C
	//tuple = append(tuple, []interface{}{p.Krs.X.Bytes(), p.Krs.Y.Bytes()})

	return tuple
}

type ProvingKey struct {
	// Verifying Key is embedded into the proving key (needed by Prove)
	Vk *VK

	// qr,ql,qm,qo (in canonical basis).
	Ql, Qr, Qm, Qo []fr.Element

	// LQk (CQk) qk in Lagrange basis (canonical basis), prepended with as many zeroes as public inputs.
	// Storing LQk in Lagrange basis saves a fft...
	CQk, LQk []fr.Element

	// Domains used for the FFTs.
	// Domain[0] = small Domain
	// Domain[1] = big Domain
	Domain [2]fft.Domain
	// Domain[0], Domain[1] fft.Domain

	// Permutation polynomials
	EvaluationPermutationBigDomainBitReversed []fr.Element
	S1Canonical, S2Canonical, S3Canonical     []fr.Element

	// position -> permuted position (position in [0,3*sizeSystem-1])
	Permutation []int64
}

func (pk *ProvingKey) ReadFrom(r io.Reader) (int64, error) {
	pk.Vk = &VK{}
	n, err := pk.Vk.ReadFrom(r)
	if err != nil {
		return n, err
	}

	n2, err := pk.Domain[0].ReadFrom(r)
	n += n2
	if err != nil {
		return n, err
	}

	n2, err = pk.Domain[1].ReadFrom(r)
	n += n2
	if err != nil {
		return n, err
	}

	pk.Permutation = make([]int64, 3*pk.Domain[0].Cardinality)

	dec := bn254.NewDecoder(r)
	toDecode := []interface{}{
		(*[]fr.Element)(&pk.Ql),
		(*[]fr.Element)(&pk.Qr),
		(*[]fr.Element)(&pk.Qm),
		(*[]fr.Element)(&pk.Qo),
		(*[]fr.Element)(&pk.CQk),
		(*[]fr.Element)(&pk.LQk),
		(*[]fr.Element)(&pk.S1Canonical),
		(*[]fr.Element)(&pk.S2Canonical),
		(*[]fr.Element)(&pk.S3Canonical),
		&pk.Permutation,
	}

	for _, v := range toDecode {
		if err := dec.Decode(v); err != nil {
			return n + dec.BytesRead(), err
		}
	}

	return n + dec.BytesRead(), nil
}

func NewProvingKeyFromFile(name string) *ProvingKey {
	pk := &ProvingKey{}

	f, err := os.Open(name)
	if err != nil {
		log.Fatalf("Failed to open file: %+v", err)
	}
	defer f.Close()

	_, err = pk.ReadFrom(f)
	if err != nil {
		log.Fatalf("Failed to read from file: %+v", err)
	}
	return pk
}
