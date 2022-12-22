package sortedlist

import (
	"github.com/consensys/gnark/frontend"
)

type Circuit struct {
	Z []frontend.Variable `gnark:"z"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	for x := 0; x < len(circuit.Z)-1; x++ {
		api.AssertIsLessOrEqual(circuit.Z[x], circuit.Z[x+1])
	}
	return nil
}
