package sortedlist

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func TestCubicEquation(t *testing.T) {
	assert := test.NewAssert(t)

	var sortedListCircuit = Circuit{
		Z: make([]frontend.Variable, 3),
	}

	assert.ProverSucceeded(&sortedListCircuit, &Circuit{
		Z: []frontend.Variable{1, 2, 3},
	}, test.WithCurves(ecc.BN254))

	assert.ProverFailed(&sortedListCircuit, &Circuit{
		Z: []frontend.Variable{1, 3, 2},
	}, test.WithCurves(ecc.BN254))
}
