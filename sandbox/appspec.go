package sandbox

import (
	"encoding/base64"
	"log"

	"github.com/algorand/go-algorand-sdk/abi"
	"github.com/algorand/go-algorand-sdk/types"
)

type HintSpec = map[string]Hint

type SchemaSpec struct {
	Local  Schema `json:"local"`
	Global Schema `json:"global"`
}

type AppSources struct {
	Approval string `json:"approval"`
	Clear    string `json:"clear"`
}

type Hint struct {
	Structs          map[string]Struct          `json:"structs"`
	ReadOnly         bool                       `json:"read_only"`
	DefaultArguments map[string]DefaultArgument `json:"default_arguments"`
}

type StructElement = [2]string
type Struct struct {
	Name     string          `json:"name"`
	Elements []StructElement `json:"elements"`
}

type DefaultArgument struct {
	Source string      `json:"source"`
	Data   interface{} `json:"data"`
}

type AVMType uint64

const (
	Uint64 AVMType = 1
	Bytes  AVMType = 2
)

type DeclaredSchemaValueSpec struct {
	Type   AVMType `json:"type"`
	Key    string  `json:"key"`
	Desc   string  `json:"desc"`
	Static bool    `json:"static"`
}

type ReservedSchemaValueSpec struct {
	Type    AVMType `json:"type"`
	Desc    string  `json:"desc"`
	MaxKeys uint64  `json:"max_keys"`
}

type Schema struct {
	Declared map[string]DeclaredSchemaValueSpec `json:"declared"`
	Reserved map[string]ReservedSchemaValueSpec `json:"reserved"`
}

type ApplicationSpecification struct {
	Hints    HintSpec      `json:"hints"`
	Schema   SchemaSpec    `json:"schema"`
	Source   AppSources    `json:"source"`
	Contract *abi.Contract `json:"contract"`
}

func (as ApplicationSpecification) ApprovalProgram() []byte {
	p, err := base64.StdEncoding.DecodeString(as.Source.Approval)
	if err != nil {
		log.Fatalf("couldnt decode approval program: %+v", err)
	}
	return p
}
func (as ApplicationSpecification) ClearProgram() []byte {
	p, err := base64.StdEncoding.DecodeString(as.Source.Clear)
	if err != nil {
		log.Fatalf("couldnt decode clear program: %+v", err)
	}
	return p
}

func (as ApplicationSpecification) GlobalSchema() types.StateSchema {
	gs := types.StateSchema{}
	for _, v := range as.Schema.Global.Declared {
		if v.Type == Uint64 {
			gs.NumUint += 1
		}
		if v.Type == Bytes {
			gs.NumByteSlice += 1
		}
	}

	for _, v := range as.Schema.Global.Reserved {
		if v.Type == Uint64 {
			gs.NumUint += v.MaxKeys
		}
		if v.Type == Bytes {
			gs.NumByteSlice += v.MaxKeys
		}
	}
	return gs
}

func (as ApplicationSpecification) LocalSchema() types.StateSchema {
	ls := types.StateSchema{}
	for _, v := range as.Schema.Local.Declared {
		if v.Type == Uint64 {
			ls.NumUint += 1
		}
		if v.Type == Bytes {
			ls.NumByteSlice += 1
		}
	}

	for _, v := range as.Schema.Local.Reserved {
		if v.Type == Uint64 {
			ls.NumUint += v.MaxKeys
		}
		if v.Type == Bytes {
			ls.NumByteSlice += v.MaxKeys
		}
	}
	return ls
}
