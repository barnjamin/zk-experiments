package interact

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"strings"

	"github.com/algorand/go-algorand-sdk/abi"
	"github.com/algorand/go-algorand-sdk/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/future"
	"github.com/algorand/go-algorand-sdk/types"
)

var (
	host  = "http://localhost"
	port  = "4001"
	token = strings.Repeat("a", 64)
)

type ContractClient struct {
	appId    uint64
	client   *algod.Client
	contract *abi.Contract
	acct     crypto.Account
	signer   future.BasicAccountTransactionSigner
}

func NewClient(appId uint64, contractPath string) *ContractClient {
	client, err := algod.MakeClient(fmt.Sprintf("%s:%s", host, port), token)
	if err != nil {
		log.Fatalf("Failed to init client: %+v", err)
	}

	accts, err := GetAccounts()
	if err != nil {
		log.Fatalf("Failed to get accounts: %+v", err)
	}

	b, err := ioutil.ReadFile(contractPath)
	if err != nil {
		log.Fatalf("Failed to open contract file: %+v", err)
	}

	contract := &abi.Contract{}
	if err := json.Unmarshal(b, contract); err != nil {
		log.Fatalf("Failed to marshal contract: %+v", err)
	}

	acct := accts[2]
	return &ContractClient{
		appId:    appId,
		client:   client,
		acct:     acct,
		signer:   future.BasicAccountTransactionSigner{Account: acct},
		contract: contract,
	}

}

func (cc *ContractClient) Bootstrap(vk interface{}) {

	sp, err := cc.client.SuggestedParams().Do(context.Background())
	if err != nil {
		log.Fatalf("Failed to get suggeted params: %+v", err)
	}

	// Skipping error checks below during AddMethodCall and txn create
	var atc = future.AtomicTransactionComposer{}

	m, err := cc.contract.GetMethodByName("bootstrap")
	if err != nil {
		log.Fatalf("No method named bootstrap? %+v", err)
	}
	mcp := future.AddMethodCallParams{
		AppID:           cc.appId,
		Sender:          cc.acct.Address,
		SuggestedParams: sp,
		OnComplete:      types.NoOpOC,
		Method:          m,
		MethodArgs:      []interface{}{vk},
		Signer:          cc.signer,
		BoxReferences:   []types.AppBoxReference{{AppID: cc.appId, Name: []byte("vk")}},
	}

	err = atc.AddMethodCall(mcp)
	if err != nil {
		log.Fatalf("Failed to add method call for bootstrap: %+v", err)
	}

	_, err = atc.Execute(cc.client, context.Background(), 4)
	if err != nil {
		log.Fatalf("Failed to execute call: %+v", err)
	}
}

func (cc *ContractClient) Verify(inputs interface{}, proof interface{}) bool {

	sp, err := cc.client.SuggestedParams().Do(context.Background())
	if err != nil {
		log.Fatalf("Failed to get suggeted params: %+v", err)
	}

	// Skipping error checks below during AddMethodCall and txn create
	var atc = future.AtomicTransactionComposer{}

	m, err := cc.contract.GetMethodByName("verify")
	if err != nil {
		log.Fatalf("No method named verify? %+v", err)
	}
	mcp := future.AddMethodCallParams{
		AppID:           cc.appId,
		Sender:          cc.acct.Address,
		SuggestedParams: sp,
		OnComplete:      types.NoOpOC,
		Method:          m,
		MethodArgs:      []interface{}{inputs, proof},
		Signer:          cc.signer,
		BoxReferences:   []types.AppBoxReference{{AppID: cc.appId, Name: []byte("vk")}},
	}

	err = atc.AddMethodCall(mcp)
	if err != nil {
		log.Fatalf("Failed to add method call for verify: %+v", err)
	}

	ret, err := atc.Execute(cc.client, context.Background(), 4)
	if err != nil {
		log.Fatalf("Failed to execute call: %+v", err)
	}

	return ret.MethodResults[0].ReturnValue.(bool)
}

func getBytesFromResult(inputs interface{}) []*big.Int {
	vals := inputs.([]interface{})
	out := []*big.Int{}
	for _, val := range vals {
		i := val.([]interface{})
		buf := []byte{}
		for _, b := range i {
			buf = append(buf, b.(byte))
		}
		v := new(big.Int).SetBytes(buf)
		out = append(out, v)
	}
	return out
}
