package sandbox

import (
	"context"
	"encoding/base64"
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
	appId      uint64
	appAddress string
	client     *algod.Client
	contract   *abi.Contract
	acct       crypto.Account
	signer     future.BasicAccountTransactionSigner
	appSpec    *ApplicationSpecification
}

func NewClient(appSpecPath string, appId uint64) *ContractClient {
	client, err := algod.MakeClient(fmt.Sprintf("%s:%s", host, port), token)
	if err != nil {
		log.Fatalf("Failed to init client: %+v", err)
	}

	accts, err := GetAccounts()
	if err != nil {
		log.Fatalf("Failed to get accounts: %+v", err)
	}

	b, err := ioutil.ReadFile(appSpecPath)
	if err != nil {
		log.Fatalf("Failed to open contract file: %+v", err)
	}

	appSpec := &ApplicationSpecification{}
	if err := json.Unmarshal(b, appSpec); err != nil {
		log.Fatalf("Failed to marshal contract: %+v", err)
	}

	acct := accts[2]
	return &ContractClient{
		appId:      appId,
		client:     client,
		acct:       acct,
		signer:     future.BasicAccountTransactionSigner{Account: acct},
		contract:   appSpec.Contract,
		appSpec:    appSpec,
		appAddress: crypto.GetApplicationAddress(appId).String(),
	}

}

func (cc *ContractClient) compile(tealProg []byte) []byte {
	res, err := cc.client.TealCompile(tealProg).Do(context.Background())
	if err != nil {
		log.Fatalf("Failed to compile program: %+v", err)
	}
	bin, err := base64.StdEncoding.DecodeString(res.Result)
	if err != nil {
		log.Fatalf("Failed to decode program: %+v", err)
	}
	return bin
}

func (cc *ContractClient) Create() uint64 {
	sp, err := cc.client.SuggestedParams().Do(context.Background())
	if err != nil {
		log.Fatalf("Failed to get suggeted params: %+v", err)
	}
	approvalBin := cc.compile(cc.appSpec.ApprovalProgram())
	clearBin := cc.compile(cc.appSpec.ClearProgram())

	var atc = future.AtomicTransactionComposer{}

	appCreateTxn, err := future.MakeApplicationCreateTx(
		false, approvalBin, clearBin, cc.appSpec.GlobalSchema(), cc.appSpec.LocalSchema(), nil, nil, nil, nil, sp, cc.acct.Address, nil, types.Digest{}, [32]byte{}, types.ZeroAddress,
	)
	if err != nil {
		log.Fatalf("Failed to create app call txn: %+v", err)
	}

	stxn := future.TransactionWithSigner{Txn: appCreateTxn, Signer: cc.signer}
	atc.AddTransaction(stxn)

	exRes, err := atc.Execute(cc.client, context.Background(), 4)
	if err != nil {
		log.Fatalf("Failed to execute call: %+v", err)
	}

	result, _, err := cc.client.PendingTransactionInformation(exRes.TxIDs[0]).Do(context.Background())
	if err != nil {
		log.Fatalf("%+v", err)
	}
	cc.appId = result.ApplicationIndex
	cc.appAddress = crypto.GetApplicationAddress(result.ApplicationIndex).String()

	return result.ApplicationIndex
}

func (cc *ContractClient) Update() {

}

func (cc *ContractClient) Fund(amt uint64) {
	sp, err := cc.client.SuggestedParams().Do(context.Background())
	if err != nil {
		log.Fatalf("Failed to get suggeted params: %+v", err)
	}
	var atc = future.AtomicTransactionComposer{}

	payTxn, err := future.MakePaymentTxn(cc.acct.Address.String(), cc.appAddress, amt, nil, "", sp)
	if err != nil {
		log.Fatalf("Failed to create app call txn: %+v", err)
	}

	stxn := future.TransactionWithSigner{Txn: payTxn, Signer: cc.signer}
	atc.AddTransaction(stxn)

	_, err = atc.Execute(cc.client, context.Background(), 4)
	if err != nil {
		log.Fatalf("Failed to execute call: %+v", err)
	}
}

func (cc *ContractClient) Bootstrap(vk interface{}) {

	sp, err := cc.client.SuggestedParams().Do(context.Background())
	if err != nil {
		log.Fatalf("Failed to get suggeted params: %+v", err)
	}

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
