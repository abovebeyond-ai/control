package anchor

import (
	"context"
	"errors"
	"regexp"
	"strings"

	hiero "github.com/hiero-ledger/hiero-sdk-go/v2/sdk"
)

// Operator is the Hedera account that pays for anchors: money, not identity.
type Operator struct {
	Network    string `json:"network"`
	AccountID  string `json:"accountId"`
	PrivateKey string `json:"privateKey"`
	TopicID    string `json:"topicId"`
}

// SDKSubmitter posts through the Hiero SDK.
type SDKSubmitter struct{ Operator Operator }

var txIDForm = regexp.MustCompile(`@(\d+)\.(\d+)$`)

func (s SDKSubmitter) Submit(ctx context.Context, topicID string, message []byte) (int64, string, error) {
	var client *hiero.Client
	switch s.Operator.Network {
	case "mainnet":
		client = hiero.ClientForMainnet()
	case "testnet", "":
		client = hiero.ClientForTestnet()
	default:
		return 0, "", errors.New("unknown Hedera network " + s.Operator.Network)
	}
	defer client.Close()
	account, err := hiero.AccountIDFromString(s.Operator.AccountID)
	if err != nil {
		return 0, "", err
	}
	var key hiero.PrivateKey
	if strings.HasPrefix(s.Operator.PrivateKey, "3030") {
		key, err = hiero.PrivateKeyFromStringECDSA(s.Operator.PrivateKey)
	} else {
		key, err = hiero.PrivateKeyFromStringEd25519(s.Operator.PrivateKey)
	}
	if err != nil {
		return 0, "", err
	}
	client.SetOperator(account, key)
	topic, err := hiero.TopicIDFromString(topicID)
	if err != nil {
		return 0, "", err
	}
	resp, err := hiero.NewTopicMessageSubmitTransaction().SetTopicID(topic).SetMessage(message).Execute(client)
	if err != nil {
		return 0, "", err
	}
	receipt, err := resp.GetReceipt(client)
	if err != nil {
		return 0, "", err
	}
	// HashScan reads the id as 0.0.x-seconds-nanos; the SDK prints 0.0.x@seconds.nanos.
	txID := txIDForm.ReplaceAllString(resp.TransactionID.String(), "-$1-$2")
	return int64(receipt.TopicSequenceNumber), txID, nil
}
