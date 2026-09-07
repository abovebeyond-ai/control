// Package anchor pins a gateway's signed checkpoint outside the operator's
// control. It runs OUTSIDE the trusted boundary and needs no trust: it can
// prove nothing false, because the checkpoint it posts is signed by the
// gateway and the receipt it keeps is verified against that signature; the
// worst it can do is not anchor, and the verifier detects a missed interval.
//
// Two backends from the start, so no ledger is load-bearing: an RFC 3161
// timestamp authority (a signed timestamp over the checkpoint's hash, no
// account, understood by every auditor) and Hedera Consensus Service (a
// consensus timestamp from a public ledger, read back from a mirror node).
// The standard accepts either (7.2.2); a client's own ledger is a third.
package anchor

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/abovebeyond-ai/control/canonical"
	"github.com/abovebeyond-ai/control/gateway"
	"github.com/abovebeyond-ai/control/log"
	"github.com/digitorus/timestamp"
)

// CheckpointBytesUnsigned is what the gateway signs: the checkpoint without its signature.
func CheckpointBytesUnsigned(cp gateway.Checkpoint) ([]byte, error) {
	return canonical.Encode(map[string]any{"agent": cp.Agent, "tree_size": cp.TreeSize, "root": cp.Root, "chain_head": cp.ChainHead})
}

func sha(b []byte) string { return canonical.SHA256(b) }

// CheckpointBytes is the message an anchor commits to: the signed checkpoint
// in canonical form. Small enough for a consensus message, exact enough that
// two anchorers of the same checkpoint commit to the same bytes.
func CheckpointBytes(cp gateway.Checkpoint) ([]byte, error) {
	return canonical.Encode(map[string]any{"agent": cp.Agent, "tree_size": cp.TreeSize, "root": cp.Root, "chain_head": cp.ChainHead, "signature": cp.Signature})
}

// Receipt is what is kept: the checkpoint, which backend, and what the
// backend returned, read back the way a stranger reads it.
type Receipt struct {
	Backend    string             `json:"backend"`
	Checkpoint gateway.Checkpoint `json:"checkpoint"`
	MessageSHA string             `json:"message_sha256"`
	AnchoredAt string             `json:"anchored_at"`
	TSA        *TSAReceipt        `json:"tsa,omitempty"`
	Hedera     *HederaReceipt     `json:"hedera,omitempty"`
}

// TSAReceipt: the RFC 3161 token, DER, base64, plus what it says.
type TSAReceipt struct {
	URL       string    `json:"url"`
	TokenB64  string    `json:"token"`
	Time      time.Time `json:"time"`
	Serial    string    `json:"serial"`
	SignerCN  string    `json:"signer"`
	CertCount int       `json:"certificates"`
}

// HederaReceipt: the mirror node's answer for the message.
type HederaReceipt struct {
	Network            string `json:"network"`
	TopicID            string `json:"topicId"`
	SequenceNumber     int64  `json:"sequenceNumber"`
	ConsensusTimestamp string `json:"consensusTimestamp"`
	RunningHash        string `json:"runningHash"`
	PayerAccountID     string `json:"payerAccountId"`
	TransactionID      string `json:"transactionId"`
	Mirror             string `json:"mirror"`
	HashScanTopic      string `json:"hashscanTopic"`
}

// Backend publishes checkpoint bytes and fills the receipt.
type Backend interface {
	Name() string
	Publish(ctx context.Context, message []byte, r *Receipt) error
	// Verify checks a receipt against the message; network may be false to
	// check only what the receipt carries (a TSA token verifies offline; a
	// Hedera receipt needs the mirror node for the WHEN).
	Verify(ctx context.Context, message []byte, r *Receipt, network bool) error
}

// TSA is an RFC 3161 timestamp authority.
type TSA struct {
	URL    string
	Client *http.Client
}

func (t TSA) Name() string { return "rfc3161" }

func (t TSA) Publish(ctx context.Context, message []byte, r *Receipt) error {
	req, err := timestamp.CreateRequest(bytes.NewReader(message), &timestamp.RequestOptions{Hash: crypto.SHA256, Certificates: true})
	if err != nil {
		return err
	}
	hreq, err := http.NewRequestWithContext(ctx, "POST", t.URL, bytes.NewReader(req))
	if err != nil {
		return err
	}
	hreq.Header.Set("Content-Type", "application/timestamp-query")
	client := t.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	res, err := client.Do(hreq)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("the timestamp authority answered %d", res.StatusCode)
	}
	ts, err := timestamp.ParseResponse(raw)
	if err != nil {
		return fmt.Errorf("the timestamp authority's response does not parse: %w", err)
	}
	sum := sha256.Sum256(message)
	if !bytes.Equal(ts.HashedMessage, sum[:]) {
		return errors.New("the timestamp covers a different hash than the checkpoint")
	}
	rec := &TSAReceipt{URL: t.URL, TokenB64: base64.StdEncoding.EncodeToString(ts.RawToken), Time: ts.Time.UTC(), Serial: ts.SerialNumber.String(), CertCount: len(ts.Certificates)}
	if len(ts.Certificates) > 0 {
		rec.SignerCN = ts.Certificates[0].Subject.CommonName
	}
	r.TSA = rec
	r.AnchoredAt = ts.Time.UTC().Format(time.RFC3339)
	return nil
}

func (t TSA) Verify(_ context.Context, message []byte, r *Receipt, _ bool) error {
	if r.TSA == nil {
		return errors.New("no timestamp token in the receipt")
	}
	raw, err := base64.StdEncoding.DecodeString(r.TSA.TokenB64)
	if err != nil {
		return err
	}
	// Parse checks the signature over the token when the TSA certificate is included.
	ts, err := timestamp.Parse(raw)
	if err != nil {
		return fmt.Errorf("the timestamp token does not verify: %w", err)
	}
	if len(ts.Certificates) == 0 {
		return errors.New("the timestamp token carries no certificate, so its signature was not checked")
	}
	sum := sha256.Sum256(message)
	if !bytes.Equal(ts.HashedMessage, sum[:]) {
		return errors.New("the timestamp covers a different hash than the checkpoint")
	}
	if !ts.Time.UTC().Equal(r.TSA.Time.UTC()) {
		return errors.New("the receipt's time differs from the token's")
	}
	return nil
}

// Hedera is Hedera Consensus Service through a Submitter (the SDK in
// production, a fake in a test) and the public mirror node.
type Hedera struct {
	Network   string // mainnet | testnet
	TopicID   string
	Submitter Submitter
	Client    *http.Client
	Tries     int
	Wait      time.Duration
}

// Submitter posts one message to a topic and returns the sequence number and transaction id.
type Submitter interface {
	Submit(ctx context.Context, topicID string, message []byte) (seq int64, transactionID string, err error)
}

var mirrors = map[string]string{"mainnet": "https://mainnet-public.mirrornode.hedera.com", "testnet": "https://testnet.mirrornode.hedera.com"}
var hashscan = map[string]string{"mainnet": "https://hashscan.io/mainnet", "testnet": "https://hashscan.io/testnet"}

func (h Hedera) Name() string { return "hedera" }

func (h Hedera) mirrorURL(seq int64) (string, error) {
	base, ok := mirrors[h.Network]
	if !ok {
		return "", fmt.Errorf("unknown Hedera network %q", h.Network)
	}
	return fmt.Sprintf("%s/api/v1/topics/%s/messages/%d", base, h.TopicID, seq), nil
}

func (h Hedera) fetch(ctx context.Context, url string, tries int) (map[string]any, error) {
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	wait := h.Wait
	if wait == 0 {
		wait = 2500 * time.Millisecond
	}
	var last int
	for i := 0; i < tries; i++ {
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		req.Header.Set("Accept", "application/json")
		res, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		res.Body.Close()
		if res.StatusCode == 200 {
			var body map[string]any
			if err := json.Unmarshal(raw, &body); err != nil {
				return nil, err
			}
			return body, nil
		}
		last = res.StatusCode
		if res.StatusCode != 404 {
			break
		}
		if i+1 < tries {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	return nil, fmt.Errorf("mirror node %d for %s", last, url)
}

func (h Hedera) Publish(ctx context.Context, message []byte, r *Receipt) error {
	if len(message) > 1024 {
		return fmt.Errorf("the checkpoint is %d bytes, over the 1024-byte limit of a consensus message", len(message))
	}
	if h.Submitter == nil {
		return errors.New("no Hedera submitter configured")
	}
	seq, txID, err := h.Submitter.Submit(ctx, h.TopicID, message)
	if err != nil {
		return err
	}
	url, err := h.mirrorURL(seq)
	if err != nil {
		return err
	}
	tries := h.Tries
	if tries == 0 {
		tries = 12
	}
	body, err := h.fetch(ctx, url, tries)
	if err != nil {
		return err
	}
	onLedger, _ := base64.StdEncoding.DecodeString(str(body["message"]))
	if !bytes.Equal(onLedger, message) {
		return errors.New("the mirror node returned a different message than was submitted")
	}
	r.Hedera = &HederaReceipt{
		Network: h.Network, TopicID: h.TopicID, SequenceNumber: seq,
		ConsensusTimestamp: str(body["consensus_timestamp"]), RunningHash: str(body["running_hash"]), PayerAccountID: str(body["payer_account_id"]),
		TransactionID: txID, Mirror: url, HashScanTopic: hashscan[h.Network] + "/topic/" + h.TopicID,
	}
	r.AnchoredAt = consensusToRFC3339(str(body["consensus_timestamp"]))
	return nil
}

func (h Hedera) Verify(ctx context.Context, message []byte, r *Receipt, network bool) error {
	if r.Hedera == nil {
		return errors.New("no Hedera record in the receipt")
	}
	if !network {
		return nil // the WHEN is the mirror node's word; nothing to check offline
	}
	body, err := h.fetch(ctx, r.Hedera.Mirror, 1)
	if err != nil {
		return err
	}
	onLedger, _ := base64.StdEncoding.DecodeString(str(body["message"]))
	if !bytes.Equal(onLedger, message) {
		return errors.New("the mirror node returns different bytes than the checkpoint")
	}
	if str(body["consensus_timestamp"]) != r.Hedera.ConsensusTimestamp {
		return fmt.Errorf("the mirror node dates the message %s, the receipt says %s", body["consensus_timestamp"], r.Hedera.ConsensusTimestamp)
	}
	if r.Hedera.RunningHash != "" && str(body["running_hash"]) != r.Hedera.RunningHash {
		return errors.New("the running hash on the mirror node differs from the receipt")
	}
	return nil
}

func consensusToRFC3339(ts string) string {
	secs, _, _ := strings.Cut(ts, ".")
	n, err := strconv.ParseInt(secs, 10, 64)
	if err != nil {
		return ""
	}
	return time.Unix(n, 0).UTC().Format(time.RFC3339)
}

func str(v any) string { s, _ := v.(string); return s }

// Pin anchors a checkpoint with a backend and writes the receipt under
// dir/<agent>/<tree_size>.<backend>.json, unless that size is anchored already.
func Pin(ctx context.Context, dir string, cp gateway.Checkpoint, b Backend) (*Receipt, bool, error) {
	message, err := CheckpointBytes(cp)
	if err != nil {
		return nil, false, err
	}
	path := filepath.Join(dir, log.Safe(cp.Agent), fmt.Sprintf("%d.%s.json", cp.TreeSize, b.Name()))
	if _, err := os.Stat(path); err == nil {
		return nil, false, nil
	}
	r := &Receipt{Backend: b.Name(), Checkpoint: cp, MessageSHA: canonical.SHA256(message)}
	if err := b.Publish(ctx, message, r); err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, false, err
	}
	raw, _ := json.MarshalIndent(r, "", " ")
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		return nil, false, err
	}
	return r, true, nil
}

// Latest receipt of an agent, the one covering the largest tree; nil when none.
func Latest(dir, agent string) (*Receipt, error) {
	entries, err := os.ReadDir(filepath.Join(dir, log.Safe(agent)))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	type cand struct {
		size int
		name string
	}
	var cands []cand
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		size, err := strconv.Atoi(strings.SplitN(e.Name(), ".", 2)[0])
		if err != nil {
			continue
		}
		cands = append(cands, cand{size, e.Name()})
	}
	if len(cands) == 0 {
		return nil, nil
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].size > cands[j].size })
	raw, err := os.ReadFile(filepath.Join(dir, log.Safe(agent), cands[0].name))
	if err != nil {
		return nil, err
	}
	var r Receipt
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Check a receipt: the checkpoint's signature under the gateway key, the
// message hash, and the backend's own verification.
func Check(ctx context.Context, r *Receipt, pub []byte, b Backend, network bool) error {
	if !gateway.VerifyCheckpoint(r.Checkpoint, pub) {
		return errors.New("the checkpoint in the receipt is not signed by the gateway")
	}
	message, err := CheckpointBytes(r.Checkpoint)
	if err != nil {
		return err
	}
	if canonical.SHA256(message) != r.MessageSHA {
		return errors.New("the receipt's message hash does not match its checkpoint")
	}
	return b.Verify(ctx, message, r, network)
}

// BackendOf builds the backend a receipt names, for verification.
func BackendOf(r *Receipt) (Backend, error) {
	switch r.Backend {
	case "rfc3161":
		url := ""
		if r.TSA != nil {
			url = r.TSA.URL
		}
		return TSA{URL: url}, nil
	case "hedera":
		if r.Hedera == nil {
			return nil, errors.New("hedera receipt without a record")
		}
		return Hedera{Network: r.Hedera.Network, TopicID: r.Hedera.TopicID}, nil
	}
	return nil, fmt.Errorf("unknown backend %q", r.Backend)
}

// FetchCheckpoint reads a gateway's checkpoint and key over HTTP.
func FetchCheckpoint(ctx context.Context, gatewayURL, agent string) (gateway.Checkpoint, []byte, error) {
	var cp gateway.Checkpoint
	if err := getJSON(ctx, gatewayURL+"/v1/checkpoint?agent="+agent, &cp); err != nil {
		return cp, nil, err
	}
	var key struct {
		PublicKey string `json:"public_key"`
	}
	if err := getJSON(ctx, gatewayURL+"/v1/key", &key); err != nil {
		return cp, nil, err
	}
	pub, err := hex.DecodeString(key.PublicKey)
	if err != nil {
		return cp, nil, err
	}
	if !gateway.VerifyCheckpoint(cp, pub) {
		return cp, nil, errors.New("the gateway's checkpoint is not signed by the key it publishes")
	}
	return cp, pub, nil
}

func getJSON(ctx context.Context, url string, into any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	res, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("%s answered %d", url, res.StatusCode)
	}
	return json.NewDecoder(res.Body).Decode(into)
}
