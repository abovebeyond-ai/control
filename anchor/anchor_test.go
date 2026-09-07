package anchor

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/abovebeyond-ai/control/gateway"
	"github.com/digitorus/timestamp"
)

// A timestamp authority in-process: a self-signed certificate with the
// timestamping purpose, answering RFC 3161 requests over HTTP as a real one
// does, so the receipt's verification runs the real parser and signature check.
func fakeTSA(t *testing.T) (*httptest.Server, *x509.Certificate) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test TSA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}, BasicConstraintsValid: true, IsCA: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		req, err := timestamp.ParseRequest(raw)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		ts := timestamp.Timestamp{HashAlgorithm: crypto.SHA256, HashedMessage: req.HashedMessage, Time: time.Date(2026, 9, 7, 20, 0, 0, 0, time.UTC), SerialNumber: big.NewInt(42), Policy: asn1.ObjectIdentifier{1, 2, 3, 4, 1}, Certificates: []*x509.Certificate{cert}, AddTSACertificate: true}
		resp, err := ts.CreateResponse(cert, key)
		if err != nil {
			w.WriteHeader(500)
			_, _ = w.Write([]byte(err.Error()))
			t.Logf("fake TSA: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = w.Write(resp)
	}))
	return srv, cert
}

func signedCheckpoint(t *testing.T) (gateway.Checkpoint, ed25519.PublicKey) {
	seed, _ := hex.DecodeString(strings.Repeat("44", 32))
	key := ed25519.NewKeyFromSeed(seed)
	cp := gateway.Checkpoint{Agent: "did:webvh:QmTest:example.org#agent-fix", TreeSize: 3, Root: "sha-256:" + strings.Repeat("ab", 32), ChainHead: "sha-256:" + strings.Repeat("cd", 32)}
	// sign the way the gateway does
	g := gateway.Checkpoint{Agent: cp.Agent, TreeSize: cp.TreeSize, Root: cp.Root, ChainHead: cp.ChainHead}
	in, _ := CheckpointBytes(gateway.Checkpoint{Agent: g.Agent, TreeSize: g.TreeSize, Root: g.Root, ChainHead: g.ChainHead})
	_ = in
	cp.Signature = signCheckpoint(cp, key)
	if !gateway.VerifyCheckpoint(cp, key.Public().(ed25519.PublicKey)) {
		t.Fatal("test checkpoint does not verify")
	}
	return cp, key.Public().(ed25519.PublicKey)
}

func TestATimestampAuthorityAnchorsAndVerifiesOffline(t *testing.T) {
	srv, _ := fakeTSA(t)
	defer srv.Close()
	cp, pub := signedCheckpoint(t)
	dir := t.TempDir()
	b := TSA{URL: srv.URL}
	r, pinned, err := Pin(context.Background(), dir, cp, b)
	if err != nil || !pinned {
		t.Fatalf("pin: %v %v", pinned, err)
	}
	if r.TSA == nil || r.TSA.SignerCN != "Test TSA" || r.AnchoredAt != "2026-09-07T20:00:00Z" {
		t.Fatalf("receipt: %+v", r)
	}
	if _, again, _ := Pin(context.Background(), dir, cp, b); again {
		t.Error("the same size was anchored twice")
	}
	latest, err := Latest(dir, cp.Agent)
	if err != nil || latest == nil || latest.Checkpoint.TreeSize != 3 {
		t.Fatalf("latest: %v %v", latest, err)
	}
	if err := Check(context.Background(), latest, pub, b, false); err != nil {
		t.Error(err)
	}
	// A receipt whose checkpoint was edited after the fact fails on the gateway signature.
	edited := *latest
	edited.Checkpoint.TreeSize = 9
	if err := Check(context.Background(), &edited, pub, b, false); err == nil || !strings.Contains(err.Error(), "not signed by the gateway") {
		t.Errorf("edited checkpoint: %v", err)
	}
	// A token moved to another checkpoint fails on the hash it covers.
	other := *latest
	other.Checkpoint.ChainHead = "sha-256:" + strings.Repeat("ef", 32)
	other.Checkpoint.Signature = signCheckpoint(other.Checkpoint, ed25519.NewKeyFromSeed(mustHex(strings.Repeat("44", 32))))
	m, _ := CheckpointBytes(other.Checkpoint)
	other.MessageSHA = sha(m)
	if err := Check(context.Background(), &other, pub, b, false); err == nil || !strings.Contains(err.Error(), "different hash") {
		t.Errorf("moved token: %v", err)
	}
}

type fakeLedger struct {
	topic map[int64]map[string]any
}

func (f *fakeLedger) Submit(_ context.Context, topicID string, message []byte) (int64, string, error) {
	seq := int64(len(f.topic) + 1)
	f.topic[seq] = map[string]any{"message": base64.StdEncoding.EncodeToString(message), "consensus_timestamp": "1788470710.000000001", "running_hash": strings.Repeat("aa", 48), "payer_account_id": "0.0.1001", "sequence_number": seq, "topic_id": topicID}
	return seq, "0.0.1001-1788470702-863049633", nil
}

func TestHederaAnchorsThroughAFakeLedgerAndTheMirrorConfirms(t *testing.T) {
	ledger := &fakeLedger{topic: map[int64]map[string]any{}}
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var seq int64
		_, _ = json.Marshal(nil)
		parts := strings.Split(r.URL.Path, "/")
		_, err := json.Marshal(parts)
		if err == nil {
			json.Unmarshal([]byte(parts[len(parts)-1]), &seq)
		}
		if m, ok := ledger.topic[seq]; ok {
			_ = json.NewEncoder(w).Encode(m)
			return
		}
		w.WriteHeader(404)
	}))
	defer mirror.Close()
	mirrors["fake"] = mirror.URL
	hashscan["fake"] = mirror.URL
	cp, pub := signedCheckpoint(t)
	dir := t.TempDir()
	b := Hedera{Network: "fake", TopicID: "0.0.5555", Submitter: ledger, Tries: 2, Wait: time.Millisecond}
	r, pinned, err := Pin(context.Background(), dir, cp, b)
	if err != nil || !pinned {
		t.Fatalf("pin: %v %v", pinned, err)
	}
	if r.Hedera == nil || r.Hedera.SequenceNumber != 1 || r.AnchoredAt != "2026-09-03T21:25:10Z" {
		t.Fatalf("receipt: %+v", r)
	}
	if err := Check(context.Background(), r, pub, b, true); err != nil {
		t.Error(err)
	}
	ledger.topic[1]["consensus_timestamp"] = "1.000000000"
	if err := Check(context.Background(), r, pub, b, true); err == nil || !strings.Contains(err.Error(), "dates the message") {
		t.Errorf("moved time: %v", err)
	}
}

func signCheckpoint(cp gateway.Checkpoint, key ed25519.PrivateKey) string {
	in, _ := CheckpointBytesUnsigned(cp)
	return hex.EncodeToString(ed25519.Sign(key, in))
}

func mustHex(s string) []byte { b, _ := hex.DecodeString(s); return b }
