package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abovebeyond-ai/control/effects"
	"github.com/abovebeyond-ai/control/gateway"
	"github.com/abovebeyond-ai/control/log"
	"github.com/abovebeyond-ai/control/policy"
)

const (
	logOwner  = "did:x#operator"
	logElixir = "did:x#agent-elixir"
	logShed   = "did:x#agent-workbench-shed"
)

type policyLogFixture struct {
	cfg     config
	carried []byte
	owner   ed25519.PrivateKey
	elixir  ed25519.PrivateKey
	served  []string
	server  *httptest.Server
	asked   []string
}

func newPolicyLogFixture(t *testing.T) *policyLogFixture {
	t.Helper()
	opub, opriv, _ := ed25519.GenerateKey(rand.Reader)
	epub, epriv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	f := &policyLogFixture{owner: opriv, elixir: epriv}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.asked = append(f.asked, r.URL.Query().Get("after")+" "+r.Header.Get("Authorization"))
		json.NewEncoder(w).Encode(map[string]any{"versions": f.served})
	}))
	t.Cleanup(f.server.Close)
	f.cfg = config{Issuer: "x", Store: filepath.Join(dir, "store"), Secrets: filepath.Join(dir, "secrets"), Dry: true,
		Agents: map[string]struct {
			Grant policy.Grant `json:"grant"`
		}{logShed: {Grant: policy.Grant{Principal: "did:x", Kinds: []string{"pull.open"}, Resources: []string{"abovebeyond-ai/portal"}, MaxPerKind: 1}}},
		PolicyLog: &policyLogConfig{URL: f.server.URL + "/api/control/policy", State: filepath.Join(dir, "policy-log.json"), Signers: policy.Signers{
			Widen:  map[string]string{logOwner: hex.EncodeToString(opub)},
			Narrow: map[string]string{logElixir: hex.EncodeToString(epub)},
		}},
	}
	f.carried, _ = json.Marshal(f.cfg)
	return f
}

// sign makes the next version on head with the given grants and key.
func (f *policyLogFixture) sign(head policy.Head, iss string, key ed25519.PrivateKey, resources ...string) string {
	v := policy.LogVersion{Type: policy.VersionType, Iss: iss, Version: head.Version + 1, Prev: head.Hash, Iat: time.Now().Unix(),
		Agents: map[string]policy.HandGrant{logShed: {Grant: policy.Grant{Principal: "did:x", Kinds: []string{"pull.open"}, Resources: resources, MaxPerKind: 1}}},
		Change: []string{"the workbench at home may propose on " + strings.Join(resources, ", ")}}
	payload, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, payload))
}

func TestTheGatewayPullsAVersionKeepsItAndServesIt(t *testing.T) {
	f := newPolicyLogFixture(t)
	boot := bootHead(f.cfg, f.carried)
	v1 := f.sign(boot, logOwner, f.owner, "abovebeyond-ai/portal", "abovebeyond-ai/portal-android")
	f.served = []string{v1}

	took, err := pullPolicy(f.cfg, f.carried, f.server.Client(), "hand-token", time.Now())
	if err != nil || took != 1 {
		t.Fatalf("took %d, %v", took, err)
	}
	if f.asked[0] != "0 Bearer hand-token" {
		t.Fatalf("asked %q", f.asked[0])
	}
	head, applied, err := loadChain(f.cfg, f.carried, time.Now())
	if err != nil || head.Version != 1 || len(applied) != 1 {
		t.Fatalf("replayed head %+v, %d applied, %v", head, len(applied), err)
	}
	served := withHead(f.cfg, head)
	if !policy.ResourceCovered(served.Agents[logShed].Grant.Resources, "abovebeyond-ai/portal-android") {
		t.Fatal("the gateway does not serve the new repository")
	}
	if in := policyInputs(applied); len(in) != 1 || in[0].Name != "policy-version-1" {
		t.Fatalf("RTMR3 inputs %+v", in)
	}

	// Nothing new: nothing applied, and the next pull asks after version 1.
	f.served = nil
	if took, err := pullPolicy(f.cfg, f.carried, f.server.Client(), "", time.Now()); took != 0 || err != nil {
		t.Fatalf("took %d, %v", took, err)
	}
	if !strings.HasPrefix(f.asked[1], "1 ") {
		t.Fatalf("asked %q", f.asked[1])
	}

	// The gateway serves the version whole, for Elixir to draft the next one on.
	rec0 := httptest.NewRecorder()
	(&service{cfg: config{head: &head}}).policy(rec0, httptest.NewRequest("GET", "/v1/policy", nil))
	var whole struct {
		Version int                         `json:"version"`
		Hash    string                      `json:"hash"`
		Agents  map[string]policy.HandGrant `json:"agents"`
	}
	if json.Unmarshal(rec0.Body.Bytes(), &whole); rec0.Code != 200 || whole.Version != 1 || whole.Hash != head.Hash || len(whole.Agents[logShed].Grant.Resources) != 2 {
		t.Fatalf("GET /v1/policy: %d %s", rec0.Code, rec0.Body.String())
	}

	// Every record under it names the version served.
	dir := t.TempDir()
	store, _ := log.Open(filepath.Join(dir, "store"))
	served.applied, served.head = applied, &head
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	s := &service{cfg: served, key: key, store: store, effects: effects.Registry{}, gateways: map[string]*gateway.Gateway{}}
	raw, _ := json.Marshal(submitRequest{Agent: logShed, Action: policy.Action{Kind: "pull.open", Resource: "abovebeyond-ai/portal-android", Params: map[string]any{"branch": "b", "base": "main", "title": "t"}}})
	rec := httptest.NewRecorder()
	s.submit(rec, httptest.NewRequest("POST", "/v1/submit", bytes.NewReader(raw)))
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	records, _ := store.Records(logShed)
	if len(records) == 0 {
		t.Fatal("no records")
	}
	for i, tok := range records {
		if c := tok.Claims(); c["control_policy"] != "v1 "+head.Hash {
			t.Errorf("record %d names the policy as %v", i, c["control_policy"])
		}
	}
}

func TestARefusedVersionIsNotKeptAndBlocksWhatFollows(t *testing.T) {
	f := newPolicyLogFixture(t)
	boot := bootHead(f.cfg, f.carried)
	// Elixir adds a repository: a widening it may not sign.
	wider := f.sign(boot, logElixir, f.elixir, "abovebeyond-ai/portal", "client/secret")
	f.served = []string{wider}
	took, err := pullPolicy(f.cfg, f.carried, f.server.Client(), "", time.Now())
	if took != 0 || err == nil || !strings.Contains(err.Error(), "only take away") {
		t.Fatalf("took %d, %v", took, err)
	}
	if _, err := os.Stat(f.cfg.PolicyLog.statePath()); !os.IsNotExist(err) {
		t.Fatal("a refused version must not be kept")
	}
	// Elixir taking the only repository away is narrower and is applied.
	f.served = []string{f.sign(boot, logElixir, f.elixir)}
	if took, err := pullPolicy(f.cfg, f.carried, f.server.Client(), "", time.Now()); took != 1 || err != nil {
		t.Fatalf("took %d, %v", took, err)
	}
}

func TestANewCarryOverSetsTheKeptVersionsAside(t *testing.T) {
	f := newPolicyLogFixture(t)
	f.served = []string{f.sign(bootHead(f.cfg, f.carried), logOwner, f.owner, "abovebeyond-ai/portal", "abovebeyond-ai/portal-android")}
	if took, _ := pullPolicy(f.cfg, f.carried, f.server.Client(), "", time.Now()); took != 1 {
		t.Fatal("version 1 not applied")
	}
	// The operator carries over a configuration: the chain kept follows the old one.
	carried := append([]byte{}, f.carried...)
	carried = append(carried, ' ')
	head, applied, err := loadChain(f.cfg, carried, time.Now())
	if err != nil || head.Version != 0 || len(applied) != 0 || head.Hash != policy.HashOf(carried) {
		t.Fatalf("head %+v, %d applied, %v", head, len(applied), err)
	}
}
