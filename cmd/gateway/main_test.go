package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"github.com/abovebeyond-ai/control/attest"
	"github.com/google/go-tdx-guest/testing/testdata"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abovebeyond-ai/control/effects"
	"github.com/abovebeyond-ai/control/gateway"
	"github.com/abovebeyond-ai/control/log"
	"github.com/abovebeyond-ai/control/policy"
	"github.com/abovebeyond-ai/control/premises"
	proveml "github.com/abovebeyond-ai/proveml-go"
)

// The service end to end: a hand proposes over HTTP, the gateway judges and
// records, and the effect goes out with a credential the hand never had. A
// refusal leaves the fake GitHub untouched.
func TestTheServiceJudgesRecordsAndPerforms(t *testing.T) {
	calls := []string{}
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		if strings.HasSuffix(r.URL.Path, "/dispatches") {
			w.WriteHeader(204)
			return
		}
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"html_url":"https://github.com/x/y/pull/9","number":9}`))
	}))
	defer github.Close()

	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "secrets"), 0o700)
	os.WriteFile(filepath.Join(dir, "secrets", "github-token-x"), []byte("tok-x\n"), 0o600)
	store, _ := log.Open(filepath.Join(dir, "store"))
	seed, _ := hex.DecodeString(strings.Repeat("33", 32))
	agent := "did:webvh:QmTest:example.org#agent-fix"
	s := &service{
		cfg: config{Issuer: "https://gateway.example/control", Store: filepath.Join(dir, "store"), Secrets: filepath.Join(dir, "secrets"), Agents: map[string]struct {
			Grant policy.Grant `json:"grant"`
		}{agent: {Grant: policy.Grant{Principal: "did:webvh:QmTest:example.org", Kinds: []string{"workflow.dispatch", "pull.open"}, Resources: []string{"x/y"}, MaxPerKind: 1, PremisesFor: []string{"workflow.dispatch"}}}}},
		key: ed25519.NewKeyFromSeed(seed), store: store, effects: effects.Registry{}, gateways: map[string]*gateway.Gateway{},
	}
	s.effects.Add(effects.GitHub{SecretsDir: filepath.Join(dir, "secrets"), Base: github.URL})

	post := func(body any) (int, map[string]any) {
		raw, _ := json.Marshal(body)
		rec := httptest.NewRecorder()
		s.submit(rec, httptest.NewRequest("POST", "/v1/submit", bytes.NewReader(raw)))
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	material := premises.Material{
		Certificate:      "@[package:tar]{tar} moves from %[from]{7.13.1} to %[to]{7.14.2}, ?[safe: FIX_WITHIN_SEMVER]{within semver}.",
		Store:            map[string]any{"package:tar.name": "tar", "package:tar.from": "7.13.1", "package:tar.to": "7.14.2", "package:tar.semverSafe": 1},
		Registry:         proveml.Registry{"FIX_WITHIN_SEMVER": {Field: "semverSafe", Op: "eq", Value: 1}},
		Provenance:       map[string]string{"package:tar.name": "inferred", "package:tar.from": "inferred", "package:tar.to": "inferred", "package:tar.semverSafe": "gateway"},
		RequiredControls: []string{"FIX_WITHIN_SEMVER"}, RequiredGrades: map[string]string{"semverSafe": "gateway"},
	}
	code, out := post(submitRequest{Agent: agent, Action: policy.Action{Kind: "workflow.dispatch", Resource: "x/y", Params: map[string]any{"workflow": "elixir-fix.yml", "ref": "main"}}, Premises: &material})
	if code != 200 || out["verdict"] != "ALLOW" || out["effect"].(map[string]any)["ok"] != true {
		t.Fatalf("%d %v", code, out)
	}
	code, out = post(submitRequest{Agent: agent, Action: policy.Action{Kind: "pull.open", Resource: "x/y", Params: map[string]any{"branch": "elixir/security", "base": "main", "title": "Security: update 1 package"}}})
	if code != 200 || out["verdict"] != "ALLOW" || out["effect"].(map[string]any)["detail"].(map[string]any)["url"] != "https://github.com/x/y/pull/9" {
		t.Fatalf("%d %v", code, out)
	}
	code, out = post(submitRequest{Agent: agent, Action: policy.Action{Kind: "pull.open", Resource: "x/y", Params: map[string]any{"branch": "b", "base": "main", "title": "t"}}})
	if code != 200 || out["verdict"] != "DENY" || out["effect"] != nil {
		t.Fatalf("a second proposal: %d %v", code, out)
	}
	if code, out := post(submitRequest{Agent: "did:webvh:QmTest:example.org#agent-nobody", Action: policy.Action{Kind: "pull.open", Resource: "x/y"}}); code != 403 {
		t.Fatalf("unknown agent: %d %v", code, out)
	}
	if len(calls) != 2 || !strings.Contains(calls[0], "/repos/x/y/actions/workflows/elixir-fix.yml/dispatches Bearer tok-x") || !strings.Contains(calls[1], "/repos/x/y/pulls Bearer tok-x") {
		t.Errorf("GitHub saw %v", calls)
	}
	records, _ := store.Records(agent)
	if len(records) != 3 {
		t.Errorf("%d records", len(records))
	}
	// Dry: judge and record, perform nothing. A restart in between: the first
	// run's dispatch is remembered from the log, so this one names a new run.
	s.cfg.Dry = true
	s.gateways = map[string]*gateway.Gateway{}
	code, out = post(submitRequest{Run: "run-2", Agent: agent, Action: policy.Action{Kind: "workflow.dispatch", Resource: "x/y", Params: map[string]any{"workflow": "w", "ref": "main"}}, Premises: &material})
	if code != 200 || out["verdict"] != "ALLOW" || out["effect"] != nil || len(calls) != 2 {
		t.Errorf("dry: %d %v, calls %d", code, out, len(calls))
	}
}

// A gateway told to attest on hardware it does not have refuses to start:
// evidence that claims INTEL_TDX from a laptop would be the lie the whole
// scheme exists to make impossible.
func TestAGatewayConfiguredToAttestWithoutHardwareRefuses(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	if _, err := attestation(config{Attestation: "tdx", Store: t.TempDir()}, key); err == nil || !strings.Contains(err.Error(), "cannot") {
		t.Fatalf("expected a refusal: %v", err)
	}
	if _, err := attestation(config{Attestation: "software"}, key); err != nil {
		t.Fatal(err)
	}
	if _, err := attestation(config{Attestation: "sgx"}, key); err == nil {
		t.Fatal("an unknown platform must be refused")
	}
}

// A record already beside the store is used when it binds this key and
// refused when it binds another: the privileged pre-step writes it, the
// unprivileged service must not be able to be handed somebody else's.
func TestAStoredAttestationIsUsedOnlyWhenItBindsTheKey(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	pub := key.Public().(ed25519.PublicKey)
	dir := t.TempDir()
	raw := append([]byte(nil), testdata.RawQuote...)
	rd := attest.ReportDataForKey(pub)
	copy(raw[attest.ReportDataOffset:], rd[:])
	own, _ := attest.FromRaw(raw, "rehearsal", pub)
	b, _ := json.Marshal(own)
	os.WriteFile(filepath.Join(dir, "attestation.json"), b, 0o644)
	r, err := attestation(config{Attestation: "tdx", Store: dir}, key)
	if err != nil || r == nil || r.MRTD != own.MRTD || r.Provider != "rehearsal" {
		t.Fatalf("the stored record must be used: %v %+v", err, r)
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{10}, 32))
	if _, err := attestation(config{Attestation: "tdx", Store: dir}, other); err == nil {
		t.Fatal("a record binding another key must not be used, and this machine cannot acquire one")
	}
}
