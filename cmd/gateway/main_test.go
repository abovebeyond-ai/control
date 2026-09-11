package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/abovebeyond-ai/control/attest"
	"github.com/abovebeyond-ai/control/canonical"
	"github.com/google/go-tdx-guest/testing/testdata"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	bodies := []string{}
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		raw, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(raw))
		if strings.HasSuffix(r.URL.Path, "/dispatches") {
			// A workflow that declares no evidence inputs refuses them, as GitHub does.
			if strings.Contains(string(raw), `"evidence":`) && strings.Contains(r.URL.Path, "/undeclared.yml/") {
				w.WriteHeader(422)
				_, _ = w.Write([]byte(`{"message":"Unexpected inputs provided: [\"evidence\", \"capability\"]"}`))
				return
			}
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
	if code, out := post(submitRequest{Agent: "did:webvh:QmTest:example.org#agent-nobody", Action: policy.Action{Kind: "pull.open", Resource: "x/y", Params: map[string]any{"branch": "b", "base": "main"}}}); code != 403 {
		t.Fatalf("unknown agent: %d %v", code, out)
	}
	if len(calls) != 2 || !strings.Contains(calls[0], "/repos/x/y/actions/workflows/elixir-fix.yml/dispatches Bearer tok-x") || !strings.Contains(calls[1], "/repos/x/y/pulls Bearer tok-x") {
		t.Errorf("GitHub saw %v", calls)
	}
	// The far end got the evidence with the effect: the dispatch's inputs carry the
	// signed record, the pull request's body carries the footer.
	if !strings.Contains(bodies[0], `"evidence":"`) || !strings.Contains(bodies[0], `"capability":`) {
		t.Errorf("the dispatch carried no evidence: %s", bodies[0])
	}
	if !strings.Contains(bodies[1], "proof-of-control") || !strings.Contains(bodies[1], "Evidence: ") {
		t.Errorf("the pull request carried no footer: %s", bodies[1])
	}
	records, _ := store.Records(agent)
	if len(records) != 9 { // three actions, three records each
		t.Errorf("%d records", len(records))
	}
	if records[1].Claims()["control_phase"] != "effect" || records[1].Claims()["reason"] != "effect performed" || records[2].Claims()["control_phase"] != "result" {
		t.Errorf("effect and result records: %v %v", records[1].Claims()["reason"], records[2].Claims()["control_phase"])
	}
	if records[7].Claims()["reason"] != "not performed: the request was refused" {
		t.Errorf("a refusal's effect record: %v", records[7].Claims()["reason"])
	}
	// A repository whose workflow declares no evidence inputs still gets its dispatch,
	// without them, and the outcome says the evidence was not carried.
	code, out = post(submitRequest{Run: "run-u", Agent: agent, Action: policy.Action{Kind: "workflow.dispatch", Resource: "x/y", Params: map[string]any{"workflow": "undeclared.yml", "ref": "main"}}, Premises: &material})
	if code != 200 || out["verdict"] != "ALLOW" || out["effect"].(map[string]any)["ok"] != true || out["effect"].(map[string]any)["detail"].(map[string]any)["evidence_carried"] != false {
		t.Fatalf("undeclared inputs: %d %v", code, out)
	}
	if len(calls) != 4 || len(records) != 9 {
		t.Fatalf("the retry is one more call: %d calls", len(calls))
	}

	// Dry: judge and record, perform nothing. A restart in between: the first
	// run's dispatch is remembered from the log, so this one names a new run.
	s.cfg.Dry = true
	s.gateways = map[string]*gateway.Gateway{}
	code, out = post(submitRequest{Run: "run-2", Agent: agent, Action: policy.Action{Kind: "workflow.dispatch", Resource: "x/y", Params: map[string]any{"workflow": "w", "ref": "main"}}, Premises: &material})
	if code != 200 || out["verdict"] != "ALLOW" || out["effect"] != nil || len(calls) != 4 {
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

// A gateway with a client token refuses a submission without it and serves its
// agents and attachments to anyone: acting is guarded, reading is open.
func TestAClientTokenGuardsSubmitAndReadingStaysOpen(t *testing.T) {
	dir := t.TempDir()
	store, _ := log.Open(filepath.Join(dir, "store"))
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32))
	agent := "did:webvh:QmTest:example.org#agent-fix"
	s := &service{key: key, store: store, effects: effects.Registry{}, gateways: map[string]*gateway.Gateway{}, cfg: config{Issuer: "x", Store: filepath.Join(dir, "store"), Dry: true, ClientToken: "s3cret", Agents: map[string]struct {
		Grant policy.Grant `json:"grant"`
	}{agent: {Grant: policy.Grant{Principal: "did:webvh:QmTest:example.org", Kinds: []string{"pull.open"}, Resources: []string{"x/y"}, MaxPerKind: 1}}}}}
	body, _ := json.Marshal(submitRequest{Run: "r", Agent: agent, Action: policy.Action{Kind: "pull.open", Resource: "x/y", Params: map[string]any{"branch": "b", "base": "main"}}})
	rec := httptest.NewRecorder()
	s.authed(s.submit)(rec, httptest.NewRequest("POST", "/v1/submit", bytes.NewReader(body)))
	if rec.Code != 401 {
		t.Fatalf("without the token: %d", rec.Code)
	}
	req := httptest.NewRequest("POST", "/v1/submit", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer s3cret")
	rec = httptest.NewRecorder()
	s.authed(s.submit)(rec, req)
	if rec.Code != 200 {
		t.Fatalf("with the token: %d %s", rec.Code, rec.Body.String())
	}
	// A read writes an access record (row 7.6.4).
	rec = httptest.NewRecorder()
	s.accessed("records", s.records)(rec, httptest.NewRequest("GET", "/v1/records?agent="+url.QueryEscape(agent), nil))
	if access, err := os.ReadFile(filepath.Join(dir, "store", "access.jsonl")); err != nil || !strings.Contains(string(access), `"read":"records"`) {
		t.Fatalf("access record: %v %s", err, access)
	}
	rec = httptest.NewRecorder()
	s.agents(rec, httptest.NewRequest("GET", "/v1/agents", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), agent) {
		t.Fatalf("agents: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	s.attachment(rec, httptest.NewRequest("GET", "/v1/attachment?agent="+url.QueryEscape(agent)+"&step=0&name=action", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "\"run\":\"r\"") {
		t.Fatalf("attachment: %d %s", rec.Code, rec.Body.String())
	}
	// Everything written beside a record is served: the grant beside the request, the
	// outcome beside the effect. The mirror job stopped on a 400 here on 10 September 2026.
	for _, q := range []string{"step=0&name=grant", "step=1&name=outcome"} {
		rec = httptest.NewRecorder()
		s.attachment(rec, httptest.NewRequest("GET", "/v1/attachment?agent="+url.QueryEscape(agent)+"&"+q, nil))
		if rec.Code != 200 {
			t.Fatalf("attachment %s: %d %s", q, rec.Code, rec.Body.String())
		}
	}
}

// Every quote is kept by digest and served by it, so an anchor that committed to an
// earlier quote can still be checked after a retake.
func TestEarlierQuotesAreKeptAndServedByDigest(t *testing.T) {
	dir := t.TempDir()
	store, _ := log.Open(filepath.Join(dir, "store"))
	seed := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, 32))
	rec, _ := attest.FromRaw(testdata.RawQuote, "sample", seed.Public().(ed25519.PublicKey))
	raw, _ := json.Marshal(rec)
	quote, _ := base64.StdEncoding.DecodeString(rec.QuoteB64)
	os.MkdirAll(filepath.Join(dir, "store", "attestations"), 0o755)
	os.WriteFile(filepath.Join(dir, "store", "attestations", canonical.SHA256(quote)+".json"), raw, 0o644)
	s := &service{store: store, cfg: config{Store: filepath.Join(dir, "store")}}
	rr := httptest.NewRecorder()
	s.attestation(rr, httptest.NewRequest("GET", "/v1/attestation?digest="+url.QueryEscape(canonical.Tag(canonical.SHA256(quote))), nil))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), rec.MRTD) {
		t.Fatalf("by digest: %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	s.attestation(rr, httptest.NewRequest("GET", "/v1/attestation?digest=sha-256:"+strings.Repeat("0", 64), nil))
	if rr.Code != 404 {
		t.Fatalf("unknown digest: %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	s.attestations(rr, httptest.NewRequest("GET", "/v1/attestations", nil))
	if !strings.Contains(rr.Body.String(), canonical.SHA256(quote)) {
		t.Fatalf("list: %s", rr.Body.String())
	}
}

// A branch.push: the runner hands the change back as files, the gateway judges it with
// its working, keeps the files beside the record, and creates the branch itself through
// the Git Data API with its own credential; the commit message carries the evidence
// footer. Files that do not match the judged digest never reach the judgement.
func TestABranchIsPushedByTheGatewayFromTheFilesHandedBack(t *testing.T) {
	calls := []string{}
	var commitMessage string
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case strings.HasSuffix(r.URL.Path, "/git/commits/abc123"):
			_, _ = w.Write([]byte(`{"sha":"abc123","tree":{"sha":"tree-base"}}`))
		case strings.HasSuffix(r.URL.Path, "/git/blobs"):
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"sha":"blob-1"}`))
		case strings.HasSuffix(r.URL.Path, "/git/trees"):
			if !strings.Contains(string(raw), `"base_tree":"tree-base"`) || !strings.Contains(string(raw), `"path":"package-lock.json"`) {
				t.Errorf("tree request: %s", raw)
			}
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"sha":"tree-new"}`))
		case strings.HasSuffix(r.URL.Path, "/git/commits"):
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			commitMessage, _ = body["message"].(string)
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"sha":"commit-new"}`))
		case strings.HasSuffix(r.URL.Path, "/git/refs"):
			if !strings.Contains(string(raw), `"ref":"refs/heads/elixir/security-1"`) || !strings.Contains(string(raw), `"sha":"commit-new"`) {
				t.Errorf("ref request: %s", raw)
			}
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"ref":"refs/heads/elixir/security-1"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer github.Close()

	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "secrets"), 0o700)
	os.WriteFile(filepath.Join(dir, "secrets", "github-token-x"), []byte("tok-x\n"), 0o600)
	store, _ := log.Open(filepath.Join(dir, "store"))
	seed, _ := hex.DecodeString(strings.Repeat("34", 32))
	agent := "did:webvh:QmTest:example.org#agent-fix"
	s := &service{
		cfg: config{Issuer: "https://gateway.example/control", Store: filepath.Join(dir, "store"), Secrets: filepath.Join(dir, "secrets"), Agents: map[string]struct {
			Grant policy.Grant `json:"grant"`
		}{agent: {Grant: policy.Grant{Principal: "did:webvh:QmTest:example.org", Kinds: []string{"branch.push"}, Resources: []string{"x/y"}, MaxPerKind: 1, PremisesFor: []string{"branch.push"}}}}},
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
	files := []effects.FileChange{{Path: "package-lock.json", Content: "eyJuYW1lIjoieSJ9"}}
	digest, _ := effects.FilesDigest(files)
	params := map[string]any{"branch": "elixir/security-1", "base_sha": "abc123", "message": "Security updates", "files_sha256": digest, "packages": 1}

	// Files that do not match the digest are refused before any judgement.
	tampered := []effects.FileChange{{Path: "package-lock.json", Content: "eyJuYW1lIjoiWiJ9"}}
	if code, out := post(submitRequest{Agent: agent, Action: policy.Action{Kind: "branch.push", Resource: "x/y", Params: params}, Premises: &material, Files: tampered}); code != 400 || !strings.Contains(fmt.Sprint(out["error"]), "files_sha256") {
		t.Fatalf("tampered files: %d %v", code, out)
	}
	if got := len(calls); got != 0 {
		t.Fatalf("GitHub was reached before the judgement: %v", calls)
	}

	code, out := post(submitRequest{Agent: agent, Action: policy.Action{Kind: "branch.push", Resource: "x/y", Params: params}, Premises: &material, Files: files})
	if code != 200 || out["verdict"] != "ALLOW" {
		t.Fatalf("%d %v", code, out)
	}
	detail := out["effect"].(map[string]any)["detail"].(map[string]any)
	if detail["commit"] != "commit-new" || detail["branch"] != "elixir/security-1" {
		t.Errorf("effect: %v", detail)
	}
	if strings.Join(calls, " ") != "GET /repos/x/y/git/commits/abc123 POST /repos/x/y/git/blobs POST /repos/x/y/git/trees POST /repos/x/y/git/commits POST /repos/x/y/git/refs" {
		t.Errorf("GitHub saw %v", calls)
	}
	if !strings.HasPrefix(commitMessage, "Security updates\n\n") || !strings.Contains(commitMessage, "Evidence: ") {
		t.Errorf("commit message: %q", commitMessage)
	}
	// The files are kept beside the record, as the working is.
	var kept []effects.FileChange
	step := int(out["step"].(float64))
	if found, err := store.Attachment(agent, step, "files", &kept); err != nil || !found || len(kept) != 1 || kept[0].Path != "package-lock.json" {
		t.Errorf("attachment: %v %v %v", found, err, kept)
	}
}

// The hand's bill of materials (C1.2, row 1.1.1): submitted with the request, its digest
// is the record's agbom_digest on all three records of the action, the manifest is kept
// beside the request record, and the verifier resolves the one to the other.
func TestTheBillOfMaterialsIsNamedByEveryRecordAndKeptBesideIt(t *testing.T) {
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"html_url":"https://github.com/x/y/pull/1","number":1}`))
	}))
	defer github.Close()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "secrets"), 0o700)
	os.WriteFile(filepath.Join(dir, "secrets", "github-token-x"), []byte("tok-x\n"), 0o600)
	store, _ := log.Open(filepath.Join(dir, "store"))
	seed, _ := hex.DecodeString(strings.Repeat("35", 32))
	agent := "did:webvh:QmTest:example.org#agent-fix"
	s := &service{
		cfg: config{Issuer: "https://gateway.example/control", Store: filepath.Join(dir, "store"), Secrets: filepath.Join(dir, "secrets"), Release: "v0.12.0 sha256:abc", Agents: map[string]struct {
			Grant policy.Grant `json:"grant"`
		}{agent: {Grant: policy.Grant{Principal: "did:webvh:QmTest:example.org", Kinds: []string{"pull.open"}, Resources: []string{"x/y"}, MaxPerKind: 1}}}},
		key: ed25519.NewKeyFromSeed(seed), store: store, effects: effects.Registry{}, gateways: map[string]*gateway.Gateway{},
	}
	s.effects.Add(effects.GitHub{SecretsDir: filepath.Join(dir, "secrets"), Base: github.URL})
	agbom := map[string]any{"agbom": "elixir", "agent": agent, "software": map[string]any{"repository": "abovebeyond-ai/elixir", "commit": "3ce51e3"}, "model": nil}
	raw, _ := json.Marshal(submitRequest{Agent: agent, Action: policy.Action{Kind: "pull.open", Resource: "x/y", Params: map[string]any{"branch": "b", "base": "main", "title": "t"}}, Agbom: agbom})
	rec := httptest.NewRecorder()
	s.submit(rec, httptest.NewRequest("POST", "/v1/submit", bytes.NewReader(raw)))
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	want, _ := canonical.Digest(agbom)
	records, _ := store.Records(agent)
	if len(records) != 3 {
		t.Fatalf("%d records", len(records))
	}
	for i, tok := range records {
		c := tok.Claims()
		if c["agbom_digest"] != canonical.Tag(want) {
			t.Errorf("record %d names %v, not the submitted bill of materials", i, c["agbom_digest"])
		}
		if c["control_gateway"] != "v0.12.0 sha256:abc" {
			t.Errorf("record %d names the gateway as %v", i, c["control_gateway"])
		}
	}
	var kept map[string]any
	if found, err := store.Attachment(agent, 0, "agbom", &kept); err != nil || !found || kept["agbom"] != "elixir" {
		t.Errorf("manifest beside the record: %v %v %v", found, err, kept)
	}
}
