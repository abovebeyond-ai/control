package gateway

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abovebeyond-ai/control/evidence"
	"github.com/abovebeyond-ai/control/log"
	"github.com/abovebeyond-ai/control/policy"
	"github.com/abovebeyond-ai/control/premises"
	proveml "github.com/abovebeyond-ai/proveml-go"
)

func fixture(t *testing.T, premisesFor ...string) (*Gateway, *log.Store) {
	dir := t.TempDir()
	store, err := log.Open(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(strings.Repeat("11", 32))
	g, err := Open(Config{
		Issuer: "https://gateway.example/control", Agent: "did:webvh:QmTest:example.org#agent-fix",
		Policy: policy.Policy{Grant: policy.Grant{Principal: "did:webvh:QmTest:example.org", Kinds: []string{"workflow.dispatch", "pull.open"}, Resources: []string{"x/y"}, MaxPerKind: 1, PremisesFor: premisesFor}, PathAware: true},
		Store:  store, Key: ed25519.NewKeyFromSeed(seed), AgbomDigest: strings.Repeat("a", 64), Clock: func() time.Time { return time.Unix(1754400000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return g, store
}

func goodPremises() *premises.Material {
	return &premises.Material{
		Certificate:      "@[package:tar]{tar} moves from %[from]{7.13.1} to %[to]{7.14.2}, closing %[advisories]{2} advisories, ?[safe: FIX_WITHIN_SEMVER]{within semver}.",
		Store:            map[string]any{"package:tar.name": "tar", "package:tar.from": "7.13.1", "package:tar.to": "7.14.2", "package:tar.advisories": 2, "package:tar.semverSafe": 1},
		Registry:         proveml.Registry{"FIX_WITHIN_SEMVER": {Field: "semverSafe", Op: "eq", Value: 1, Label: "the update stays within semver"}},
		Provenance:       map[string]string{"package:tar.name": "inferred", "package:tar.from": "inferred", "package:tar.to": "inferred", "package:tar.advisories": "inferred", "package:tar.semverSafe": "gateway"},
		RequiredControls: []string{"FIX_WITHIN_SEMVER"}, RequiredGrades: map[string]string{"from": "inferred", "to": "inferred", "advisories": "inferred", "semverSafe": "gateway"},
	}
}

func TestAnAllowedActionIsEvidencedBeforeRelease(t *testing.T) {
	g, store := fixture(t)
	v := g.Submit(policy.Action{Kind: "workflow.dispatch", Resource: "x/y", Params: map[string]any{"workflow": "elixir-fix.yml"}}, "did:webvh:QmTest:example.org", map[string]any{"project": "demo"}, nil)
	if !v.Allowed() || v.Reason != "within grant" {
		t.Fatalf("%s: %s", v.Verdict, v.Reason)
	}
	c := v.Token.Claims()
	if c["step_index"] != 0 || c["tree_size"] != 1 || c["project"] != "demo" {
		t.Errorf("claims: %v", c)
	}
	records, _ := store.Records(g.cfg.Agent)
	if len(records) != 1 {
		t.Fatalf("%d records", len(records))
	}
	if r := evidence.VerifyChain(records, g.PublicKey(), g.Measurement()); !r.OK {
		t.Error(r.Reason)
	}
	cp, _ := g.Checkpoint()
	if !VerifyCheckpoint(cp, g.PublicKey()) || cp.TreeSize != 1 || cp.ChainHead != c["chain_head"] {
		t.Errorf("checkpoint: %+v", cp)
	}
	cp.TreeSize = 2
	if VerifyCheckpoint(cp, g.PublicKey()) {
		t.Error("an edited checkpoint verified")
	}
}

func TestRefusalsAreRecordedAndThePathCounts(t *testing.T) {
	g, store := fixture(t)
	if v := g.Submit(policy.Action{Kind: "pull.merge", Resource: "x/y"}, "p", nil, nil); v.Verdict != "DENY" || v.Reason != "kind not in grant" {
		t.Errorf("%+v", v)
	}
	g.Submit(policy.Action{Kind: "workflow.dispatch", Resource: "x/y"}, "p", nil, nil)
	if v := g.Submit(policy.Action{Kind: "workflow.dispatch", Resource: "x/y"}, "p", nil, nil); v.Verdict != "DENY" || !strings.Contains(v.Reason, "second workflow.dispatch") {
		t.Errorf("%+v", v)
	}
	records, _ := store.Records(g.cfg.Agent)
	if len(records) != 3 || g.Step() != 3 {
		t.Errorf("%d records, step %d", len(records), g.Step())
	}
	if r := evidence.VerifyChain(records, g.PublicKey(), g.Measurement()); !r.OK {
		t.Error(r.Reason)
	}
}

func TestTheChainPersistsAndABrokenLogRefusesToOpen(t *testing.T) {
	g, store := fixture(t)
	g.Submit(policy.Action{Kind: "workflow.dispatch", Resource: "x/y"}, "p", nil, nil)
	again, err := Open(g.cfg)
	if err != nil || again.Step() != 1 {
		t.Fatalf("reopen: %v, step %d", err, again.Step())
	}
	v := again.Submit(policy.Action{Kind: "pull.open", Resource: "x/y"}, "p", nil, nil)
	if !v.Allowed() || v.Token.Claims()["step_index"] != 1 {
		t.Errorf("%+v", v)
	}
	file := filepath.Join(store.Dir, strings.NewReplacer(":", "_", "#", "_").Replace(g.cfg.Agent)+".jsonl")
	raw, _ := os.ReadFile(file)
	os.WriteFile(file, []byte(strings.Replace(string(raw), `"verdict":"ALLOW"`, `"verdict":"DENY"`, 1)), 0o640)
	if _, err := Open(g.cfg); err == nil || !strings.Contains(err.Error(), "breaks at record 0") {
		t.Errorf("a rewritten log opened: %v", err)
	}
}

func TestAnUnwritableStoreFailsClosed(t *testing.T) {
	g, store := fixture(t)
	g.Submit(policy.Action{Kind: "workflow.dispatch", Resource: "x/y"}, "p", nil, nil)
	store.Available = false
	v := g.Submit(policy.Action{Kind: "pull.open", Resource: "x/y"}, "p", nil, nil)
	if v.Verdict != "FAIL_CLOSED" || v.Token != nil || g.Step() != 1 {
		t.Errorf("%+v step %d", v, g.Step())
	}
	store.Available = true
	if v := g.Submit(policy.Action{Kind: "pull.open", Resource: "x/y"}, "p", nil, nil); !v.Allowed() || g.Step() != 2 {
		t.Errorf("%+v", v)
	}
}

func TestPremisesDecideBeforeTheGrant(t *testing.T) {
	g, store := fixture(t, "workflow.dispatch")
	if v := g.Submit(policy.Action{Kind: "workflow.dispatch", Resource: "x/y"}, "p", nil, nil); v.Verdict != "DENY" || v.Reason != "no certificate of premises for workflow.dispatch" {
		t.Errorf("%+v", v)
	}
	bad := goodPremises()
	bad.Store["package:tar.semverSafe"] = 0
	if v := g.Submit(policy.Action{Kind: "workflow.dispatch", Resource: "x/y"}, "p", nil, bad); v.Verdict != "DENY" || !strings.Contains(v.Reason, "does not verify") || v.Token.Claims()["proveml_verified"] != false {
		t.Errorf("%+v", v)
	}
	good := goodPremises()
	v := g.Submit(policy.Action{Kind: "workflow.dispatch", Resource: "x/y"}, "p", map[string]any{"project": "t"}, good)
	if !v.Allowed() {
		t.Fatalf("%+v", v)
	}
	c := v.Token.Claims()
	for _, k := range []string{"proveml_certificate_hash", "proveml_store_hash", "proveml_registry_hash", "proveml_required_controls", "proveml_verified", "proveml_provenance_hash", "proveml_provenance"} {
		if _, ok := c[k]; !ok {
			t.Errorf("missing %s", k)
		}
	}
	var material premises.Material
	found, err := store.Attachment(g.cfg.Agent, v.Step, "premises", &material)
	if err != nil || !found {
		t.Fatalf("attachment: %v %v", found, err)
	}
	if err := premises.Replay(c, material); err != nil {
		t.Error(err)
	}
	material.Certificate = strings.Replace(material.Certificate, "7.14.2", "8.0.0", 1)
	if err := premises.Replay(c, material); err == nil || !strings.Contains(err.Error(), "certificate_hash") {
		t.Errorf("edited material replayed: %v", err)
	}
	// The DENY for failing premises is a record with its material too.
	records, _ := store.Records(g.cfg.Agent)
	var m2 premises.Material
	if ok, _ := store.Attachment(g.cfg.Agent, 1, "premises", &m2); !ok {
		t.Fatal("no material beside the refusal")
	}
	if err := premises.Replay(records[1].Claims(), m2); err != nil {
		t.Error(err)
	}
}
