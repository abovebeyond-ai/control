package gateway

import (
	"crypto/ed25519"
	"encoding/hex"
	"github.com/abovebeyond-ai/control/attest"
	"github.com/abovebeyond-ai/control/canonical"
	"github.com/abovebeyond-ai/control/capability"
	"github.com/google/go-tdx-guest/testing/testdata"
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
	v := g.Submit(policy.Action{Kind: "workflow.dispatch", Resource: "x/y", Params: map[string]any{"workflow": "elixir-fix.yml", "ref": "main"}}, "did:webvh:QmTest:example.org", map[string]any{"project": "demo"}, nil)
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
	g.Submit(policy.Action{Kind: "workflow.dispatch", Resource: "x/y", Params: map[string]any{"workflow": "w", "ref": "main"}}, "p", nil, nil)
	if v := g.Submit(policy.Action{Kind: "workflow.dispatch", Resource: "x/y", Params: map[string]any{"workflow": "w", "ref": "main"}}, "p", nil, nil); v.Verdict != "DENY" || !strings.Contains(v.Reason, "second workflow.dispatch") {
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
	g.Submit(policy.Action{Kind: "workflow.dispatch", Resource: "x/y", Params: map[string]any{"workflow": "w", "ref": "main"}}, "p", nil, nil)
	again, err := Open(g.cfg)
	if err != nil || again.Step() != 1 {
		t.Fatalf("reopen: %v, step %d", err, again.Step())
	}
	v := again.Submit(policy.Action{Kind: "pull.open", Resource: "x/y", Params: map[string]any{"branch": "b", "base": "main"}}, "p", nil, nil)
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
	g.Submit(policy.Action{Kind: "workflow.dispatch", Resource: "x/y", Params: map[string]any{"workflow": "w", "ref": "main"}}, "p", nil, nil)
	store.Available = false
	v := g.Submit(policy.Action{Kind: "pull.open", Resource: "x/y", Params: map[string]any{"branch": "b", "base": "main"}}, "p", nil, nil)
	if v.Verdict != "FAIL_CLOSED" || v.Token != nil || g.Step() != 1 {
		t.Errorf("%+v step %d", v, g.Step())
	}
	store.Available = true
	if v := g.Submit(policy.Action{Kind: "pull.open", Resource: "x/y", Params: map[string]any{"branch": "b", "base": "main"}}, "p", nil, nil); !v.Allowed() || g.Step() != 2 {
		t.Errorf("%+v", v)
	}
}

func TestPremisesDecideBeforeTheGrant(t *testing.T) {
	g, store := fixture(t, "workflow.dispatch")
	if v := g.Submit(policy.Action{Kind: "workflow.dispatch", Resource: "x/y", Params: map[string]any{"workflow": "w", "ref": "main"}}, "p", nil, nil); v.Verdict != "DENY" || v.Reason != "no certificate of premises for workflow.dispatch" {
		t.Errorf("%+v", v)
	}
	bad := goodPremises()
	bad.Store["package:tar.semverSafe"] = 0
	if v := g.Submit(policy.Action{Kind: "workflow.dispatch", Resource: "x/y", Params: map[string]any{"workflow": "w", "ref": "main"}}, "p", nil, bad); v.Verdict != "DENY" || !strings.Contains(v.Reason, "does not verify") || v.Token.Claims()["proveml_verified"] != false {
		t.Errorf("%+v", v)
	}
	good := goodPremises()
	v := g.Submit(policy.Action{Kind: "workflow.dispatch", Resource: "x/y", Params: map[string]any{"workflow": "w", "ref": "main"}}, "p", map[string]any{"project": "t"}, good)
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

// Under hardware attestation the token names the platform and carries the
// MRTD as its measurement, and the chain replays against that measurement.
// A quote that binds another key is refused at open: a gateway must never
// sign under an attestation that is not its own.
func TestAnAttestedGatewayNamesThePlatformAndTheMRTD(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 7
	}
	key := ed25519.NewKeyFromSeed(seed)
	pub := key.Public().(ed25519.PublicKey)
	foreign, err := attest.FromRaw(testdata.RawQuote, "sample", pub)
	if err != nil {
		t.Fatal(err)
	}
	store, _ := log.Open(t.TempDir())
	cfg := Config{Issuer: "https://gateway.example", Agent: "did:example:agent#a", Policy: policy.Policy{Grant: policy.Grant{Kinds: []string{"pull.open"}, Resources: []string{"o/r"}, MaxPerKind: 2}}, Store: store, Key: key, Attestation: foreign}
	if _, err := Open(cfg); err == nil || !strings.Contains(err.Error(), "does not bind") {
		t.Fatalf("a foreign attestation must be refused: %v", err)
	}

	raw := append([]byte(nil), testdata.RawQuote...)
	rd := attest.ReportDataForKey(pub)
	copy(raw[attest.ReportDataOffset:], rd[:])
	own, _ := attest.FromRaw(raw, "sample", pub)
	cfg.Attestation = own
	g, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if g.Platform() != attest.PlatformTDX || len(g.Measurement()) != 96 || g.Measurement() != own.MRTD {
		t.Fatalf("platform %s measurement %s", g.Platform(), g.Measurement())
	}
	v := g.Submit(policy.Action{Kind: "pull.open", Resource: "o/r", Params: map[string]any{"branch": "b", "base": "main"}}, "did:example:principal", nil, nil)
	if !v.Allowed() {
		t.Fatal(v.Reason)
	}
	// The checkpoint commits to the quote as well (row 8.1.7), and still verifies.
	cp, _ := g.Checkpoint()
	if cp.Attestation != canonical.Tag(canonical.SHA256(raw)) || !VerifyCheckpoint(cp, pub) {
		t.Fatalf("checkpoint attestation %q, verifies %v", cp.Attestation, VerifyCheckpoint(cp, pub))
	}
	cp.Attestation = ""
	if VerifyCheckpoint(cp, pub) {
		t.Fatal("dropping the attestation digest must break the checkpoint's signature")
	}
	att := v.Token["submods"].(map[string]any)["attestation"].(map[string]any)
	if att["platform"] != "INTEL_TDX" || att["measurement"] != "sha-384:"+own.MRTD {
		t.Fatalf("attestation submodule: %v", att)
	}
	records, _ := store.Records(cfg.Agent)
	if r := evidence.VerifyChain(records, pub, g.Measurement()); !r.OK {
		t.Fatal(r.Reason)
	}
	if r := evidence.VerifyChain(records, pub, strings.Repeat("0", 96)); r.OK {
		t.Fatal("another MRTD must not verify")
	}
}

// Path limits are per run: the first dispatch of the next run is not "a second
// dispatch". A restart rebuilds each run's path from the actions beside the
// log, so what a run already did is not forgotten. And a log judged under
// another measurement refuses to open.
func TestPathLimitsArePerRunAndSurviveARestart(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 3
	}
	key := ed25519.NewKeyFromSeed(seed)
	store, _ := log.Open(t.TempDir())
	cfg := Config{Issuer: "https://gateway.example", Agent: "did:example:agent#m", Policy: policy.Policy{Grant: policy.Grant{Kinds: []string{"workflow.dispatch"}, Resources: []string{"o/r", "o/s"}, MaxPerKind: 1}, PathAware: true}, Store: store, Key: key}
	g, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	dispatch := func(run, res string) Verdict {
		return g.SubmitIn(run, policy.Action{Kind: "workflow.dispatch", Resource: res, Params: map[string]any{"workflow": "w", "ref": "main"}}, "did:example:p", nil, nil)
	}
	if v := dispatch("run-1", "o/r"); !v.Allowed() {
		t.Fatal(v.Reason)
	}
	if v := dispatch("run-2", "o/s"); !v.Allowed() {
		t.Fatalf("the first dispatch of another run must be allowed: %s", v.Reason)
	}
	if v := dispatch("run-1", "o/r"); v.Allowed() {
		t.Fatal("a second dispatch in run-1 must be refused")
	}
	records, _ := store.Records(cfg.Agent)
	if records[0].Claims()["control_run"] != "run-1" || records[1].Claims()["control_run"] != "run-2" {
		t.Fatal("the run must be a claim on the record")
	}
	g, err = Open(cfg) // a restart
	if err != nil {
		t.Fatal(err)
	}
	if v := dispatch("run-2", "o/s"); v.Allowed() {
		t.Fatal("after a restart run-2 must still remember its dispatch")
	}
	if v := dispatch("run-3", "o/s"); !v.Allowed() {
		t.Fatal(v.Reason)
	}
	if r := evidence.VerifyChain(func() []evidence.Token { r, _ := store.Records(cfg.Agent); return r }(), g.PublicKey(), g.Measurement()); !r.OK {
		t.Fatal(r.Reason)
	}
	// Another engine, another measurement: the log refuses to open under it.
	old := Engine
	defer func() { engineForTest(old) }()
	engineForTest("control-other")
	if _, err := Open(cfg); err == nil || !strings.Contains(err.Error(), "rotate the log") {
		t.Fatalf("a log judged under another measurement must refuse to open: %v", err)
	}
}

// One action is three records sharing one action id: the request as judged, the
// effect as performed, the result as returned. A refused request still gets its
// effect record, saying nothing was performed, so the count per action never varies.
func TestOneActionIsThreeLinkedRecords(t *testing.T) {
	g, store := fixture(t)
	a := policy.Action{Kind: "pull.open", Resource: "x/y", Params: map[string]any{"branch": "b", "base": "main"}}
	v := g.SubmitIn("r1", a, "did:webvh:QmTest:example.org", nil, nil)
	if !v.Allowed() || v.ActionID == "" {
		t.Fatal(v.Reason)
	}
	e := g.Follow("r1", v.ActionID, PhaseEffect, a, "did:webvh:QmTest:example.org", v.Verdict, "effect performed", map[string]any{"ok": true, "url": "https://github.com/x/y/pull/9"})
	r := g.Follow("r1", v.ActionID, PhaseResult, a, "did:webvh:QmTest:example.org", v.Verdict, "result returned", map[string]any{"verdict": "ALLOW"})
	if e.Step != 1 || r.Step != 2 {
		t.Fatalf("steps %d %d", e.Step, r.Step)
	}
	records, _ := store.Records(g.cfg.Agent)
	for i, phase := range []string{PhaseRequest, PhaseEffect, PhaseResult} {
		c := records[i].Claims()
		if c["control_action"] != v.ActionID || c["control_phase"] != phase || c["control_run"] != "r1" {
			t.Fatalf("record %d: %v", i, c)
		}
	}
	if records[1].Claims()["interception_point"] != "POST_CALL_TOOL_RESULT" {
		t.Fatal("the effect record is a post-call record")
	}
	if res := evidence.VerifyChain(records, g.PublicKey(), g.Measurement()); !res.OK {
		t.Fatal(res.Reason)
	}
	var outcome map[string]any
	if found, _ := store.Attachment(g.cfg.Agent, 1, "outcome", &outcome); !found || outcome["url"] != "https://github.com/x/y/pull/9" {
		t.Fatal("the outcome is written beside the effect record")
	}
	// A second pull.open in the same run is refused; its effect record says so.
	d := g.SubmitIn("r1", a, "did:webvh:QmTest:example.org", nil, nil)
	de := g.Follow("r1", d.ActionID, PhaseEffect, a, "did:webvh:QmTest:example.org", d.Verdict, "not performed: the request was refused", map[string]any{"performed": false})
	if d.Allowed() || de.Verdict != "DENY" || de.Step != 4 {
		t.Fatalf("%v %v", d, de)
	}
}

// The record names what it matched and the digest of the parameters it validated,
// and the grant it was judged under sits beside it (rows 4.1.1, 4.1.2, 4.1.4).
func TestTheRecordNamesTheMatchAndTheParametersAndCarriesTheGrant(t *testing.T) {
	g, store := fixture(t)
	a := policy.Action{Kind: "pull.open", Resource: "x/y", Params: map[string]any{"branch": "b", "base": "main"}}
	v := g.SubmitIn("r", a, "did:webvh:QmTest:example.org", nil, nil)
	c := v.Token.Claims()
	if c["control_matched"] != "pull.open on x/y, 1 of 1 this run" {
		t.Fatalf("matched: %v", c["control_matched"])
	}
	d, _ := canonical.Digest(map[string]any{"branch": "b", "base": "main"})
	if c["control_params"] != canonical.Tag(d) {
		t.Fatalf("params: %v", c["control_params"])
	}
	var bundle map[string]any
	if found, _ := store.Attachment(g.cfg.Agent, 0, "grant", &bundle); !found {
		t.Fatal("the grant must sit beside the record")
	}
	bd, _ := canonical.Digest(bundle)
	if c["policy_bundle_hash"] != canonical.Tag(bd) {
		t.Fatal("the grant beside the record must be the bundle the claims name")
	}
	bad := g.SubmitIn("r2", policy.Action{Kind: "pull.open", Resource: "x/y", Params: map[string]any{"branch": "b", "base": "main", "force": true}}, "did:webvh:QmTest:example.org", nil, nil)
	if bad.Allowed() || !strings.Contains(bad.Reason, "out of schema") {
		t.Fatalf("%v", bad)
	}
}

// A hand that signs what it sends is recorded as verified; when the grant names its
// key, an unsigned or wrongly signed submission is refused, and the refusal itself
// is a record (row 5.1.2).
func TestASignedSubmissionIsVerifiedAgainstTheAgentsKey(t *testing.T) {
	handSeed, _ := hex.DecodeString(strings.Repeat("22", 32))
	hand := ed25519.NewKeyFromSeed(handSeed)
	store, _ := log.Open(t.TempDir())
	gwSeed, _ := hex.DecodeString(strings.Repeat("11", 32))
	cfg := Config{Issuer: "https://gateway.example/control", Agent: "did:example:agent#s", Policy: policy.Policy{Grant: policy.Grant{Kinds: []string{"pull.open"}, Resources: []string{"x/y"}, MaxPerKind: 3, SubmitterKey: hex.EncodeToString(hand.Public().(ed25519.PublicKey))}}, Store: store, Key: ed25519.NewKeyFromSeed(gwSeed)}
	g, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a := policy.Action{Kind: "pull.open", Resource: "x/y", Params: map[string]any{"branch": "b", "base": "main"}}
	body := []byte(`{"agent":"did:example:agent#s","action":{"kind":"pull.open"}}`)
	v := g.SubmitSigned("r", a, "p", nil, nil, body, ed25519.Sign(hand, body))
	if !v.Allowed() || v.Token.Claims()["control_submitter"] != "verified" {
		t.Fatalf("%s %s %v", v.Verdict, v.Reason, v.Token.Claims()["control_submitter"])
	}
	if u := g.SubmitSigned("r", a, "p", nil, nil, body, nil); u.Allowed() || u.Token.Claims()["control_submitter"] != "unsigned" || !strings.Contains(u.Reason, "not signed") {
		t.Fatalf("unsigned: %s %s", u.Verdict, u.Reason)
	}
	if w := g.SubmitSigned("r", a, "p", nil, nil, body, ed25519.Sign(hand, []byte("other bytes"))); w.Allowed() || w.Token.Claims()["control_submitter"] != "invalid" {
		t.Fatalf("invalid: %s %s", w.Verdict, w.Reason)
	}
	if plain := g.SubmitIn("r", a, "p", nil, nil); plain.Allowed() {
		t.Fatal("with a submitter key in the grant, an unsigned submission must be refused")
	}
}

// With a principal key in the grant, a submission needs the principal's capability
// for the task, and the capability narrows the grant: what it does not cover is
// refused even though the grant allows it (rows 4.2.1, 4.2.3, 5.1.3).
func TestACapabilityFromThePrincipalIsRequiredAndNarrows(t *testing.T) {
	principal := ed25519.NewKeyFromSeed([]byte("principal-seed-principal-seed-32"))
	store, _ := log.Open(t.TempDir())
	seed, _ := hex.DecodeString(strings.Repeat("11", 32))
	now := time.Unix(1_800_000_000, 0)
	cfg := Config{Issuer: "https://gateway.example/control", Agent: "did:example:ab#agent-fix",
		Policy: policy.Policy{Grant: policy.Grant{Principal: "did:example:ab", Kinds: []string{"workflow.dispatch", "pull.open"}, Resources: []string{"o/r", "o/s"}, MaxPerKind: 5, PrincipalKey: hex.EncodeToString(principal.Public().(ed25519.PublicKey))}, PathAware: true},
		Store:  store, Key: ed25519.NewKeyFromSeed(seed), Clock: func() time.Time { return now }}
	g, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a := policy.Action{Kind: "pull.open", Resource: "o/r", Params: map[string]any{"branch": "b", "base": "main"}}
	if v := g.SubmitWith("r", a, "did:example:ab", nil, nil, nil, nil, ""); v.Allowed() || !strings.Contains(v.Reason, "no capability") {
		t.Fatalf("without: %v", v)
	}
	tok, _ := capability.Issue(capability.Payload{Issuer: "did:example:ab#portal", Subject: cfg.Agent, Audience: cfg.Issuer,
		Task: capability.Task{Playbook: "elixir-fix", Project: "demo"}, Kinds: []string{"pull.open"}, Resources: []string{"o/r"},
		IssuedAt: now.Unix(), Expires: now.Add(time.Hour).Unix(), ID: "01J"}, principal)
	v := g.SubmitWith("r", a, "did:example:ab", nil, nil, nil, nil, tok)
	if !v.Allowed() {
		t.Fatalf("with: %v", v.Reason)
	}
	c := v.Token.Claims()
	if c["control_capability"] != capability.Digest(tok) || c["control_task"].(map[string]any)["project"] != "demo" {
		t.Fatalf("claims: %v", c)
	}
	// The grant allows o/s and workflow.dispatch; the capability names neither.
	if v := g.SubmitWith("r", policy.Action{Kind: "pull.open", Resource: "o/s", Params: map[string]any{"branch": "b", "base": "main"}}, "did:example:ab", nil, nil, nil, nil, tok); v.Allowed() || !strings.Contains(v.Reason, "does not cover") {
		t.Fatalf("narrowing: %v", v)
	}
	// A capability for another gateway, and an expired one, are refused and recorded.
	other, _ := capability.Issue(capability.Payload{Issuer: "x", Subject: cfg.Agent, Audience: "https://elsewhere", Kinds: []string{"pull.open"}, Resources: []string{"o/r"}, IssuedAt: now.Unix(), Expires: now.Add(time.Hour).Unix()}, principal)
	if v := g.SubmitWith("r", a, "did:example:ab", nil, nil, nil, nil, other); v.Allowed() || v.Token == nil {
		t.Fatalf("other audience: %v", v)
	}
	records, _ := store.Records(cfg.Agent)
	if len(records) != 4 {
		t.Fatalf("%d records: every refusal is recorded", len(records))
	}
}
