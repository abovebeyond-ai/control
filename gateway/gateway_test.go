package gateway

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
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
	// A request with no effect behind it is an interrupted action: reopening writes
	// the two records that say so, and the next action starts after them.
	again, err := Open(g.cfg)
	if err != nil || again.Step() != 3 {
		t.Fatalf("reopen: %v, step %d", err, again.Step())
	}
	v := again.Submit(policy.Action{Kind: "pull.open", Resource: "x/y", Params: map[string]any{"branch": "b", "base": "main"}}, "p", nil, nil)
	if !v.Allowed() || v.Token.Claims()["step_index"] != 3 {
		t.Errorf("%+v", v)
	}
	file := filepath.Join(store.Dir, strings.NewReplacer(":", "_", "#", "_").Replace(g.cfg.Agent)+".jsonl")
	raw, _ := os.ReadFile(file)
	os.WriteFile(file, []byte(strings.Replace(string(raw), `"verdict":"ALLOW"`, `"verdict":"DENY"`, 1)), 0o640)
	// Since 22 September 2026 the replay checks the signature before the link, so a
	// rewritten verdict is refused as an unsigned record rather than as a broken chain.
	// Either way it names the record it refuses on, and that is what this pins.
	if _, err := Open(g.cfg); err == nil || !strings.Contains(err.Error(), "record 0") {
		t.Errorf("a rewritten log opened: %v", err)
	}
}

// A log whose records are consistent among themselves but not signed by this gateway is
// the interesting rewrite: an attacker who cannot sign can still recompute every chain
// head, and until 22 September 2026 that opened as if it held, because the replay read
// the links and not the signatures.
func TestALogWithRecomputedLinksButNoSignatureRefusesToOpen(t *testing.T) {
	g, store := fixture(t)
	g.Submit(policy.Action{Kind: "pull.open", Resource: "x/y", Params: map[string]any{"branch": "b", "base": "main"}}, "p", nil, nil)

	file := filepath.Join(store.Dir, strings.NewReplacer(":", "_", "#", "_").Replace(g.cfg.Agent)+".jsonl")
	raw, _ := os.ReadFile(file)

	var tok evidence.Token
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(raw))), &tok); err != nil {
		t.Fatalf("read back: %v", err)
	}
	// The record is left intact except for its signature: every link still checks out.
	tok["signature"] = strings.Repeat("00", 64)
	line, _ := json.Marshal(tok)
	os.WriteFile(file, append(line, '\n'), 0o640)

	if _, err := Open(g.cfg); err == nil || !strings.Contains(err.Error(), "not signed by this gateway's key") {
		t.Errorf("a log with a forged signature opened: %v", err)
	}
}

// The halt while running (row 8.3.3): rewriting the log under a live gateway used to go
// unnoticed until the next restart or the daily replay, and every action in between went
// through. Now each judgement first holds the tail of the store to the head it carries.
func TestRewritingTheLogUnderALiveGatewayHaltsIt(t *testing.T) {
	g, store := fixture(t)
	first := g.Submit(policy.Action{Kind: "pull.open", Resource: "x/y", Params: map[string]any{"branch": "b", "base": "main"}}, "p", nil, nil)
	if !first.Allowed() {
		t.Fatalf("the first action should stand: %+v", first)
	}

	file := filepath.Join(store.Dir, strings.NewReplacer(":", "_", "#", "_").Replace(g.cfg.Agent)+".jsonl")
	raw, _ := os.ReadFile(file)
	os.WriteFile(file, []byte(strings.Replace(string(raw), `"verdict":"ALLOW"`, `"verdict":"DENY"`, 1)), 0o640)

	// Another kind, so that without the halt this action would have been ALLOW: the test
	// has to show the halt stopping something that would otherwise have gone through.
	v := g.Submit(policy.Action{Kind: "workflow.dispatch", Resource: "x/y", Params: map[string]any{"workflow": "w", "ref": "main"}}, "p", nil, nil)
	if v.Verdict != "FAIL_CLOSED" || v.Token != nil {
		t.Errorf("a rewritten log did not halt the gateway: %+v", v)
	}
	if !strings.Contains(v.Reason, "not signed by this gateway's key") && !strings.Contains(v.Reason, "chain head") {
		t.Errorf("the halt does not say why: %q", v.Reason)
	}
}

// A store that cannot be read is a halt too: a gateway that cannot see its own evidence
// cannot promise that the next record follows the last one.
func TestAnUnreadableStoreHaltsTheGateway(t *testing.T) {
	g, store := fixture(t)
	g.Submit(policy.Action{Kind: "pull.open", Resource: "x/y", Params: map[string]any{"branch": "b", "base": "main"}}, "p", nil, nil)

	file := filepath.Join(store.Dir, strings.NewReplacer(":", "_", "#", "_").Replace(g.cfg.Agent)+".jsonl")
	os.WriteFile(file, []byte("this is not a record\n"), 0o640)

	v := g.Submit(policy.Action{Kind: "workflow.dispatch", Resource: "x/y", Params: map[string]any{"workflow": "w", "ref": "main"}}, "p", nil, nil)
	if v.Verdict != "FAIL_CLOSED" {
		t.Errorf("an unreadable store did not halt the gateway: %+v", v)
	}
}

// The gateway stopped between a request record and its effect record (a reset of the
// machine on 12 September 2026): on the next open the effect and result records are
// written, and say the effect is unrecorded, so the chain has its three per action and
// a verifier reads an interruption, not a gap. An action with all three is left alone,
// and opening twice writes nothing more.
func TestAnInterruptedActionIsClosedOnOpenAndSaysSo(t *testing.T) {
	g, store := fixture(t)
	v := g.Submit(policy.Action{Kind: "workflow.dispatch", Resource: "x/y", Params: map[string]any{"workflow": "w", "ref": "main"}}, "p", nil, nil)
	if !v.Allowed() {
		t.Fatal(v)
	}
	again, err := Open(g.cfg)
	if err != nil {
		t.Fatal(err)
	}
	records, _ := store.Records(g.cfg.Agent)
	if len(records) != 3 {
		t.Fatalf("%d records", len(records))
	}
	effect, result := records[1].Claims(), records[2].Claims()
	if effect["control_phase"] != PhaseEffect || effect["control_action"] != v.ActionID || effect["reason"] != "effect interrupted" || effect["verdict"] != "ALLOW" || effect["initiating_user"] != "p" {
		t.Errorf("effect record: %v", effect)
	}
	if result["control_phase"] != PhaseResult || result["control_action"] != v.ActionID || result["reason"] != "result interrupted" {
		t.Errorf("result record: %v", result)
	}
	var outcome map[string]any
	if found, _ := store.Attachment(g.cfg.Agent, 1, "outcome", &outcome); !found || outcome["ok"] != false || outcome["error"] != Interrupted {
		t.Errorf("outcome beside the effect: %v %v", found, outcome)
	}
	if _, err := Open(again.cfg); err != nil {
		t.Fatal(err)
	}
	if records, _ = store.Records(g.cfg.Agent); len(records) != 3 {
		t.Errorf("opening again wrote %d records", len(records)-3)
	}
}

// The same stop can take the action file beside the request with it: the closing
// records then name the kind and resource from the record's claims and say the
// parameters are lost, rather than leaving the gap.
func TestAnInterruptedActionWithoutItsFileIsStillClosed(t *testing.T) {
	g, store := fixture(t)
	v := g.Submit(policy.Action{Kind: "workflow.dispatch", Resource: "x/y", Params: map[string]any{"workflow": "w", "ref": "main"}}, "p", nil, nil)
	os.Remove(filepath.Join(store.Dir, strings.NewReplacer(":", "_", "#", "_").Replace(g.cfg.Agent), "action", "0.json"))
	if _, err := Open(g.cfg); err != nil {
		t.Fatal(err)
	}
	records, _ := store.Records(g.cfg.Agent)
	if len(records) != 3 || records[1].Claims()["control_action"] != v.ActionID || records[1].Claims()["target_resource"] != "x/y" {
		t.Fatalf("%d records: %v", len(records), records[len(records)-1].Claims())
	}
	var outcome map[string]any
	if found, _ := store.Attachment(g.cfg.Agent, 1, "outcome", &outcome); !found || !strings.Contains(str(outcome["error"]), "parameters beside the request record were lost") {
		t.Errorf("outcome: %v %v", found, outcome)
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

// The operator's own keys, on hardware tokens, named in the grant by DID fragment: a
// capability the operator signed is verified against the key its issuer names, either
// token's; a capability that names a listed fragment but is signed by another key is
// refused; a capability by the principal key still works; and an issuer the grant does
// not name falls back to the principal key, which then fails the signature.
func TestACapabilityFromTheOperatorsOwnKeyIsVerifiedAgainstIt(t *testing.T) {
	portal := ed25519.NewKeyFromSeed([]byte("principal-seed-principal-seed-32"))
	op1 := ed25519.NewKeyFromSeed([]byte("operator-one-operator-one-seed32"))
	op2 := ed25519.NewKeyFromSeed([]byte("operator-two-operator-two-seed32"))
	store, _ := log.Open(t.TempDir())
	seed, _ := hex.DecodeString(strings.Repeat("11", 32))
	now := time.Unix(1_800_000_000, 0)
	pub := func(k ed25519.PrivateKey) string { return hex.EncodeToString(k.Public().(ed25519.PublicKey)) }
	cfg := Config{Issuer: "https://gateway.example/control", Agent: "did:example:ab#agent-workbench",
		Policy: policy.Policy{Grant: policy.Grant{Principal: "did:example:ab", Kinds: []string{"pull.open"}, Resources: []string{"o/r"}, MaxPerKind: 5,
			PrincipalKey: pub(portal), PrincipalKeys: map[string]string{"did:example:ab#operator": pub(op1), "did:example:ab#operator-2": pub(op2)}}, PathAware: true},
		Store: store, Key: ed25519.NewKeyFromSeed(seed), Clock: func() time.Time { return now }}
	g, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a := policy.Action{Kind: "pull.open", Resource: "o/r", Params: map[string]any{"branch": "b", "base": "main"}}
	issue := func(iss string, key ed25519.PrivateKey) string {
		tok, _ := capability.Issue(capability.Payload{Issuer: iss, Subject: cfg.Agent, Audience: cfg.Issuer,
			Task: capability.Task{Playbook: "workbench", Project: "demo"}, Kinds: []string{"pull.open"}, Resources: []string{"o/r"},
			IssuedAt: now.Unix(), Expires: now.Add(time.Hour).Unix(), ID: "01K"}, key)
		return tok
	}
	for _, c := range []struct {
		iss string
		key ed25519.PrivateKey
		ok  bool
	}{
		{"did:example:ab#operator", op1, true},
		{"did:example:ab#operator-2", op2, true},
		{"did:example:ab#portal", portal, true},
		{"did:example:ab#operator", op2, false},    // the fragment of one token, the signature of the other
		{"did:example:ab#operator", portal, false}, // Portal cannot speak as the operator
		{"did:example:ab#stranger", op1, false},    // an issuer the grant does not name
	} {
		v := g.SubmitWith("r-"+c.iss, a, "did:example:ab", nil, nil, nil, nil, issue(c.iss, c.key))
		if v.Allowed() != c.ok {
			t.Fatalf("%s signed by its %v: allowed=%v reason=%s", c.iss, c.key != nil, v.Allowed(), v.Reason)
		}
		if c.ok && v.Token.Claims()["control_task"].(map[string]any)["iss"] != c.iss {
			t.Fatalf("the record names which key spoke: %v", v.Token.Claims()["control_task"])
		}
	}
	// A grant with operator keys and no principal key still demands a capability.
	cfg.Policy.Grant.PrincipalKey = ""
	g2, _ := Open(Config{Issuer: cfg.Issuer, Agent: cfg.Agent, Policy: cfg.Policy, Store: store, Key: cfg.Key, Clock: cfg.Clock})
	if v := g2.SubmitWith("r-none", a, "did:example:ab", nil, nil, nil, nil, ""); v.Allowed() || !strings.Contains(v.Reason, "no capability") {
		t.Fatalf("without a capability: %v", v)
	}
	if v := g2.SubmitWith("r-op", a, "did:example:ab", nil, nil, nil, nil, issue("did:example:ab#operator-2", op2)); !v.Allowed() {
		t.Fatalf("the operator's key alone suffices: %v", v.Reason)
	}
}

// A working is only as good as the rule it argues. A grant that names no judgement
// accepts FIX_WITHIN_SEMVER and nothing else; a grant that names MAJOR_UNDER_TESTS accepts
// a working that argues tests before and after crossing a major version. The certificate
// verifies either way: what changes is whether this permit takes that reason.
// majorPremises is a working that argues MAJOR_UNDER_TESTS: tests green on both sides of a major.
func majorPremises() *premises.Material {
	return &premises.Material{
		Certificate:      "@[package:uuid]{uuid} moves from %[from]{9.0.1} to %[to]{11.1.0}, a major; tests before %[testsBefore]{1}, tests after %[testsAfter]{1}, coverage %[coverage]{82}, ?[under: MAJOR_UNDER_TESTS]{green on both sides}.",
		Store:            map[string]any{"package:uuid.name": "uuid", "package:uuid.from": "9.0.1", "package:uuid.to": "11.1.0", "package:uuid.testsBefore": 1, "package:uuid.testsAfter": 1, "package:uuid.coverage": 82, "package:uuid.underTests": 1},
		Registry:         proveml.Registry{"MAJOR_UNDER_TESTS": {Field: "underTests", Op: "eq", Value: 1, Label: "the tests were green before and after the change"}},
		Provenance:       map[string]string{"package:uuid.name": "inferred", "package:uuid.from": "inferred", "package:uuid.to": "inferred", "package:uuid.testsBefore": "gateway", "package:uuid.testsAfter": "gateway", "package:uuid.coverage": "inferred", "package:uuid.underTests": "gateway"},
		RequiredControls: []string{"MAJOR_UNDER_TESTS"}, RequiredGrades: map[string]string{"underTests": "gateway"},
	}
}

func TestTheGrantNamesTheJudgementsAWorkingMayArgue(t *testing.T) {
	major := majorPremises
	action := policy.Action{Kind: "workflow.dispatch", Resource: "x/y", Params: map[string]any{"workflow": "w", "ref": "main"}}

	// The fleet's grant, naming nothing: a major's working is refused, and the reason says why.
	g, _ := fixture(t, "workflow.dispatch")
	if v := g.Submit(action, "p", nil, major()); v.Verdict != "DENY" || !strings.Contains(v.Reason, "argues MAJOR_UNDER_TESTS, which this grant does not accept") {
		t.Errorf("default grant: %+v", v)
	}
	if v := g.Submit(action, "p", nil, goodPremises()); !v.Allowed() {
		t.Errorf("default grant, within semver: %+v", v)
	}

	// A grant for a project with tests, naming the major judgement: accepted; and a working
	// that argues nothing is refused, since a certificate without a rule is a story.
	store, _ := log.Open(filepath.Join(t.TempDir(), "s"))
	seed, _ := hex.DecodeString(strings.Repeat("36", 32))
	g2, err := Open(Config{
		Issuer: "https://gateway.example/control", Agent: "did:webvh:QmTest:example.org#agent-major",
		Policy: policy.Policy{Grant: policy.Grant{Principal: "did:webvh:QmTest:example.org", Kinds: []string{"workflow.dispatch"}, Resources: []string{"x/y"}, MaxPerKind: 1, PremisesFor: []string{"workflow.dispatch"}, Judgements: []string{"MAJOR_UNDER_TESTS"}}, PathAware: true},
		Store:  store, Key: ed25519.NewKeyFromSeed(seed), AgbomDigest: strings.Repeat("a", 64), Clock: func() time.Time { return time.Unix(1754400000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if v := g2.Submit(action, "p", nil, major()); !v.Allowed() {
		t.Errorf("major grant: %+v", v)
	}
	none := major()
	none.RequiredControls = nil
	g3, _ := Open(Config{
		Issuer: "https://gateway.example/control", Agent: "did:webvh:QmTest:example.org#agent-major",
		Policy: policy.Policy{Grant: policy.Grant{Principal: "did:webvh:QmTest:example.org", Kinds: []string{"workflow.dispatch"}, Resources: []string{"x/y"}, MaxPerKind: 1, PremisesFor: []string{"workflow.dispatch"}, Judgements: []string{"MAJOR_UNDER_TESTS"}}, PathAware: true},
		Store:  store, Key: ed25519.NewKeyFromSeed(seed), AgbomDigest: strings.Repeat("a", 64), Clock: func() time.Time { return time.Unix(1754400000, 0) },
	})
	if v := g3.Submit(action, "p", nil, none); v.Verdict != "DENY" || !strings.Contains(v.Reason, "argues no judgement") {
		t.Errorf("no judgement: %+v", v)
	}
	// The grant carried in the record names what it accepts, so a reader sees the rule.
	v := g2.Submit(action, "p", nil, major())
	if grant, _ := v.Token.Claims()["control_grant"].(map[string]any); grant != nil {
		if j, _ := grant["judgements"].([]any); len(j) != 1 || j[0] != "MAJOR_UNDER_TESTS" {
			t.Errorf("grant in the record: %v", grant)
		}
	}
}

// One hand that runs several playbooks under one key is one agent: the grant is per
// task, and the task the principal's capability names selects the verbs, the premises
// and the judgements out of it. A capability for a task the grant does not have is
// refused; so is a submission without one; a task never widens the grant.
func TestOneAgentSeveralTasksTheCapabilitySelectsTheTask(t *testing.T) {
	principal := ed25519.NewKeyFromSeed([]byte("principal-seed-principal-seed-32"))
	store, _ := log.Open(t.TempDir())
	seed, _ := hex.DecodeString(strings.Repeat("12", 32))
	now := time.Unix(1_800_000_000, 0)
	cfg := Config{Issuer: "https://gateway.example/control", Agent: "did:example:ab#agent-elixir",
		Policy: policy.Policy{Grant: policy.Grant{Principal: "did:example:ab",
			Kinds: []string{"workflow.dispatch", "branch.push", "pull.open", "pull.ready"}, Resources: []string{"o/r"}, MaxPerKind: 5,
			PrincipalKey: hex.EncodeToString(principal.Public().(ed25519.PublicKey)),
			Tasks: map[string]policy.TaskGrant{
				"elixir-fix":    {Kinds: []string{"workflow.dispatch", "branch.push", "pull.open"}, PremisesFor: []string{"workflow.dispatch"}, Judgements: []string{"FIX_WITHIN_SEMVER"}},
				"major-upgrade": {Kinds: []string{"workflow.dispatch", "branch.push", "pull.open", "pull.ready"}, PremisesFor: []string{"workflow.dispatch"}, Judgements: []string{"MAJOR_UNDER_TESTS"}},
				"headers":       {Kinds: []string{"workflow.dispatch", "branch.push", "pull.open", "pull.merge"}, PremisesFor: []string{"workflow.dispatch"}, Judgements: []string{"HEADERS_SAFE_SET"}},
			}}, PathAware: true},
		Store: store, Key: ed25519.NewKeyFromSeed(seed), AgbomDigest: strings.Repeat("a", 64), Clock: func() time.Time { return now }}
	g, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cap := func(playbook string, kinds ...string) string {
		tok, _ := capability.Issue(capability.Payload{Issuer: "did:example:ab#portal", Subject: cfg.Agent, Audience: cfg.Issuer,
			Task: capability.Task{Playbook: playbook, Project: "demo"}, Kinds: kinds, Resources: []string{"o/r"},
			IssuedAt: now.Unix(), Expires: now.Add(time.Hour).Unix(), ID: "01J" + playbook}, principal)
		return tok
	}
	dispatch := policy.Action{Kind: "workflow.dispatch", Resource: "o/r", Params: map[string]any{"workflow": "w", "ref": "main"}}
	ready := policy.Action{Kind: "pull.ready", Resource: "o/r", Params: map[string]any{"number": 1}}

	// The fixer's task takes the semver working and not the major's.
	if v := g.SubmitWith("r1", dispatch, "did:example:ab", nil, goodPremises(), nil, nil, cap("elixir-fix", "workflow.dispatch")); !v.Allowed() {
		t.Fatalf("fixer within semver: %v", v.Reason)
	}
	if v := g.SubmitWith("r2", dispatch, "did:example:ab", nil, majorPremises(), nil, nil, cap("elixir-fix", "workflow.dispatch")); v.Allowed() || !strings.Contains(v.Reason, "MAJOR_UNDER_TESTS, which this grant does not accept") {
		t.Fatalf("fixer with a major's working: %v", v)
	}
	// The major's task takes it, and may mark a pull request ready; the fixer's may not.
	if v := g.SubmitWith("r3", dispatch, "did:example:ab", nil, majorPremises(), nil, nil, cap("major-upgrade", "workflow.dispatch")); !v.Allowed() {
		t.Fatalf("major under tests: %v", v.Reason)
	}
	if v := g.SubmitWith("r4", ready, "did:example:ab", nil, nil, nil, nil, cap("major-upgrade", "pull.ready")); !v.Allowed() {
		t.Fatalf("major marks ready: %v", v.Reason)
	}
	if v := g.SubmitWith("r5", ready, "did:example:ab", nil, nil, nil, nil, cap("elixir-fix", "pull.ready")); v.Allowed() || v.Reason != "kind not in grant" {
		t.Fatalf("fixer marks ready: %v", v)
	}
	// A task never widens: pull.merge is in the headers task but in nobody's grant.
	merge := policy.Action{Kind: "pull.merge", Resource: "o/r", Params: map[string]any{"number": 1}}
	if v := g.SubmitWith("r6", merge, "did:example:ab", nil, nil, nil, nil, cap("headers", "pull.merge")); v.Allowed() || v.Reason != "kind not in grant" {
		t.Fatalf("task wider than grant: %v", v)
	}
	// A task the grant does not name, and no capability at all, are refused and recorded.
	if v := g.SubmitWith("r7", dispatch, "did:example:ab", nil, goodPremises(), nil, nil, cap("vera", "workflow.dispatch")); v.Allowed() || v.Reason != "the grant names no task vera" {
		t.Fatalf("unknown task: %v", v)
	}
	if v := g.SubmitWith("r8", dispatch, "did:example:ab", nil, goodPremises(), nil, nil, ""); v.Allowed() || !strings.Contains(v.Reason, "no capability") {
		t.Fatalf("no capability: %v", v)
	}
	// The record names the task, and the bundle carries the tasks so a reader sees the rule.
	v := g.SubmitWith("r9", dispatch, "did:example:ab", nil, goodPremises(), nil, nil, cap("elixir-fix", "workflow.dispatch"))
	if v.Token.Claims()["control_task"].(map[string]any)["playbook"] != "elixir-fix" {
		t.Fatalf("task in record: %v", v.Token.Claims())
	}
	tasks, ok := cfg.Policy.Bundle()["tasks"].([]map[string]any)
	if !ok || len(tasks) != 3 || tasks[0]["task"] != "elixir-fix" {
		t.Fatalf("bundle tasks: %v", cfg.Policy.Bundle()["tasks"])
	}
	if _, has := (policy.Policy{Grant: policy.Grant{Kinds: []string{"pull.open"}}}).Bundle()["tasks"]; has {
		t.Fatal("a grant without tasks carries no tasks key, so its bundle hashes as before")
	}
	records, _ := store.Records(cfg.Agent)
	if len(records) != 9 {
		t.Fatalf("%d records", len(records))
	}
}

// What a person cannot undo needs a word that names the act. A window is fine for a branch
// and a pull request, which end in a review; an invitation is mail already sent and a seal is
// anchored, so for those kinds the grant asks for a capability naming this action, and the
// gateway spends it. Without spending, a machine holding the hand key could replay the same
// signed word until it expired, and "the operator signed this action" would mean "signed one
// like it, once" (13 September 2026).
func TestAWordForOneActIsRequiredAndSpent(t *testing.T) {
	principal := ed25519.NewKeyFromSeed([]byte("principal-seed-principal-seed-32"))
	store, _ := log.Open(t.TempDir())
	seed, _ := hex.DecodeString(strings.Repeat("11", 32))
	now := time.Unix(1_800_000_000, 0)
	cfg := Config{Issuer: "https://gateway.example/control", Agent: "did:example:ab#agent-vera",
		Policy: policy.Policy{Grant: policy.Grant{Principal: "did:example:ab", Kinds: []string{"review.invite", "review.publish"}, Resources: []string{"vera/p/*"}, MaxPerKind: 5,
			PerAction: []string{"review.invite"}, PrincipalKey: hex.EncodeToString(principal.Public().(ed25519.PublicKey))}},
		Store: store, Key: ed25519.NewKeyFromSeed(seed), Clock: func() time.Time { return now }}
	g, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	invite := policy.Action{Kind: "review.invite", Resource: "vera/p/one", Params: map[string]any{"email": "someone@example.org"}}
	word := func(act, id string) string {
		tok, _ := capability.Issue(capability.Payload{Issuer: "did:example:ab#operator", Subject: cfg.Agent, Audience: cfg.Issuer,
			Task: capability.Task{Playbook: "vera", Project: "p"}, Kinds: []string{"review.invite", "review.publish"}, Resources: []string{"vera/p/*"},
			IssuedAt: now.Unix(), Expires: now.Add(time.Hour).Unix(), ID: id, Act: act}, principal)
		return tok
	}
	// A word for a period does not carry an act, so it cannot invite.
	if v := g.SubmitWith("r1", invite, "did:example:ab", nil, nil, nil, nil, word("", "adm-1")); v.Allowed() || !strings.Contains(v.Reason, "names a period instead") {
		t.Fatalf("a period: %v", v.Reason)
	}
	// A word for another act is refused, even for the same verb on the same review.
	elsewhere := capability.ActDigest(policy.Action{Kind: "review.invite", Resource: "vera/p/one", Params: map[string]any{"email": "someone-else@example.org"}})
	if v := g.SubmitWith("r2", invite, "did:example:ab", nil, nil, nil, nil, word(elsewhere, "adm-2")); v.Allowed() || !strings.Contains(v.Reason, "another act") {
		t.Fatalf("another act: %v", v.Reason)
	}
	// The word for this act allows it once, and says on the record that it was spent.
	this := word(capability.ActDigest(invite), "adm-3")
	v := g.SubmitWith("r3", invite, "did:example:ab", nil, nil, nil, nil, this)
	if !v.Allowed() {
		t.Fatalf("this act: %v", v.Reason)
	}
	if w, ok := v.Token.Claims()["control_word"].(map[string]any); !ok || w["act"] != capability.ActDigest(invite) {
		t.Fatalf("the record does not name the word: %v", v.Token.Claims()["control_word"])
	}
	if v := g.SubmitWith("r4", invite, "did:example:ab", nil, nil, nil, nil, this); v.Allowed() || !strings.Contains(v.Reason, "already spent") {
		t.Fatalf("replay: %v", v.Reason)
	}
	// A kind the grant does not list keeps its window: publishing twice on one word is fine.
	publish := policy.Action{Kind: "review.publish", Resource: "vera/p/one", Params: map[string]any{"page_sha256": strings.Repeat("ab", 32)}}
	period := word("", "adm-4")
	if v := g.SubmitWith("r5", publish, "did:example:ab", nil, nil, nil, nil, period); !v.Allowed() {
		t.Fatalf("publish on a period: %v", v.Reason)
	}
	if v := g.SubmitWith("r6", publish, "did:example:ab", nil, nil, nil, nil, period); !v.Allowed() {
		t.Fatalf("publish again on the same period: %v", v.Reason)
	}
}
