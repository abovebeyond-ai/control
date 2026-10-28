package gateway

import (
	"crypto/ed25519"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abovebeyond-ai/control/evidence"
	"github.com/abovebeyond-ai/control/log"
	"github.com/abovebeyond-ai/control/policy"
)

// lifeFixture is a coding hand under a lifecycle, with a clock the test moves.
func lifeFixture(t *testing.T, life policy.Lifecycle, dir string, now *time.Time) *Gateway {
	t.Helper()
	store, err := log.Open(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(strings.Repeat("12", 32))
	g, err := Open(Config{
		Issuer: "https://gateway.example/control", Agent: "did:webvh:QmTest:example.org#agent-code",
		Policy: policy.Policy{Grant: policy.Grant{Principal: "did:webvh:QmTest:example.org", Kinds: []string{"branch.push", "pull.open"}, Resources: []string{"x/y"}, MaxPerKind: 1, Lifecycle: &life}, PathAware: true},
		Store:  store, Key: ed25519.NewKeyFromSeed(seed), AgbomDigest: strings.Repeat("a", 64), Clock: func() time.Time { return *now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

var (
	push   = policy.Action{Kind: "branch.push", Resource: "x/y", Params: map[string]any{"branch": "workbench/fix", "files_sha256": strings.Repeat("b", 64)}}
	openPR = policy.Action{Kind: "pull.open", Resource: "x/y", Params: map[string]any{"branch": "workbench/fix", "base": "main"}}
)

func run(kind string, params map[string]any) policy.Action {
	return policy.Action{Kind: kind, Resource: "x/y", Params: params}
}

func handover(next ...any) policy.Action {
	return run(policy.RunCloseKind, map[string]any{"outcome": "handover", "summary": "pushed, no pull request yet", "next": next})
}

func TestARunClosesAsDoneOnlyWhenItsDefinitionOfDoneHolds(t *testing.T) {
	now := time.Unix(1754400000, 0)
	g := lifeFixture(t, policy.Lifecycle{Done: []string{"branch.push", "pull.open"}, Checks: []string{"tests"}}, t.TempDir(), &now)
	p := "did:webvh:QmTest:example.org"
	done := func(checks ...any) policy.Action {
		return run(policy.RunCloseKind, map[string]any{"outcome": "done", "summary": "fixed", "checks": checks})
	}
	if v := g.SubmitIn("r1", push, p, nil, nil); !v.Allowed() {
		t.Fatal(v.Reason)
	}
	if v := g.SubmitIn("r1", done(map[string]any{"name": "tests", "result": "passed"}), p, nil, nil); v.Allowed() || v.Reason != "not done: the run has no pull.open yet" {
		t.Fatalf("done before the pull request: %s %s", v.Verdict, v.Reason)
	}
	if v := g.SubmitIn("r1", openPR, p, nil, nil); !v.Allowed() {
		t.Fatal(v.Reason)
	}
	if v := g.SubmitIn("r1", done(), p, nil, nil); v.Allowed() || v.Reason != "not done: the check tests is not reported" {
		t.Fatalf("done without its checks: %s %s", v.Verdict, v.Reason)
	}
	if v := g.SubmitIn("r1", done(map[string]any{"name": "tests", "result": "failed"}), p, nil, nil); v.Allowed() || v.Reason != "not done: the check tests reports failed" {
		t.Fatalf("done on red: %s %s", v.Verdict, v.Reason)
	}
	v := g.SubmitIn("r1", done(map[string]any{"name": "tests", "result": "passed"}), p, nil, nil)
	if !v.Allowed() {
		t.Fatal(v.Reason)
	}
	if c := v.Token.Claims()["control_lifecycle"].(map[string]any); c["effects"] != 2 || c["requests"] != 5 {
		t.Errorf("the record carries the state it judged: %v", c)
	}
	// A closed run does nothing more, and is nobody's to continue.
	if v := g.SubmitIn("r1", run(policy.RunCheckpointKind, map[string]any{"summary": "one more thing"}), p, nil, nil); v.Allowed() || !strings.HasPrefix(v.Reason, "the run was closed as done") {
		t.Fatalf("after done: %s %s", v.Verdict, v.Reason)
	}
	if v := g.SubmitIn("r2", run(policy.RunOpenKind, map[string]any{"continues": "r1"}), p, nil, nil); v.Allowed() || v.Reason != "the run r1 closed as done and hands nothing over" {
		t.Fatalf("continuing a finished run: %s %s", v.Verdict, v.Reason)
	}
}

func TestARunPastItsTimeOrBudgetMayOnlyClose(t *testing.T) {
	now := time.Unix(1754400000, 0)
	g := lifeFixture(t, policy.Lifecycle{MaxMinutes: 30, MaxRequests: 4}, t.TempDir(), &now)
	p := "did:webvh:QmTest:example.org"
	if v := g.SubmitIn("slow", push, p, nil, nil); !v.Allowed() {
		t.Fatal(v.Reason)
	}
	now = now.Add(31 * time.Minute)
	if v := g.SubmitIn("slow", openPR, p, nil, nil); v.Allowed() || !strings.Contains(v.Reason, "past its 30 minutes") {
		t.Fatalf("past time: %s %s", v.Verdict, v.Reason)
	}
	if v := g.SubmitIn("slow", handover("open the pull request"), p, nil, nil); !v.Allowed() {
		t.Fatalf("the way out stays open: %s", v.Reason)
	}

	// A hand looping on a refusal spends its requests as surely as one looping on effects.
	if v := g.SubmitIn("loop", push, p, nil, nil); !v.Allowed() {
		t.Fatal(v.Reason)
	}
	for i := 0; i < 3; i++ {
		g.SubmitIn("loop", push, p, nil, nil) // a second push in one run, refused each time
	}
	if v := g.SubmitIn("loop", openPR, p, nil, nil); v.Allowed() || !strings.Contains(v.Reason, "made its 4 requests") {
		t.Fatalf("past budget: %s %s", v.Verdict, v.Reason)
	}
	if v := g.SubmitIn("loop", run(policy.RunCloseKind, map[string]any{"outcome": "abandoned", "summary": "kept pushing twice"}), p, nil, nil); !v.Allowed() {
		t.Fatal(v.Reason)
	}
}

func TestACheckpointIsOwedAndAStalledRunHandsItOver(t *testing.T) {
	now := time.Unix(1754400000, 0)
	g := lifeFixture(t, policy.Lifecycle{MaxMinutes: 30, CheckpointEvery: 1}, t.TempDir(), &now)
	p := "did:webvh:QmTest:example.org"
	g.SubmitIn("a", push, p, nil, nil)
	if v := g.SubmitIn("a", openPR, p, nil, nil); v.Allowed() || !strings.Contains(v.Reason, "run.checkpoint first") {
		t.Fatalf("no checkpoint: %s %s", v.Verdict, v.Reason)
	}
	cp := run(policy.RunCheckpointKind, map[string]any{"summary": "pushed workbench/fix", "next": []any{"open the pull request"}, "state": map[string]any{"branch": "workbench/fix"}})
	if v := g.SubmitIn("a", cp, p, nil, nil); !v.Allowed() {
		t.Fatal(v.Reason)
	}
	// Still running: nobody takes it over.
	open := run(policy.RunOpenKind, map[string]any{"continues": "a"})
	if v := g.SubmitIn("b", open, p, nil, nil); v.Allowed() || !strings.Contains(v.Reason, "still running") {
		t.Fatalf("a live run taken over: %s %s", v.Verdict, v.Reason)
	}
	// The hand dies without closing. Past its time, the checkpoint is the handover.
	now = now.Add(45 * time.Minute)
	if runs := g.Runs(); len(runs) != 2 || runs[0].Run != "a" || !runs[0].Stalled || !runs[0].Waiting {
		t.Fatalf("runs: %+v", runs)
	}
	if v := g.SubmitIn("c", open, p, nil, nil); !v.Allowed() {
		t.Fatal(v.Reason)
	}
	h := g.Handover("a")
	if h["stalled"] != true || h["handover"].(map[string]any)["state"].(map[string]any)["branch"] != "workbench/fix" {
		t.Errorf("handover: %v", h)
	}
	if v := g.SubmitIn("d", open, p, nil, nil); v.Allowed() || v.Reason != "the run a was already continued by c" {
		t.Fatalf("a second taker: %s %s", v.Verdict, v.Reason)
	}
}

func TestAChainOfHandoversStopsAndAHandoverCarriesNoCredential(t *testing.T) {
	now := time.Unix(1754400000, 0)
	g := lifeFixture(t, policy.Lifecycle{MaxHandovers: 2}, t.TempDir(), &now)
	p := "did:webvh:QmTest:example.org"
	if v := g.SubmitIn("r0", handover("everything"), p, nil, nil); !v.Allowed() {
		t.Fatal(v.Reason)
	}
	prev := "r0"
	for _, next := range []string{"r1", "r2"} {
		if v := g.SubmitIn(next, run(policy.RunOpenKind, map[string]any{"continues": prev}), p, nil, nil); !v.Allowed() {
			t.Fatalf("%s: %s", next, v.Reason)
		}
		if v := g.SubmitIn(next, handover("still everything"), p, nil, nil); !v.Allowed() {
			t.Fatalf("%s: %s", next, v.Reason)
		}
		prev = next
	}
	if v := g.SubmitIn("r3", run(policy.RunOpenKind, map[string]any{"continues": "r2"}), p, nil, nil); v.Allowed() || !strings.Contains(v.Reason, "handed over 2 times") {
		t.Fatalf("the third handover: %s %s", v.Verdict, v.Reason)
	}
	leak := run(policy.RunCloseKind, map[string]any{"outcome": "handover", "summary": "use ghp_abcdefghijklmnop to push", "next": []any{"push"}})
	if v := g.SubmitIn("r4", leak, p, nil, nil); v.Allowed() || !strings.Contains(v.Reason, "looks like it carries a credential") {
		t.Fatalf("a credential handed over: %s %s", v.Verdict, v.Reason)
	}
	if v := g.SubmitIn("r5", run(policy.RunCloseKind, map[string]any{"outcome": "handover", "summary": "s"}), p, nil, nil); v.Allowed() || v.Reason != "a handover names what remains in next" {
		t.Fatalf("an empty handover: %s %s", v.Verdict, v.Reason)
	}
	if v := g.Submit(push, p, nil, nil); v.Allowed() || v.Reason != "a run under a lifecycle must have a name" {
		t.Fatalf("no run name: %s %s", v.Verdict, v.Reason)
	}
}

func TestTheLifecycleSurvivesARestart(t *testing.T) {
	now := time.Unix(1754400000, 0)
	dir := t.TempDir()
	life := policy.Lifecycle{Done: []string{"branch.push", "pull.open"}}
	g := lifeFixture(t, life, dir, &now)
	p := "did:webvh:QmTest:example.org"
	g.SubmitIn("a", push, p, nil, nil)
	g.SubmitIn("a", handover("open the pull request"), p, nil, nil)
	g.SubmitIn("b", run(policy.RunOpenKind, map[string]any{"continues": "a"}), p, nil, nil)

	g = lifeFixture(t, life, dir, &now)
	if v := g.SubmitIn("c", run(policy.RunOpenKind, map[string]any{"continues": "a"}), p, nil, nil); v.Allowed() || v.Reason != "the run a was already continued by b" {
		t.Fatalf("after a restart: %s %s", v.Verdict, v.Reason)
	}
	if v := g.SubmitIn("a", openPR, p, nil, nil); v.Allowed() || !strings.HasPrefix(v.Reason, "the run was closed as handover") {
		t.Fatalf("after a restart: %s %s", v.Verdict, v.Reason)
	}
	// The pull request in b and the push in a: the chain is done.
	if v := g.SubmitIn("b", openPR, p, nil, nil); !v.Allowed() {
		t.Fatal(v.Reason)
	}
	if v := g.SubmitIn("b", run(policy.RunCloseKind, map[string]any{"outcome": "done", "summary": "opened the pull request"}), p, nil, nil); !v.Allowed() {
		t.Fatal(v.Reason)
	}
	store, _ := log.Open(filepath.Join(dir, "store"))
	records, _ := store.Records(g.cfg.Agent)
	if r := evidence.VerifyChain(records, g.PublicKey(), g.Measurement()); !r.OK {
		t.Error(r.Reason)
	}
}

func TestWithoutALifecycleTheRunKindsAreNotInTheGrant(t *testing.T) {
	g, _ := fixture(t)
	v := g.SubmitIn("r", run(policy.RunCloseKind, map[string]any{"outcome": "done", "summary": "s"}), "did:webvh:QmTest:example.org", nil, nil)
	if v.Allowed() || v.Reason != "kind not in grant" {
		t.Fatalf("%s %s", v.Verdict, v.Reason)
	}
	if _, ok := v.Token.Claims()["control_lifecycle"]; ok {
		t.Error("a grant without a lifecycle writes no lifecycle state")
	}
}
