package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abovebeyond-ai/control/capability"
	"github.com/abovebeyond-ai/control/effects"
	"github.com/abovebeyond-ai/control/evidence"
	"github.com/abovebeyond-ai/control/gateway"
	"github.com/abovebeyond-ai/control/log"
	"github.com/abovebeyond-ai/control/policy"
)

// The run lifecycle end to end (docs/run-lifecycle.md). A first session pushes the fix and runs
// out of road before the pull request: it says so with a handover and stops. A second session,
// told nothing by a person, finds the run waiting, takes it over, receives the branch and what
// remains, opens the pull request and closes the work as done, which the gateway allows only
// with the pushed branch, the opened pull request and the tests reported green. The owner's
// capability names the effects and never the run kinds; the task's lifecycle admits those.
func TestOneSessionHandsOverAndTheNextFinishesWithoutAPerson(t *testing.T) {
	var calls []string
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case strings.HasSuffix(r.URL.Path, "/git/commits/abc123"):
			_, _ = w.Write([]byte(`{"sha":"abc123","tree":{"sha":"tree-base"}}`))
		case strings.HasSuffix(r.URL.Path, "/git/blobs"):
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"sha":"blob-1"}`))
		case strings.HasSuffix(r.URL.Path, "/git/trees"):
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"sha":"tree-new"}`))
		case strings.HasSuffix(r.URL.Path, "/git/commits"):
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"sha":"commit-new"}`))
		case strings.HasSuffix(r.URL.Path, "/git/refs"):
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"ref":"refs/heads/workbench/fix"}`))
		case strings.HasSuffix(r.URL.Path, "/pulls"):
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"html_url":"https://github.com/x/y/pull/12","number":12}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer github.Close()

	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "secrets"), 0o700)
	os.WriteFile(filepath.Join(dir, "secrets", "github-token-x"), []byte("tok-x\n"), 0o600)
	operator := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	agent := "did:webvh:QmTest:example.org#agent-workbench"
	grant := policy.Grant{Principal: "did:webvh:QmTest:example.org", Kinds: []string{"branch.push", "pull.open"}, Resources: []string{"x/y"}, MaxPerKind: 1,
		PrincipalKeys: map[string]string{"did:webvh:QmTest:example.org#operator": hex.EncodeToString(operator.Public().(ed25519.PublicKey))},
		Tasks: map[string]policy.TaskGrant{"code": {Kinds: []string{"branch.push", "pull.open"}, Lifecycle: &policy.Lifecycle{
			Done: []string{"branch.push", "pull.open"}, Checks: []string{"tests"}, MaxMinutes: 120, MaxRequests: 20, CheckpointEvery: 3, MaxHandovers: 2,
		}}}}
	start := func() *service {
		store, _ := log.Open(filepath.Join(dir, "store"))
		s := &service{key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32)), store: store, effects: effects.Registry{}, gateways: map[string]*gateway.Gateway{},
			cfg: config{Issuer: "https://gw.example/control", Store: filepath.Join(dir, "store"), Secrets: filepath.Join(dir, "secrets"), Agents: map[string]struct {
				Grant policy.Grant `json:"grant"`
			}{agent: {Grant: grant}}}}
		s.effects.Add(effects.GitHub{SecretsDir: filepath.Join(dir, "secrets"), Base: github.URL})
		return s
	}
	word, _ := capability.Issue(capability.Payload{Issuer: "did:webvh:QmTest:example.org#operator", Subject: agent, Audience: "https://gw.example/control",
		Task: capability.Task{Playbook: "code", Project: "demo"}, Kinds: []string{"branch.push", "pull.open"}, Resources: []string{"x/y"},
		IssuedAt: time.Now().Unix(), Expires: time.Now().Add(time.Hour).Unix(), ID: "cap-code"}, operator)

	s := start()
	post := func(run string, kind string, params map[string]any, files []effects.FileChange) map[string]any {
		t.Helper()
		raw, _ := json.Marshal(submitRequest{Run: run, Agent: agent, Capability: word, Action: policy.Action{Kind: kind, Resource: "x/y", Params: params}, Files: files})
		rec := httptest.NewRecorder()
		s.submit(rec, httptest.NewRequest("POST", "/v1/submit", bytes.NewReader(raw)))
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != 200 {
			t.Fatalf("%s: %d %v", kind, rec.Code, out)
		}
		return out
	}
	allowed := func(out map[string]any) map[string]any {
		t.Helper()
		if out["verdict"] != "ALLOW" {
			t.Fatalf("refused: %v", out["reason"])
		}
		return out["effect"].(map[string]any)
	}
	runs := func(query string) []gateway.RunView {
		rec := httptest.NewRecorder()
		s.runs(rec, httptest.NewRequest("GET", "/v1/runs?agent="+agent+query, nil))
		var out struct{ Runs []gateway.RunView }
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out.Runs
	}

	// The first session: open, push, and stop short of the pull request with a handover.
	allowed(post("s1", policy.RunOpenKind, map[string]any{"goal": "update tar within semver"}, nil))
	files := []effects.FileChange{{Path: "package-lock.json", Content: "eyJuYW1lIjoieSJ9"}}
	digest, _ := effects.FilesDigest(files)
	if detail := allowed(post("s1", "branch.push", map[string]any{"branch": "workbench/fix", "base_sha": "abc123", "message": "Update tar", "files_sha256": digest}, files))["detail"].(map[string]any); detail["commit"] != "commit-new" {
		t.Fatalf("push: %v", detail)
	}
	if out := post("s1", policy.RunCloseKind, map[string]any{"outcome": "done", "summary": "pushed"}, nil); out["verdict"] != "DENY" || out["reason"] != "not done: the run has no pull.open yet" {
		t.Fatalf("an early done: %v", out)
	}
	allowed(post("s1", policy.RunCloseKind, map[string]any{"outcome": "handover", "summary": "tar updated on workbench/fix, tests green locally",
		"next": []any{"open the pull request from workbench/fix"}, "state": map[string]any{"branch": "workbench/fix", "commit": "commit-new"}}, nil))

	// The gateway restarts between the sessions; the run is still waiting.
	s = start()
	waiting := runs("&waiting=1")
	if len(waiting) != 1 || waiting[0].Run != "s1" || waiting[0].State["closed"] != "handover" {
		t.Fatalf("waiting: %+v", waiting)
	}

	// The second session takes it over and is handed the branch and what remains.
	h := allowed(post("s2", policy.RunOpenKind, map[string]any{"continues": waiting[0].Run}, nil))["detail"].(map[string]any)["handover"].(map[string]any)
	state := h["handover"].(map[string]any)["state"].(map[string]any)
	next := h["handover"].(map[string]any)["next"].([]any)
	if state["branch"] != "workbench/fix" || len(next) != 1 {
		t.Fatalf("handover: %v", h)
	}
	if detail := allowed(post("s2", "pull.open", map[string]any{"branch": state["branch"], "base": "main", "title": "Update tar"}, nil))["detail"].(map[string]any); detail["url"] != "https://github.com/x/y/pull/12" {
		t.Fatalf("pull request: %v", detail)
	}
	if out := post("s2", policy.RunCloseKind, map[string]any{"outcome": "done", "summary": "opened #12", "checks": []any{map[string]any{"name": "tests", "result": "failed"}}}, nil); out["verdict"] != "DENY" {
		t.Fatalf("done on red: %v", out)
	}
	allowed(post("s2", policy.RunCloseKind, map[string]any{"outcome": "done", "summary": "opened #12 for review", "checks": []any{map[string]any{"name": "tests", "result": "passed"}}}, nil))

	if len(runs("&waiting=1")) != 0 {
		t.Error("nothing should wait once the work is done")
	}
	all := runs("")
	if len(all) != 2 || all[0].State["continued_by"] != "s2" || all[1].State["closed"] != "done" || all[1].State["continues"] != "s1" {
		t.Errorf("runs: %+v", all)
	}
	// Review stays where it was: one push, one pull request, nothing merged.
	merged := strings.Join(calls, " ")
	if strings.Count(merged, "POST /repos/x/y/pulls") != 1 || strings.Contains(merged, "/merge") {
		t.Errorf("GitHub saw %v", calls)
	}
	records, _ := s.store.Records(agent)
	g, _ := s.gateway(agent)
	if r := evidence.VerifyChain(records, g.PublicKey(), g.Measurement()); !r.OK {
		t.Error(r.Reason)
	}
}
