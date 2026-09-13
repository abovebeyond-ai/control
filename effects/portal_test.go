package effects

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/abovebeyond-ai/control/policy"
)

type portalCall struct {
	Method, Path, Auth, Evidence, Capability string
	Body                                     map[string]any
}

// A fake Portal that remembers what it was asked, answers 2xx to what it knows and 422
// to the rest, the way the ingest API refuses a body its validation does not accept.
func fakePortal(t *testing.T) (*httptest.Server, *[]portalCall) {
	var calls []portalCall
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		calls = append(calls, portalCall{Method: r.Method, Path: r.URL.Path, Auth: r.Header.Get("Authorization"), Evidence: r.Header.Get("Control-Evidence"), Capability: r.Header.Get("Control-Capability"), Body: body})
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/ingest/update" && body["title"] == "":
			w.WriteHeader(422)
			_, _ = w.Write([]byte(`{"message":"The title field is required."}`))
		case r.URL.Path == "/api/ingest/measure/hoet":
			w.WriteHeader(202)
			_, _ = w.Write([]byte(`{"queued":true}`))
		case r.URL.Path == "/api/ingest/playbooks/maintenance/hoet":
			w.WriteHeader(409)
			_, _ = w.Write([]byte(`{"queued":false,"refused":"no tests"}`))
		default:
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func portalWithToken(t *testing.T, base string) Portal {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "portal-token"), []byte("tok-portal\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return Portal{SecretsDir: dir, Base: base}
}

// The token stays in the gateway's secrets and goes out as the bearer; the record and
// the capability the gateway added ride as headers, never in the body Portal validates.
func TestAnUpdateIsWrittenWithTheGatewaysTokenAndItsEvidence(t *testing.T) {
	srv, calls := fakePortal(t)
	p := portalWithToken(t, srv.URL)
	o := p.Perform(context.Background(), policy.Action{Kind: "portal.update", Resource: "portal:hoet", Params: map[string]any{
		"title": "Rapport", "body": []any{"Regel.", "- punt"}, "clientVisible": false, "evidence": "ev.token", "capability": "cap.token", "stray": "no",
	}})
	if !o.OK {
		t.Fatalf("update refused: %s", o.Error)
	}
	c := (*calls)[0]
	if c.Method != "POST" || c.Path != "/api/ingest/update" || c.Auth != "Bearer tok-portal" {
		t.Fatalf("unexpected call %+v", c)
	}
	if c.Evidence != "ev.token" || c.Capability != "cap.token" {
		t.Fatalf("evidence must travel in the headers: %+v", c)
	}
	if c.Body["project"] != "hoet" || c.Body["title"] != "Rapport" {
		t.Fatalf("body must name the project and carry the update: %v", c.Body)
	}
	for _, k := range []string{"evidence", "capability", "stray"} {
		if _, there := c.Body[k]; there {
			t.Fatalf("%s must not reach Portal's body", k)
		}
	}
}

// What Portal refuses is an effect that failed, named by Portal's own words.
func TestPortalsRefusalIsTheOutcome(t *testing.T) {
	srv, _ := fakePortal(t)
	p := portalWithToken(t, srv.URL)
	o := p.Perform(context.Background(), policy.Action{Kind: "portal.playbook", Resource: "portal:hoet", Params: map[string]any{"playbook": "maintenance"}})
	if o.OK || o.Error != "Portal answered 409: no tests" {
		t.Fatalf("expected Portal's refusal, got %+v", o)
	}
	o = p.Perform(context.Background(), policy.Action{Kind: "portal.measure", Resource: "portal:hoet", Params: map[string]any{"only": "site"}})
	if !o.OK || o.Detail["queued"] != true {
		t.Fatalf("a queued measurement is a performed effect: %+v", o)
	}
}

// A project patch carries the fields the schema names and nothing else (the schema
// refuses the rest before the adapter sees it); a patch with nothing to set is refused
// without a call, and clearNextAction becomes the null Portal takes.
func TestAProjectPatchCarriesOnlyProjectFields(t *testing.T) {
	srv, calls := fakePortal(t)
	p := portalWithToken(t, srv.URL)
	o := p.Perform(context.Background(), policy.Action{Kind: "portal.project.patch", Resource: "portal:hoet", Params: map[string]any{"evidence": "ev", "capability": "cap"}})
	if o.OK || len(*calls) != 0 {
		t.Fatalf("a patch with no project field must be refused without a call: %+v, %d calls", o, len(*calls))
	}
	o = p.Perform(context.Background(), policy.Action{Kind: "portal.project.patch", Resource: "portal:hoet", Params: map[string]any{"clearNextAction": true, "elixir": true, "evidence": "ev"}})
	if !o.OK || (*calls)[0].Method != "PATCH" || (*calls)[0].Path != "/api/ingest/project/hoet" {
		t.Fatalf("a known patch goes to the project: %+v %+v", o, *calls)
	}
	body := (*calls)[0].Body
	if v, there := body["nextAction"]; !there || v != nil || body["elixir"] != true {
		t.Fatalf("clearNextAction must reach Portal as a null nextAction: %v", body)
	}
	if _, there := body["evidence"]; there {
		t.Fatal("the evidence rides in the headers, not the body")
	}
}

// Every Portal kind has a parameter schema, or the gateway refuses it as out of schema
// before the grant is read: the first proposal of a Portal write on 2026-09-13 was
// refused with "no parameter schema is registered for portal.task".
func TestEveryPortalKindHasASchema(t *testing.T) {
	for _, k := range (Portal{}).Kinds() {
		if _, ok := policy.Schemas[k]; !ok {
			t.Fatalf("%s has no parameter schema", k)
		}
	}
	err := policy.Validate(policy.Action{Kind: "portal.update", Resource: "portal:hoet", Params: map[string]any{"title": "Rapport", "body": []any{"Regel.", "- punt"}, "clientVisible": false}})
	if err != nil {
		t.Fatalf("a well-formed update must pass the schema: %v", err)
	}
	err = policy.Validate(policy.Action{Kind: "portal.project.patch", Resource: "portal:hoet", Params: map[string]any{"milestones": []any{map[string]any{"title": "Fase", "status": "bezig"}}, "stack": []any{"Laravel 13"}, "clearNextAction": true}})
	if err != nil {
		t.Fatalf("a well-formed patch must pass the schema: %v", err)
	}
	if err := policy.Validate(policy.Action{Kind: "portal.time_entry", Resource: "portal:hoet", Params: map[string]any{"hours": 2.5, "monitor": false}}); err == nil {
		t.Fatal("a key outside the schema must be refused")
	}
}

// The resource is the project, prefixed so it cannot be mistaken for a repository, and
// without a token nothing is attempted.
func TestTheResourceIsAPrefixedSlugAndNoTokenMeansNoCall(t *testing.T) {
	srv, calls := fakePortal(t)
	p := portalWithToken(t, srv.URL)
	for _, res := range []string{"hoet", "portal:", "portal:a/b", "owner/repo"} {
		if o := p.Perform(context.Background(), policy.Action{Kind: "portal.task", Resource: res, Params: map[string]any{"key": "packages", "state": "bezig"}}); o.OK {
			t.Fatalf("resource %q must be refused", res)
		}
	}
	if len(*calls) != 0 {
		t.Fatal("a refused resource must not reach Portal")
	}
	bare := Portal{SecretsDir: t.TempDir(), Base: srv.URL}
	if o := bare.Perform(context.Background(), policy.Action{Kind: "portal.task", Resource: "portal:hoet", Params: map[string]any{"key": "packages", "state": "bezig"}}); o.OK || len(*calls) != 0 {
		t.Fatalf("without a token nothing is attempted: %+v", o)
	}
	o := p.Perform(context.Background(), policy.Action{Kind: "portal.task", Resource: "portal:hoet", Params: map[string]any{"key": "packages", "state": "bezig", "url": "https://github.com/x/y/pull/1"}})
	if !o.OK || (*calls)[0].Path != "/api/ingest/tasks/hoet/packages" || (*calls)[0].Body["state"] != "bezig" {
		t.Fatalf("a task goes to tasks/<slug>/<key>: %+v %+v", o, *calls)
	}
}
