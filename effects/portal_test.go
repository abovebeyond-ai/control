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

// A project field outside the known list is refused before anything is written: Portal's
// validation would drop it silently and the record would say the field was set.
func TestAnUnknownProjectFieldIsRefusedBeforeTheWrite(t *testing.T) {
	srv, calls := fakePortal(t)
	p := portalWithToken(t, srv.URL)
	o := p.Perform(context.Background(), policy.Action{Kind: "portal.project.patch", Resource: "portal:hoet", Params: map[string]any{"fields": map[string]any{"status": "active", "monitor": false}}})
	if o.OK || len(*calls) != 0 {
		t.Fatalf("an unknown field must be refused without a call: %+v, %d calls", o, len(*calls))
	}
	o = p.Perform(context.Background(), policy.Action{Kind: "portal.project.patch", Resource: "portal:hoet", Params: map[string]any{"fields": map[string]any{"nextAction": "bellen", "elixir": true}}})
	if !o.OK || (*calls)[0].Method != "PATCH" || (*calls)[0].Path != "/api/ingest/project/hoet" {
		t.Fatalf("a known patch goes to the project: %+v %+v", o, *calls)
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
