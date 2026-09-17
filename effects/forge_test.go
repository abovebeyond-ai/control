package effects

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abovebeyond-ai/control/policy"
)

// The deploy trigger URL is the secret: it is read from the gateway's secrets under the
// project's name, called once, and never appears in the outcome, not even on a failure.
func TestADeployIsTriggeredFromTheSecretAndTheUrlStaysOut(t *testing.T) {
	calls := []string{}
	forge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.String())
		if strings.Contains(r.URL.RawQuery, "token=s3cret") {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(403)
	}))
	defer forge.Close()
	dir := t.TempDir()
	trigger := forge.URL + "/servers/1/sites/2/deploy/http?token=s3cret"
	os.WriteFile(filepath.Join(dir, ForgeSecret("demo")), []byte(trigger+"\n"), 0o600)
	os.WriteFile(filepath.Join(dir, ForgeSecret("elsewhere")), []byte("https://evil.example/hook\n"), 0o600)
	f := Forge{SecretsDir: dir, Base: forge.URL + "/"}
	sha := "0123456789abcdef0123456789abcdef01234567"

	out := f.Perform(context.Background(), policy.Action{Kind: policy.ForgeDeployKind, Resource: "forge:demo", Params: map[string]any{"sha": sha, "pull": 511}})
	if !out.OK || out.Detail["project"] != "demo" || out.Detail["commit"] != sha || out.Detail["pull"] != 511 || out.Detail["accepted"] != true {
		t.Fatalf("%+v", out)
	}
	if len(calls) != 1 || calls[0] != "POST /servers/1/sites/2/deploy/http?token=s3cret" {
		t.Errorf("Forge saw %v", calls)
	}
	for _, o := range []Outcome{
		f.Perform(context.Background(), policy.Action{Kind: policy.ForgeDeployKind, Resource: "forge:elsewhere"}),
		f.Perform(context.Background(), policy.Action{Kind: policy.ForgeDeployKind, Resource: "forge:nobody"}),
		f.Perform(context.Background(), policy.Action{Kind: policy.ForgeDeployKind, Resource: "portal:demo"}),
	} {
		if o.OK {
			t.Errorf("must be refused: %+v", o)
		}
		if strings.Contains(o.Error, "s3cret") || strings.Contains(o.Error, "evil.example") {
			t.Errorf("the outcome carries the secret or its address: %s", o.Error)
		}
	}
	if len(calls) != 1 {
		t.Errorf("a refused trigger reached a server: %v", calls)
	}
	// Forge's own refusal is the outcome, without the URL.
	os.WriteFile(filepath.Join(dir, ForgeSecret("demo")), []byte(forge.URL+"/servers/1/sites/2/deploy/http?token=wrong\n"), 0o600)
	if o := f.Perform(context.Background(), policy.Action{Kind: policy.ForgeDeployKind, Resource: "forge:demo"}); o.OK || o.Error != "Forge answered 403 for the deploy of demo" {
		t.Errorf("%+v", o)
	}
}

// preview.push moves the one branch a preview site tracks: forced when it exists, made
// when it does not, and refused for any other branch before GitHub is reached.
func TestThePreviewBranchIsForcedOrMadeAndNoOtherBranchIsTouched(t *testing.T) {
	calls := []string{}
	bodies := []string{}
	exists := true
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		bodies = append(bodies, string(buf[:n]))
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/git/ref/heads/preview"):
			if !exists {
				w.WriteHeader(404)
				return
			}
			_, _ = w.Write([]byte(`{"ref":"refs/heads/preview","object":{"sha":"oldoldoldoldoldoldoldoldoldoldoldoldoldo"}}`))
		case r.Method == "PATCH" && strings.HasSuffix(r.URL.Path, "/git/refs/heads/preview"):
			_, _ = w.Write([]byte(`{"ref":"refs/heads/preview"}`))
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/git/refs"):
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"ref":"refs/heads/preview"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer github.Close()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "github-token-o"), []byte("tok\n"), 0o600)
	g := GitHub{SecretsDir: dir, Base: github.URL}
	sha := "0123456789abcdef0123456789abcdef01234567"

	out := g.Perform(context.Background(), policy.Action{Kind: policy.PreviewPushKind, Resource: "o/r", Params: map[string]any{"branch": "preview", "sha": sha, "pull": 511, "head": "workbench/x"}})
	if !out.OK || out.Detail["commit"] != sha || out.Detail["previous"] != "oldoldoldoldoldoldoldoldoldoldoldoldoldo" || out.Detail["created"] != false || out.Detail["pull"] != 511 || out.Detail["head"] != "workbench/x" {
		t.Fatalf("%+v", out)
	}
	if strings.Join(calls, " ") != "GET /repos/o/r/git/ref/heads/preview PATCH /repos/o/r/git/refs/heads/preview" || !strings.Contains(bodies[1], `"force":true`) || !strings.Contains(bodies[1], `"sha":"`+sha+`"`) {
		t.Errorf("GitHub saw %v %v", calls, bodies)
	}

	exists = false
	calls, bodies = nil, nil
	out = g.Perform(context.Background(), policy.Action{Kind: policy.PreviewPushKind, Resource: "o/r", Params: map[string]any{"branch": "preview", "sha": sha}})
	if !out.OK || out.Detail["created"] != true {
		t.Fatalf("%+v", out)
	}
	if strings.Join(calls, " ") != "GET /repos/o/r/git/ref/heads/preview POST /repos/o/r/git/refs" || !strings.Contains(bodies[1], `"ref":"refs/heads/preview"`) {
		t.Errorf("GitHub saw %v %v", calls, bodies)
	}

	calls = nil
	for _, params := range []map[string]any{{"branch": "main", "sha": sha}, {"branch": "preview", "sha": "0123456"}} {
		if o := g.Perform(context.Background(), policy.Action{Kind: policy.PreviewPushKind, Resource: "o/r", Params: params}); o.OK {
			t.Errorf("must be refused: %+v", o)
		}
	}
	if len(calls) != 0 {
		t.Errorf("GitHub was reached for a refused push: %v", calls)
	}
}
