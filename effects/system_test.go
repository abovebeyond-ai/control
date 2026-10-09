package effects

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/abovebeyond-ai/control/policy"
)

// An action on a running system arrives at its control endpoint with the evidence in the
// headers and only the kind's own parameters in the body; the system's answer is the outcome.
func TestASystemActionCarriesItsEvidenceAndOnlyItsParams(t *testing.T) {
	var got struct {
		Kind     string         `json:"kind"`
		Resource string         `json:"resource"`
		Params   map[string]any `json:"params"`
	}
	var evidence, capability string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/control/act" {
			t.Fatalf("expected POST /control/act, got %s %s", r.Method, r.URL.Path)
		}
		evidence, capability = r.Header.Get("Control-Evidence"), r.Header.Get("Control-Capability")
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"ok":true,"written":34}`))
	}))
	defer srv.Close()

	s := System{Bases: map[string]string{"stocklist:platform": srv.URL + "/"}}
	o := s.Perform(context.Background(), policy.Action{Kind: "stocklist.photos_repair", Resource: "stocklist:platform", Params: map[string]any{
		"vehicle": float64(23312), "apply": true, "evidence": "ev-b64", "capability": "cap.tok",
	}})
	if !o.OK || o.Detail["written"] != float64(34) || o.Detail["resource"] != "stocklist:platform" {
		t.Fatalf("the system's answer must be the outcome: %+v", o)
	}
	if evidence != "ev-b64" || capability != "cap.tok" {
		t.Fatalf("the evidence rides in the headers: %q %q", evidence, capability)
	}
	if got.Kind != "stocklist.photos_repair" || got.Resource != "stocklist:platform" || got.Params["vehicle"] != float64(23312) || got.Params["apply"] != true {
		t.Fatalf("the body names the action: %+v", got)
	}
	if _, ok := got.Params["evidence"]; ok {
		t.Fatalf("the evidence must not become a parameter: %+v", got.Params)
	}
}

// A refusal comes back in the system's own words, and an unknown system is not guessed at.
func TestASystemRefusalAndAnUnknownSystem(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"refused":"the capability does not cover stocklist.photos_repair"}`))
	}))
	defer srv.Close()
	s := System{Bases: map[string]string{"stocklist:platform": srv.URL}}
	o := s.Perform(context.Background(), policy.Action{Kind: "stocklist.photos_repair", Resource: "stocklist:platform", Params: map[string]any{"vehicle": float64(1)}})
	if o.OK || !strings.Contains(o.Error, "answered 403") || !strings.Contains(o.Error, "does not cover") {
		t.Fatalf("a refusal is the system's: %+v", o)
	}
	o = s.Perform(context.Background(), policy.Action{Kind: "stocklist.photos_repair", Resource: "stocklist:other", Params: map[string]any{"vehicle": float64(1)}})
	if o.OK || !strings.Contains(o.Error, "no system is configured") {
		t.Fatalf("an unknown system must be refused by name: %+v", o)
	}
}

// Every system kind has a schema, or the gateway refuses it before the grant is read; and the
// photo repair takes one car and nothing else.
func TestEverySystemKindHasASchema(t *testing.T) {
	for _, k := range (System{}).Kinds() {
		if _, ok := policy.Schemas[k]; !ok {
			t.Fatalf("%s has no parameter schema", k)
		}
	}
	ok := policy.Validate(policy.Action{Kind: "stocklist.photos_repair", Resource: "stocklist:platform", Params: map[string]any{"vehicle": float64(23312), "apply": false}})
	if ok != nil {
		t.Fatalf("one car must pass: %v", ok)
	}
	if err := policy.Validate(policy.Action{Kind: "stocklist.photos_repair", Resource: "stocklist:platform", Params: map[string]any{"vehicle": float64(1), "all": true}}); err == nil {
		t.Fatal("a parameter outside the schema must be refused")
	}
	if err := policy.Validate(policy.Action{Kind: "stocklist.photos_repair", Resource: "stocklist:platform", Params: map[string]any{"apply": true}}); err == nil {
		t.Fatal("a repair without a car must be refused")
	}
	brief := map[string]any{"title": "Refurbished phones", "description": "What drives it?", "context": "From a call.",
		"sources": []any{map[string]any{"url": "https://example.com/r", "label": "Report"}, map[string]any{"type": "insight", "id": "ins-1"}}}
	if err := policy.Validate(policy.Action{Kind: "studio.research_draft", Resource: "observatory:pipeline", Params: brief}); err != nil {
		t.Fatalf("a brief with its sources must pass: %v", err)
	}
	if err := policy.Validate(policy.Action{Kind: "studio.research_draft", Resource: "observatory:pipeline", Params: map[string]any{"title": "No question"}}); err == nil {
		t.Fatal("a brief without a description must be refused")
	}
	if err := policy.Validate(policy.Action{Kind: "studio.research_draft", Resource: "observatory:pipeline", Params: map[string]any{"title": "t", "description": "d", "publish": true}}); err == nil {
		t.Fatal("a parameter outside the schema must be refused")
	}
	if err := policy.Validate(policy.Action{Kind: "studio.research_draft", Resource: "observatory:pipeline", Params: map[string]any{"title": "t", "description": "d", "sources": []any{map[string]any{"id": float64(3)}}}}); err == nil {
		t.Fatal("a source that is not an object of strings must be refused")
	}
	if err := policy.Validate(policy.Action{Kind: "observatory.trend_edit", Resource: "observatory:pipeline", Params: map[string]any{"trend": "insight-1", "field": "headline", "text": "Sharper"}}); err != nil {
		t.Fatalf("a trend edit must pass: %v", err)
	}
	if err := policy.Validate(policy.Action{Kind: "observatory.trend_site", Resource: "observatory:pipeline", Params: map[string]any{"trend": "insight-1"}}); err == nil {
		t.Fatal("a site decision without an action must be refused")
	}
}

// Every action on a running system is named on the repair list or deliberately left off it,
// so a new system kind cannot slip under the passkey by default, nor be forgotten there.
func TestEverySystemKindIsDecidedForTheRepairList(t *testing.T) {
	notRepair := map[string]bool{}
	for _, k := range SystemKinds {
		if !policy.IsRepairKind(k) && !notRepair[k] {
			t.Errorf("%s is neither on policy.RepairKinds nor deliberately left off", k)
		}
	}
}
