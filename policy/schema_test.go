package policy

import (
	"strings"
	"testing"
)

// Parameters are held to the kind's schema: a key the schema does not name, a wrong
// type or a missing required key refuses the call (row 4.1.4).
func TestParametersAreHeldToTheSchema(t *testing.T) {
	ok := Action{Kind: "workflow.dispatch", Resource: "o/r", Params: map[string]any{"workflow": "elixir-fix.yml", "ref": "main", "packages": float64(3), "plan_sha256": strings.Repeat("a", 64), "inputs": map[string]any{"plan": "[]"}}}
	if err := Validate(ok); err != nil {
		t.Fatal(err)
	}
	cases := map[string]Action{
		"unknown key":     {Kind: "pull.open", Resource: "o/r", Params: map[string]any{"branch": "b", "base": "main", "force": true}},
		"missing base":    {Kind: "pull.open", Resource: "o/r", Params: map[string]any{"branch": "b"}},
		"packages float":  {Kind: "branch.push", Resource: "o/r", Params: map[string]any{"branch": "b", "packages": 1.5}},
		"inputs not text": {Kind: "workflow.dispatch", Resource: "o/r", Params: map[string]any{"workflow": "w", "ref": "main", "inputs": map[string]any{"plan": 1}}},
		"bad sha":         {Kind: "workflow.dispatch", Resource: "o/r", Params: map[string]any{"workflow": "w", "ref": "main", "plan_sha256": "zz"}},
		"no schema":       {Kind: "pull.merge", Resource: "o/r"},
	}
	for name, a := range cases {
		if err := Validate(a); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
	// preview.push may say onto which base the previewed commit was merged, a full id or nothing.
	withBase := Action{Kind: PreviewPushKind, Resource: "o/r", Params: map[string]any{"branch": "preview", "sha": strings.Repeat("b", 40), "pull": float64(7), "base": strings.Repeat("c", 40)}}
	if err := Validate(withBase); err != nil {
		t.Fatal(err)
	}
	withBase.Params["base"] = "main"
	if err := Validate(withBase); err == nil {
		t.Error("a base that is not a full commit id must be refused")
	}
	p := Policy{Grant: Grant{Kinds: []string{"pull.open"}, Resources: []string{"o/r"}, MaxPerKind: 1}, PathAware: true}
	if v, r := p.Evaluate(cases["unknown key"], PathSummary{PerKind: map[string]int{}}); v != "DENY" || !strings.Contains(r, "out of schema") {
		t.Fatalf("%s %s", v, r)
	}
	if m := Matched(ok, PathSummary{PerKind: map[string]int{}}, Grant{MaxPerKind: 1}); m != "workflow.dispatch on o/r, 1 of 1 this run" {
		t.Fatal(m)
	}
}

// issue.open (19 September 2026): the mirror of a finding. A title is required, labels are a
// short list of words, and anything else is refused like every other kind.
func TestIssueOpenSchema(t *testing.T) {
	ok := Action{Kind: "issue.open", Resource: "owner/repo", Params: map[string]any{
		"title":   "Conceptfiche schrijft 48.500 km terug als 48,5",
		"body":    "docs/bedrijfsregels/bevindingen/2026-09-16-conceptfiche-herladen-schrijft-48500-als-48-5.md",
		"labels":  []any{"bevinding", "deze week"},
		"finding": "2026-09-16-conceptfiche-herladen-schrijft-48500-als-48-5",
	}}
	if err := Validate(ok); err != nil {
		t.Fatalf("a complete issue is refused: %v", err)
	}

	if err := Validate(Action{Kind: "issue.open", Resource: "owner/repo", Params: map[string]any{"body": "x"}}); err == nil {
		t.Fatal("an issue without a title is accepted")
	}

	bad := Action{Kind: "issue.open", Resource: "owner/repo", Params: map[string]any{"title": "t", "labels": []any{"a", 2}}}
	if err := Validate(bad); err == nil {
		t.Fatal("a label that is not a word is accepted")
	}

	many := make([]any, 11)
	for i := range many {
		many[i] = "label"
	}
	if err := Validate(Action{Kind: "issue.open", Resource: "owner/repo", Params: map[string]any{"title": "t", "labels": many}}); err == nil {
		t.Fatal("eleven labels are accepted")
	}
}
