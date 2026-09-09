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
	p := Policy{Grant: Grant{Kinds: []string{"pull.open"}, Resources: []string{"o/r"}, MaxPerKind: 1}, PathAware: true}
	if v, r := p.Evaluate(cases["unknown key"], PathSummary{PerKind: map[string]int{}}); v != "DENY" || !strings.Contains(r, "out of schema") {
		t.Fatalf("%s %s", v, r)
	}
	if m := Matched(ok, PathSummary{PerKind: map[string]int{}}, Grant{MaxPerKind: 1}); m != "workflow.dispatch on o/r, 1 of 1 this run" {
		t.Fatal(m)
	}
}
