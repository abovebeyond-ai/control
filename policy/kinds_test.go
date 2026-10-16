package policy

import (
	"strings"
	"testing"
)

// note is a kind on a running system as a policy defines it: no code in the gateway, the
// system adapter carries it, and the system verifies what it receives.
func note() Kind {
	return Kind{Adapter: SystemAdapter, On: []string{"glk:transferor"}, Radius: "B2", Why: "one note on a worksheet, deleted there in one step", Place: "Writes to a live system", Words: "add a note to a worksheet",
		Schema: Schema{Required: map[string]string{"worksheet": "int", "text": "string"}, Optional: map[string]string{}}}
}

// A kind on a running system is defined in a version the owner signs: the gateway then judges
// it by the schema the version gives, with no release, and a hand may hold it.
func TestAKindOnARunningSystemIsDefinedInThePolicy(t *testing.T) {
	k := newLogKeys(t)
	head := bootHead()
	head.Systems["glk:transferor"] = "https://glk.example"
	agents := changed(head, func(g *Grant) {
		g.Kinds = append(g.Kinds, "glk.worksheet_note")
		g.Resources = append(g.Resources, "glk:transferor")
	})
	v := version(head, owner, agents, head.Systems)
	v.Kinds = Kinds{"glk.worksheet_note": note()}
	for name, s := range map[string]SignedVersion{"payload": sign(t, k.owner, v), "digest": signDigest(t, k.owner, v)} {
		next, err := Next(head, s, k.signers, now)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if next.Kinds["glk.worksheet_note"].Words != "add a note to a worksheet" {
			t.Fatalf("%s: the head does not carry the definition: %+v", name, next.Kinds)
		}
		p := Policy{Grant: next.Agents[shed].Grant, Defined: next.Kinds}
		ok := Action{Kind: "glk.worksheet_note", Resource: "glk:transferor", Params: map[string]any{"worksheet": float64(7), "text": "Kabel ligt klaar"}}
		if verdict, reason := p.Evaluate(ok, PathSummary{PerKind: map[string]int{}}); verdict != "ALLOW" {
			t.Fatalf("%s: a defined kind within its schema: %s %s", name, verdict, reason)
		}
		bad := Action{Kind: "glk.worksheet_note", Resource: "glk:transferor", Params: map[string]any{"worksheet": float64(7), "text": "x", "all": true}}
		if verdict, reason := p.Evaluate(bad, PathSummary{PerKind: map[string]int{}}); verdict != "DENY" || !strings.Contains(reason, "out of schema") {
			t.Fatalf("%s: a defined kind outside its schema: %s %s", name, verdict, reason)
		}
		elsewhere := Action{Kind: "glk.worksheet_note", Resource: "stocklist:platform", Params: ok.Params}
		p.Grant.Resources = append(p.Grant.Resources, "stocklist:platform")
		if verdict, reason := p.Evaluate(elsewhere, PathSummary{PerKind: map[string]int{}}); verdict != "DENY" || !strings.Contains(reason, "acts on glk:transferor, not on stocklist:platform") {
			t.Fatalf("%s: a system kind on another system: %s %s", name, verdict, reason)
		}
		if _, there := p.Bundle()["schemas"].(map[string]any)["glk.worksheet_note"]; !there {
			t.Fatalf("%s: the bundle beside the record does not name the defined schema", name)
		}
	}
	// Without the definition, the same action is out of schema: a kind is judged only by a
	// table that has it.
	p := Policy{Grant: agents[shed].Grant}
	if verdict, _ := p.Evaluate(Action{Kind: "glk.worksheet_note", Resource: "glk:transferor", Params: map[string]any{"worksheet": float64(7), "text": "x"}}, PathSummary{PerKind: map[string]int{}}); verdict != "DENY" {
		t.Fatal("an undefined kind must be refused")
	}
}

// A policy defines kinds on a running system only, and says what the owner signs: a radius with
// what bounds it, the words, a schema of known types.
func TestADefinitionSaysWhatTheOwnerSigns(t *testing.T) {
	for name, c := range map[string]struct {
		edit func(*Kind)
		as   string
		want string
	}{
		"a built-in name":     {nil, "pull.open", "performed by this release"},
		"code of its own":     {func(k *Kind) { k.Adapter = "github" }, "", "running system only"},
		"files":               {func(k *Kind) { k.Files = "text" }, "", "carries none"},
		"B3":                  {func(k *Kind) { k.Radius = "B3" }, "", "not B1 or B2"},
		"a radius unbounded":  {func(k *Kind) { k.Why = "" }, "", "what bounds its radius"},
		"a bound, no radius":  {func(k *Kind) { k.Radius = "" }, "", "does not have"},
		"no words":            {func(k *Kind) { k.Words = "" }, "", "no words"},
		"no system":           {func(k *Kind) { k.On = nil }, "", "names no running system"},
		"an unknown type":     {func(k *Kind) { k.Required["text"] = "html" }, "", "unknown type"},
		"no optional set":     {func(k *Kind) { k.Optional = nil }, "", "empty or not"},
		"required and option": {func(k *Kind) { k.Optional["text"] = "string" }, "", "both required and optional"},
	} {
		d := note()
		if c.edit != nil {
			c.edit(&d)
		}
		name2 := "glk.worksheet_note"
		if c.as != "" {
			name2 = c.as
		}
		if err := CheckDefined(Kinds{name2: d}); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	if err := CheckDefined(Kinds{"glk.worksheet_note": note()}); err != nil {
		t.Fatal(err)
	}
	if err := CheckDefined(Kinds{"glk.worksheet_read": {Adapter: SystemAdapter, On: []string{"glk:transferor"}, Place: "Reads a live system", Words: "count the notes", Schema: Schema{Required: map[string]string{}, Optional: map[string]string{}}}}); err != nil {
		t.Fatalf("a kind with no radius is the owner's to grant, and may be defined: %v", err)
	}
}

// Defining a kind or changing one is the owner's: Elixir may only drop a definition, and
// Portal's key, after a passkey, leaves the table as it is but may grant a defined kind by
// the radius the owner gave it.
func TestOnlyTheOwnerDefinesOrChangesAKind(t *testing.T) {
	k := newLogKeys(t)
	repairKey, repairSigners := repairKeys(t)
	repairSigners.Narrow = k.signers.Narrow
	repairSigners.Widen = k.signers.Widen
	head := bootHead()
	head.Systems["glk:transferor"] = "https://glk.example"
	held := note()
	held.Words = "add a note"
	head.Kinds = Kinds{"glk.worksheet_note": note(), "glk.worksheet_read": {Adapter: SystemAdapter, On: []string{"glk:transferor"}, Place: "Reads a live system", Words: "count the notes", Schema: Schema{Required: map[string]string{}, Optional: map[string]string{}}}}
	changedNote := note()
	changedNote.Optional = map[string]string{"pin": "bool"}
	lower := note()
	lower.Radius, lower.Why = "B1", "nothing"

	for name, c := range map[string]struct {
		key   string
		kinds Kinds
		grant func(*Grant)
		want  string
	}{
		"Elixir defines one":       {elixir, Kinds{"glk.worksheet_note": note(), "glk.worksheet_read": head.Kinds["glk.worksheet_read"], "glk.other": note()}, nil, "defines the kind glk.other"},
		"Elixir widens a schema":   {elixir, Kinds{"glk.worksheet_note": changedNote, "glk.worksheet_read": head.Kinds["glk.worksheet_read"]}, nil, "changes the definition of the kind glk.worksheet_note"},
		"Elixir rewords one":       {elixir, Kinds{"glk.worksheet_note": held, "glk.worksheet_read": head.Kinds["glk.worksheet_read"]}, nil, "changes the definition"},
		"Portal lowers a radius":   {portal, Kinds{"glk.worksheet_note": lower, "glk.worksheet_read": head.Kinds["glk.worksheet_read"]}, nil, "which are the owner's"},
		"Portal drops one":         {portal, Kinds{"glk.worksheet_note": note()}, nil, "which are the owner's"},
		"Portal grants no-radius":  {portal, head.Kinds, func(g *Grant) { g.Kinds = append(g.Kinds, "glk.worksheet_read") }, "adds the kind glk.worksheet_read"},
		"Elixir drops one":         {elixir, Kinds{"glk.worksheet_note": note()}, nil, ""},
		"Portal grants a B2 kind":  {portal, head.Kinds, func(g *Grant) { g.Kinds = append(g.Kinds, "glk.worksheet_note") }, ""},
		"the owner changes schema": {owner, Kinds{"glk.worksheet_note": changedNote}, nil, ""},
	} {
		agents := head.Agents
		if c.grant != nil {
			agents = changed(head, c.grant)
		}
		v := version(head, c.key, agents, head.Systems)
		v.Kinds = c.kinds
		var s SignedVersion
		switch c.key {
		case owner:
			s = sign(t, k.owner, v)
		case elixir:
			s = sign(t, k.elixir, v)
		default:
			s = sign(t, repairKey, v)
		}
		_, err := Next(head, s, repairSigners, now)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// The table is one place per kind: every built-in kind names its adapter, its words, and a
// radius only with what bounds it; a kind that binds files names a parameter of its schema.
func TestEveryBuiltinKindIsDescribedOnce(t *testing.T) {
	for k, d := range Builtin {
		if d.Adapter == "" || d.Place == "" || d.Words == "" || d.Required == nil || d.Optional == nil {
			t.Errorf("%s is not described whole: %+v", k, d)
		}
		if (d.Radius == "") != (d.Why == "") {
			t.Errorf("%s: a radius goes with what bounds it", k)
		}
		if (d.Adapter == SystemAdapter) != (len(d.On) > 0) {
			t.Errorf("%s: a system kind names its systems, and only a system kind", k)
		}
		if d.Files != "" {
			_, r := d.Required[d.Files]
			_, o := d.Optional[d.Files]
			if !r && !o {
				t.Errorf("%s binds files by %s, which its schema does not name", k, d.Files)
			}
		}
	}
}
