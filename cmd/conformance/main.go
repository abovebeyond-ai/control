// conformance maps what this system does onto a version of a standard and
// grades it there. The facts (conformance/facts.json) say what the system does
// and whom each fact asks you to trust; they change when the system changes.
// A standard file (conformance/standards/*.json) says where each fact lands and
// how far each kind of trusted party lets a fact rise; it changes when the
// standard does. The tier is computed from the two, never written by hand, so
// a new draft that tightens a rule moves every fact it touches.
//
//	conformance [--standard FILE] [--against FILE] [--assume-proposed]
//
// With --against the table shows both versions side by side and marks what
// moved. --assume-proposed grades as if the standard's proposed rules (an
// explicit threshold of independent parties) were adopted.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

type Party struct {
	Kind string `json:"kind"`
	What string `json:"what"`
}

type Fact struct {
	ID          string     `json:"id"`
	Says        string     `json:"says"`
	How         string     `json:"how"`
	Evidence    []string   `json:"evidence"`
	Check       string     `json:"check,omitempty"`
	Trust       []string   `json:"trust"`
	Independent [][]string `json:"independent,omitempty"`
	Enforces    bool       `json:"enforces,omitempty"`
	Status      string     `json:"status"`
	Since       string     `json:"since,omitempty"`
	Open        string     `json:"open,omitempty"`
}

type Facts struct {
	Parties map[string]Party `json:"parties"`
	Facts   []Fact           `json:"facts"`
}

type Cap struct {
	Tier   int    `json:"tier"`
	Unsure bool   `json:"unsure,omitempty"`
	Why    string `json:"why,omitempty"`
}

type Placement struct {
	Domain string   `json:"domain"`
	Rows   []string `json:"rows,omitempty"`
	Note   string   `json:"note,omitempty"`
}

type Standard struct {
	ID           string         `json:"id"`
	Title        string         `json:"title"`
	PoCThreshold int            `json:"poc_threshold"`
	Caps         map[string]Cap `json:"caps"`
	Independent  struct {
		Status string `json:"status"`
		Tier   int    `json:"tier"`
		Ref    string `json:"ref"`
	} `json:"independent_parties"`
	Map map[string]Placement `json:"map"`
}

// Grade is one fact's standing under one standard.
type Grade struct {
	Tier   int
	Unsure bool
	Limits []string // the parties that hold the tier where it is, and why
	Placed *Placement
}

const maxComputed = 3 // Tier 4 is a property of the whole chain, not of one fact's trust list

func load(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// grade holds a fact to a standard: the lowest cap among the parties it trusts,
// where a set of independent parties counts as one when the standard allows it.
func grade(f Fact, fs Facts, s Standard, assumeProposed bool) (Grade, error) {
	g := Grade{Tier: maxComputed}
	if p, ok := s.Map[f.ID]; ok {
		g.Placed = &p
	}
	// A tier is unsure only when every party holding it there is graded on a
	// reading; one party the text settles is enough to make it certain.
	lower := func(tier int, unsure bool, who string) {
		if tier < g.Tier {
			g.Tier, g.Unsure, g.Limits = tier, unsure, []string{who}
		} else if tier == g.Tier && tier < maxComputed {
			g.Unsure = g.Unsure && unsure
			g.Limits = append(g.Limits, who)
		}
	}
	capOf := func(id string) (Cap, error) {
		p, ok := fs.Parties[id]
		if !ok {
			return Cap{}, fmt.Errorf("fact %s trusts %q, which is not among the parties", f.ID, id)
		}
		c, ok := s.Caps[p.Kind]
		if !ok {
			return Cap{}, fmt.Errorf("%s says nothing about parties of kind %q (%s)", s.ID, p.Kind, id)
		}
		return c, nil
	}
	for _, id := range f.Trust {
		c, err := capOf(id)
		if err != nil {
			return g, err
		}
		lower(c.Tier, c.Unsure, id)
	}
	thresholds := s.Independent.Status == "adopted" || (assumeProposed && s.Independent.Status == "proposed")
	for _, set := range f.Independent {
		if thresholds && len(set) >= 2 {
			lower(s.Independent.Tier, s.Independent.Status != "adopted", strings.Join(set, "+"))
			continue
		}
		for _, id := range set {
			c, err := capOf(id)
			if err != nil {
				return g, err
			}
			lower(c.Tier, c.Unsure, id)
		}
	}
	return g, nil
}

func tierText(g Grade) string {
	t := fmt.Sprint(g.Tier)
	if g.Unsure {
		t += "?"
	}
	return t
}

func render(w io.Writer, fs Facts, s Standard, against *Standard, assumeProposed bool) error {
	fmt.Fprintf(w, "# %s\n\n", s.Title)
	if against != nil {
		fmt.Fprintf(w, "Compared with %s. A ? marks a tier that rests on a reading of the text the standard does not settle.\n\n", against.Title)
		fmt.Fprintln(w, "| fact | status | domain | tier before | tier now | Proof-of-Control now | held below 3 by |")
		fmt.Fprintln(w, "| --- | --- | --- | --- | --- | --- | --- |")
	} else {
		fmt.Fprint(w, "A ? marks a tier that rests on a reading of the text the standard does not settle.\n\n")
		fmt.Fprintln(w, "| fact | status | domain | tier | Proof-of-Control | held below 3 by |")
		fmt.Fprintln(w, "| --- | --- | --- | --- | --- | --- |")
	}
	moved := 0
	for _, f := range fs.Facts {
		g, err := grade(f, fs, s, assumeProposed)
		if err != nil {
			return err
		}
		domain := "not placed"
		if g.Placed != nil {
			domain = g.Placed.Domain
			if len(g.Placed.Rows) > 0 {
				domain += " (" + strings.Join(g.Placed.Rows, ", ") + ")"
			}
		}
		poc := "no"
		if g.Tier >= s.PoCThreshold {
			poc = "yes"
			if f.Enforces {
				poc += ", Tier 4 candidate"
			}
		}
		held := strings.Join(g.Limits, "; ")
		if held == "" {
			held = "none"
		}
		if against == nil {
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s |\n", f.ID, f.Status, domain, tierText(g), poc, held)
			continue
		}
		b, err := grade(f, fs, *against, assumeProposed)
		if err != nil {
			return err
		}
		before := tierText(b)
		if b.Placed == nil {
			before = "not placed"
		}
		now := tierText(g)
		if b.Placed != nil && b.Tier != g.Tier {
			now = "**" + now + "**"
			moved++
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s |\n", f.ID, f.Status, domain, before, now, poc, held)
	}
	if against != nil {
		fmt.Fprintf(w, "\n%d of %d facts change tier.\n", moved, len(fs.Facts))
	}
	fmt.Fprintf(w, "\n## Why each party holds a fact where it does, under %s\n\n", s.ID)
	for _, id := range sortedKeys(fs.Parties) {
		p := fs.Parties[id]
		c := s.Caps[p.Kind]
		if c.Tier >= maxComputed {
			continue
		}
		why := c.Why
		if c.Unsure {
			why += " (a reading)"
		}
		fmt.Fprintf(w, "- %s, Tier %d: %s\n", id, c.Tier, why)
	}
	if s.Independent.Status == "proposed" && !assumeProposed {
		fmt.Fprintf(w, "\nProposed, not adopted: %s. Run with --assume-proposed to see its effect.\n", s.Independent.Ref)
	}
	return nil
}

func main() {
	factsPath := flag.String("facts", "conformance/facts.json", "the facts of the system")
	stdPath := flag.String("standard", "conformance/standards/aais-poc-1.0-draft.json", "the standard to grade against")
	againstPath := flag.String("against", "", "a second standard to compare with")
	assume := flag.Bool("assume-proposed", false, "grade as if the standard's proposed rules were adopted")
	flag.Parse()

	var fs Facts
	var s Standard
	if err := load(*factsPath, &fs); err != nil {
		fail(err)
	}
	if err := load(*stdPath, &s); err != nil {
		fail(err)
	}
	var against *Standard
	if *againstPath != "" {
		against = new(Standard)
		if err := load(*againstPath, against); err != nil {
			fail(err)
		}
	}
	if err := render(os.Stdout, fs, s, against, *assume); err != nil {
		fail(err)
	}
}

func sortedKeys(m map[string]Party) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "conformance:", err)
	os.Exit(1)
}
