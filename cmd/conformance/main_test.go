package main

import (
	"os"
	"path/filepath"
	"testing"
)

const root = "../.."

func loadAll(t *testing.T) (Facts, []Standard) {
	t.Helper()
	var fs Facts
	if err := load(filepath.Join(root, "conformance/facts.json"), &fs); err != nil {
		t.Fatal(err)
	}
	paths, _ := filepath.Glob(filepath.Join(root, "conformance/standards/*.json"))
	if len(paths) == 0 {
		t.Fatal("no standards")
	}
	var ss []Standard
	for _, p := range paths {
		var s Standard
		if err := load(p, &s); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		ss = append(ss, s)
	}
	return fs, ss
}

// Every path a fact names as its evidence is in the repository, so a fact
// cannot outlive the code it points at.
func TestEvidenceExists(t *testing.T) {
	fs, _ := loadAll(t)
	for _, f := range fs.Facts {
		if len(f.Evidence) == 0 {
			t.Errorf("%s names no evidence", f.ID)
		}
		for _, p := range f.Evidence {
			if _, err := os.Stat(filepath.Join(root, p)); err != nil {
				t.Errorf("%s: evidence %s is gone", f.ID, p)
			}
		}
	}
}

// Every standard grades every kind of party the facts trust, and places only
// facts that exist.
func TestStandardsCoverFacts(t *testing.T) {
	fs, ss := loadAll(t)
	ids := map[string]bool{}
	for _, f := range fs.Facts {
		ids[f.ID] = true
	}
	for _, s := range ss {
		for id := range s.Map {
			if !ids[id] {
				t.Errorf("%s places %s, which is not a fact", s.ID, id)
			}
		}
		for _, f := range fs.Facts {
			if _, err := grade(f, fs, s, true); err != nil {
				t.Errorf("%s: %v", s.ID, err)
			}
		}
	}
}

// Graded against v0.1, the facts give back the tiers the register declared:
// the model reproduces the statement before it is used to move it.
func TestReproducesRegister(t *testing.T) {
	fs, ss := loadAll(t)
	var v01 Standard
	for _, s := range ss {
		if s.ID == "aais-poc-0.1" {
			v01 = s
		}
	}
	var reg struct {
		Claims []struct {
			ID   string `json:"id"`
			Tier int    `json:"tier"`
		} `json:"claims"`
	}
	if err := load(filepath.Join(root, "conformance/register.json"), &reg); err != nil {
		t.Fatal(err)
	}
	byID := map[string]Fact{}
	for _, f := range fs.Facts {
		byID[f.ID] = f
	}
	for _, c := range reg.Claims {
		f, ok := byID[c.ID]
		if !ok {
			t.Errorf("register claim %s has no fact", c.ID)
			continue
		}
		g, err := grade(f, fs, v01, false)
		if err != nil {
			t.Fatal(err)
		}
		if g.Tier != c.Tier {
			t.Errorf("%s: register says Tier %d, the model gives %d (%v)", c.ID, c.Tier, g.Tier, g.Limits)
		}
	}
}
