package canonical

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The standard's two canonical vectors, byte for byte: escaping, Unicode,
// empty containers, and the UTF-16 key order that UTF-8 order gets wrong.
func TestTheStandardsCanonicalVectors(t *testing.T) {
	raw, err := os.ReadFile("../testdata/poc-vectors/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Canonical []struct {
			File        string `json:"file"`
			SHA         string `json:"canonical_sha256"`
			Description string `json:"description"`
		} `json:"canonical"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, v := range manifest.Canonical {
		data, err := os.ReadFile("../testdata/poc-vectors/" + v.File)
		if err != nil {
			t.Fatal(err)
		}
		dec := json.NewDecoder(strings.NewReader(string(data)))
		dec.UseNumber()
		var value any
		if err := dec.Decode(&value); err != nil {
			t.Fatal(err)
		}
		got, err := Digest(value)
		if err != nil {
			t.Fatalf("%s: %v", v.Description, err)
		}
		if got != v.SHA {
			t.Errorf("%s: got %s, want %s", v.Description, got, v.SHA)
		}
	}
}

func TestFloatsAndUntaggedDigestsAreRefused(t *testing.T) {
	if _, err := Encode(map[string]any{"iat": 1.5}); err == nil {
		t.Error("a float was accepted")
	}
	if _, err := Encode(map[string]any{"iat": json.Number("1.0")}); err == nil {
		t.Error("1.0 was accepted")
	}
	if _, err := Encode(map[string]any{"iat": 1754400000.0}); err != nil {
		t.Errorf("a whole float64 should pass as an integer: %v", err)
	}
	for _, bad := range []string{strings.Repeat("a", 64), "sha-256:" + strings.Repeat("A", 64), "sha-512:" + strings.Repeat("a", 64), "sha-256:"} {
		if _, err := Untag(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	if v, err := Untag("sha-256:" + strings.Repeat("a", 64)); err != nil || v != strings.Repeat("a", 64) {
		t.Errorf("a good digest was refused: %v", err)
	}
}
