package evidence

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The standard's published tokens: our signing input over their claims
// reproduces their signature under the published seed, so a token we sign is
// one the standard's validator reads the same way; and its negative vector
// for an altered claim does not verify.
func TestThePublishedTokensReSignIdentically(t *testing.T) {
	raw, err := os.ReadFile("../testdata/poc-vectors/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Seed     string `json:"private_key_seed"`
		Public   string `json:"public_key"`
		Positive []struct {
			File        string `json:"file"`
			Description string `json:"description"`
		} `json:"positive"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(manifest.Seed)
	key := ed25519.NewKeyFromSeed(seed)
	if hex.EncodeToString(key.Public().(ed25519.PublicKey)) != manifest.Public {
		t.Fatal("the seed does not give the published key")
	}
	for _, v := range manifest.Positive {
		tok := load(t, "../testdata/poc-vectors/"+v.File)
		if !Verify(tok, key.Public().(ed25519.PublicKey)) {
			t.Errorf("%s: does not verify", v.Description)
		}
		want := tok["signature"]
		if err := Sign(tok, key); err != nil {
			t.Fatal(err)
		}
		if tok["signature"] != want {
			t.Errorf("%s: re-signing gives a different signature", v.Description)
		}
	}
	bad := load(t, "../testdata/poc-vectors/negative/bad-signature.json")
	if Verify(bad, key.Public().(ed25519.PublicKey)) {
		t.Error("an altered claim verified")
	}
}

func load(t *testing.T, path string) Token {
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var tok Token
	if err := dec.Decode(&tok); err != nil {
		t.Fatal(err)
	}
	return tok
}
