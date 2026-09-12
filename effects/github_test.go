package effects

import (
	"os"
	"path/filepath"
	"testing"
)

// A repository owner is not case-sensitive on GitHub, and the secrets on the VM are
// fetched under lower-case names; a grant that spells the owner as the repository does
// must still find the token.
func TestTheTokenIsFoundWhateverCaseTheOwnerIsSpelledIn(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "github-token-shanedeconinck"), []byte("tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	g := GitHub{SecretsDir: dir}
	for _, owner := range []string{"shanedeconinck", "ShaneDeconinck", "SHANEDECONINCK"} {
		tok, err := g.token(owner)
		if err != nil || tok != "tok" {
			t.Fatalf("owner %q: token %q, err %v", owner, tok, err)
		}
	}
	if _, err := g.token("nobody"); err == nil {
		t.Fatal("an owner without a token must be refused")
	}
}
