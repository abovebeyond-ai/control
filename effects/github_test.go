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

// A deletion is a tree entry with a null sha and no blob; its digest names it, so a
// hand cannot pass a deletion off as a write of nothing.
func TestADeletionCarriesNoContentAndDigestsAsADeletion(t *testing.T) {
	if _, err := DecodeFiles([]map[string]any{{"path": "a.md", "content": "aGk=", "delete": true}}); err == nil {
		t.Fatal("a deletion with content must be refused")
	}
	files, err := DecodeFiles([]map[string]any{{"path": "a.md", "delete": true}})
	if err != nil || len(files) != 1 || !files[0].Delete {
		t.Fatalf("a deletion without content must decode: %v %+v", err, files)
	}
	del, _ := FilesDigest([]FileChange{{Path: "a.md", Delete: true}})
	empty, _ := FilesDigest([]FileChange{{Path: "a.md"}})
	if del == empty {
		t.Fatal("deleting a.md and writing an empty a.md must not digest alike")
	}
}
