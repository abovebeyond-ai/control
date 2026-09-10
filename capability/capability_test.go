package capability

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/abovebeyond-ai/control/canonical"
)

func TestACapabilityIsHeldToKeyAudienceSubjectAndTime(t *testing.T) {
	principal := ed25519.NewKeyFromSeed([]byte("principal-seed-principal-seed-32"))
	other := ed25519.NewKeyFromSeed([]byte("other-seed-other-seed-other-see!"))
	now := time.Unix(1_800_000_000, 0)
	p := Payload{Issuer: "did:example:ab#portal", Subject: "did:example:ab#agent-fix", Audience: "https://gw.example/control",
		Task: Task{Playbook: "elixir-fix", Project: "demo"}, Kinds: []string{"workflow.dispatch", "pull.open"}, Resources: []string{"o/r"},
		IssuedAt: now.Unix(), Expires: now.Add(time.Hour).Unix(), ID: "01J"}
	tok, err := Issue(p, principal)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(tok, principal.Public().(ed25519.PublicKey), p.Audience, p.Subject, now)
	if err != nil || got.Task.Project != "demo" || !got.Covers("pull.open", "o/r") || got.Covers("pull.merge", "o/r") || got.Covers("pull.open", "o/x") {
		t.Fatalf("%v %+v", err, got)
	}
	cases := map[string]func() (string, ed25519.PublicKey, string, string, time.Time){
		"wrong key": func() (string, ed25519.PublicKey, string, string, time.Time) {
			return tok, other.Public().(ed25519.PublicKey), p.Audience, p.Subject, now
		},
		"wrong aud": func() (string, ed25519.PublicKey, string, string, time.Time) {
			return tok, principal.Public().(ed25519.PublicKey), "https://elsewhere", p.Subject, now
		},
		"wrong sub": func() (string, ed25519.PublicKey, string, string, time.Time) {
			return tok, principal.Public().(ed25519.PublicKey), p.Audience, "did:example:ab#agent-other", now
		},
		"expired": func() (string, ed25519.PublicKey, string, string, time.Time) {
			return tok, principal.Public().(ed25519.PublicKey), p.Audience, p.Subject, now.Add(2 * time.Hour)
		},
		"tampered": func() (string, ed25519.PublicKey, string, string, time.Time) {
			// The payload changed, the signature did not: a widened payload under the original signature.
			wider := p
			wider.Resources = []string{"o/r", "o/x"}
			body, _ := canonical.Encode(wider)
			return base64.RawURLEncoding.EncodeToString(body) + tok[strings.Index(tok, "."):], principal.Public().(ed25519.PublicKey), p.Audience, p.Subject, now
		},
		"not a token": func() (string, ed25519.PublicKey, string, string, time.Time) {
			return "nope", principal.Public().(ed25519.PublicKey), p.Audience, p.Subject, now
		},
	}
	for name, c := range cases {
		tk, pub, aud, sub, at := c()
		if _, err := Verify(tk, pub, aud, sub, at); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
	if Digest(tok) == Digest(tok+"x") || !strings.HasPrefix(Digest(tok), "sha-256:") {
		t.Fatal("digest")
	}
}
