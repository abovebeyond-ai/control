package capability

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func signSet(t *testing.T, claims map[string]any, key ed25519.PrivateKey) string {
	t.Helper()
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, raw))
}

// A passkey word is held to the set the owner signed on the token: signed by a token key the
// grant names, for these hands, outlasting the word, at most a week, naming the project, and
// reaching every kind's layer. Each way of falling outside is refused by name.
func TestAWordIsHeldToTheWorkingSetItCarries(t *testing.T) {
	op := ed25519.NewKeyFromSeed([]byte("operator-one-operator-one-seed32"))
	portal := ed25519.NewKeyFromSeed([]byte("principal-seed-principal-seed-32"))
	keys := map[string]string{"did:example:ab#operator": hex.EncodeToString(op.Public().(ed25519.PublicKey))}
	now := time.Unix(1_800_000_000, 0)
	set := func(edit func(map[string]any)) map[string]any {
		c := map[string]any{"type": "working-set", "iss": "did:example:ab#operator", "sub": "did:example:ab", "projects": []string{"demo"},
			"layer": "B2", "iat": now.Unix(), "exp": now.Add(5 * 24 * time.Hour).Unix(), "jti": "ws-1"}
		if edit != nil {
			edit(c)
		}
		return c
	}
	word := func(token string, edit func(*Payload)) Payload {
		p := Payload{Issuer: "did:example:ab#portal", Task: Task{Playbook: "workbench", Project: "demo", WorkingSet: &TaskWorkingSet{ID: "ws-1", Token: token}},
			Kinds: []string{"branch.push", "pull.open", "portal.update"}, IssuedAt: now.Unix(), Expires: now.Add(2 * time.Hour).Unix()}
		if edit != nil {
			edit(&p)
		}
		return p
	}

	ws, err := InsideWorkingSet(word(signSet(t, set(nil), op), nil), keys, "did:example:ab", now)
	if err != nil || ws.ID != "ws-1" || ws.Issuer != "did:example:ab#operator" {
		t.Fatalf("inside: %v %+v", err, ws)
	}

	for name, c := range map[string]struct {
		p    Payload
		want string
	}{
		"no set":                {word("", nil), "must carry the working set"},
		"not a token":           {word("garbage", nil), "not a signed token"},
		"signed by Portal":      {word(signSet(t, set(nil), portal), nil), "does not hold"},
		"an unnamed key":        {word(signSet(t, set(func(c map[string]any) { c["iss"] = "did:example:ab#stranger" }), op), nil), "not a token key the grant names"},
		"another type":          {word(signSet(t, set(func(c map[string]any) { c["type"] = "policy-version" }), op), nil), "not a working set for these hands"},
		"other hands":           {word(signSet(t, set(func(c map[string]any) { c["sub"] = "did:example:zz" }), op), nil), "not a working set for these hands"},
		"outlasts the set":      {word(signSet(t, set(func(c map[string]any) { c["exp"] = now.Add(time.Hour).Unix() }), op), nil), "outlasts the working set"},
		"longer than seven":     {word(signSet(t, set(func(c map[string]any) { c["exp"] = now.Add(8 * 24 * time.Hour).Unix() }), op), nil), "a week at most"},
		"another project":       {word(signSet(t, set(nil), op), func(p *Payload) { p.Task.Project = "elsewhere" }), "elsewhere is not in the working set"},
		"a B1 set":              {word(signSet(t, set(func(c map[string]any) { c["layer"] = "B1" }), op), nil), "above the working set's layer B1"},
		"a B3 set":              {word(signSet(t, set(func(c map[string]any) { c["layer"] = "B3" }), op), nil), "B1 or B2"},
		"a kind with no radius": {word(signSet(t, set(nil), op), func(p *Payload) { p.Kinds = append(p.Kinds, "review.invite") }), "review.invite is above"},
	} {
		if _, err := InsideWorkingSet(c.p, keys, "did:example:ab", now); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: %v, want %q", name, err, c.want)
		}
	}
}
