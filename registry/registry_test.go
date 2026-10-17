package registry

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

var now = time.Unix(1_792_300_000, 0)

func okp(pub ed25519.PublicKey) JWK {
	return JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub)}
}

func ec(t *testing.T) (*ecdsa.PrivateKey, JWK) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := k.PublicKey.Bytes()
	return k, JWK{Kty: "EC", Crv: "P-256", X: base64.RawURLEncoding.EncodeToString(raw[1:33]), Y: base64.RawURLEncoding.EncodeToString(raw[33:])}
}

func issue(t *testing.T, e Entry, key ed25519.PrivateKey) string {
	tok, err := Issue(e, key)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// Acme's root signs Tom, Tom signs Elise's passkey: the chain holds, and Elise is the last.
// Every step that gives more than its parent, or is signed by the wrong key, is refused.
func TestAChainHoldsFromThePinnedRootAndOnlyNarrows(t *testing.T) {
	root := ed25519.NewKeyFromSeed([]byte("acme-root-seed-acme-root-seed-32"))
	tom := ed25519.NewKeyFromSeed([]byte("tom-seed-tom-seed-tom-seed-tom-3"))
	_, elisePub := ec(t)
	roots := map[string]ed25519.PublicKey{"acme": root.Public().(ed25519.PublicKey)}
	kinds := []string{"odoo.read", "odoo.order_draft", "odoo.order_line_set", "odoo.order_cancel", "odoo.order_request_approval"}
	tomEntry := Entry{ID: "acme#tom", Org: "acme", Parent: "acme", Holder: okp(tom.Public().(ed25519.PublicKey)), Role: "director", Kinds: kinds, CeilingEUR: 50000, MayDelegate: true, IssuedAt: now.Unix() - 100, Expires: now.Unix() + 86400*30}
	eliseEntry := Entry{ID: "acme#elise", Org: "acme", Parent: "acme#tom", Holder: elisePub, CredentialID: "Y3JlZA", Role: "buyer", Kinds: kinds, CeilingEUR: 5000, IssuedAt: now.Unix() - 50, Expires: now.Unix() + 86400*7}
	chain := []string{issue(t, tomEntry, root), issue(t, eliseEntry, tom)}
	entries, err := VerifyChain(chain, roots, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[1].ID != "acme#elise" || entries[1].CeilingEUR != 5000 || strings.Join(IDs(entries), ",") != "acme#tom,acme#elise" {
		t.Fatalf("%+v", entries)
	}
	if _, err := entries[1].Holder.ECDSA(); err != nil {
		t.Fatal(err)
	}
	if Digest(chain) == Digest(chain[:1]) || !strings.HasPrefix(Digest(chain), "sha-256:") {
		t.Fatal("digest")
	}

	other := ed25519.NewKeyFromSeed([]byte("other-seed-other-seed-other-see!"))
	cases := map[string]func() []string{
		"a wider kind": func() []string {
			e := eliseEntry
			e.Kinds = append(append([]string{}, kinds...), "odoo.order_approve")
			return []string{chain[0], issue(t, e, tom)}
		},
		"a higher ceiling": func() []string {
			e := eliseEntry
			e.CeilingEUR = 60000
			return []string{chain[0], issue(t, e, tom)}
		},
		"a later end": func() []string {
			e := eliseEntry
			e.Expires = tomEntry.Expires + 1
			return []string{chain[0], issue(t, e, tom)}
		},
		"a parent that may not delegate": func() []string {
			d := tomEntry
			d.MayDelegate = false
			return []string{issue(t, d, root), chain[1]}
		},
		"signed by another key":      func() []string { return []string{chain[0], issue(t, eliseEntry, other)} },
		"the root signed by another": func() []string { return []string{issue(t, tomEntry, other), chain[1]} },
		"another organisation's root": func() []string {
			d := tomEntry
			d.Org, d.ID, d.Parent = "evil", "evil#tom", "evil"
			return []string{issue(t, d, root)}
		},
		"a parent out of order": func() []string { return []string{chain[1], chain[0]} },
		"the wrong parent named": func() []string {
			e := eliseEntry
			e.Parent = "acme#someone"
			return []string{chain[0], issue(t, e, tom)}
		},
		"expired": func() []string {
			e := eliseEntry
			e.Expires = now.Unix() - 1
			return []string{chain[0], issue(t, e, tom)}
		},
		"issued in the future": func() []string {
			e := eliseEntry
			e.IssuedAt = now.Unix() + 3600
			return []string{chain[0], issue(t, e, tom)}
		},
		"an id outside the organisation": func() []string {
			e := eliseEntry
			e.ID = "other#elise"
			return []string{chain[0], issue(t, e, tom)}
		},
		"a passkey holder signing a child": func() []string {
			// Elise's key is P-256; she cannot sign entries, whatever may_delegate says.
			e := eliseEntry
			e.MayDelegate = true
			child := Entry{ID: "acme#intern", Org: "acme", Parent: "acme#elise", Holder: okp(other.Public().(ed25519.PublicKey)), Kinds: []string{"odoo.read"}, IssuedAt: now.Unix(), Expires: now.Unix() + 60}
			return []string{chain[0], issue(t, e, tom), issue(t, child, other)}
		},
		"none":      func() []string { return nil },
		"twice":     func() []string { return []string{chain[0], chain[0]} },
		"not a re1": func() []string { return []string{"re2." + strings.SplitN(chain[0], ".", 2)[1]} },
	}
	for name, c := range cases {
		if _, err := VerifyChain(c(), roots, now); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
	// Nothing pinned, nothing holds.
	if _, err := VerifyChain(chain, map[string]ed25519.PublicKey{}, now); err == nil || !strings.Contains(err.Error(), "no root key") {
		t.Fatalf("an organisation without a pinned root: %v", err)
	}
}

// What is signed is what every reader reads: bytes that are not canonical JSON (here a key
// given twice, the second one widening) are refused before the signature is looked at.
func TestAnEntryInAnotherFormIsRefused(t *testing.T) {
	root := ed25519.NewKeyFromSeed([]byte("acme-root-seed-acme-root-seed-32"))
	body := `{"ceiling_eur":5000,"ceiling_eur":900000,"exp":1792400000,"holder":{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(root.Public().(ed25519.PublicKey)) + `"},"iat":1792200000,"id":"acme#tom","kinds":[],"may_delegate":true,"org":"acme","parent":"acme","role":"director"}`
	tok := Prefix + "." + base64.RawURLEncoding.EncodeToString([]byte(body)) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(root, []byte(body)))
	if _, _, _, err := Parse(tok); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("a duplicated key must be refused: %v", err)
	}
	// An unknown field is refused too: an entry says what the contract says and no more.
	extra := `{"exp":2,"holder":{"crv":"Ed25519","kty":"OKP","x":"AA"},"iat":1,"id":"acme#tom","kinds":[],"may_delegate":true,"org":"acme","parent":"acme","role":"director","spend":"anything"}`
	tok = Prefix + "." + base64.RawURLEncoding.EncodeToString([]byte(extra)) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(root, []byte(extra)))
	if _, _, _, err := Parse(tok); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("an unknown field must be refused: %v", err)
	}
	if _, err := (JWK{Kty: "EC", Crv: "P-256", X: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Y: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}).ECDSA(); err == nil {
		t.Fatal("a point off the curve must be refused")
	}
}
