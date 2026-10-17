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

// A daily allowance only narrows down a chain: a parent without one puts no bound, a parent
// with one gives none wider and no child goes without one under it.
func TestADailyAllowanceOnlyNarrows(t *testing.T) {
	root := ed25519.NewKeyFromSeed([]byte("acme-root-seed-acme-root-seed-32"))
	tom := ed25519.NewKeyFromSeed([]byte("tom-seed-tom-seed-tom-seed-tom-3"))
	_, pk := ec(t)
	roots := map[string]ed25519.PublicKey{"acme": root.Public().(ed25519.PublicKey)}
	kinds := []string{"odoo.order_draft"}
	director := Entry{ID: "acme#tom", Org: "acme", Parent: "acme", Holder: okp(tom.Public().(ed25519.PublicKey)), Role: "director", Kinds: kinds, CeilingEUR: 25000, MayDelegate: true, IssuedAt: now.Unix() - 100, Expires: now.Unix() + 86400*30}
	buyer := Entry{ID: "acme#shane", Org: "acme", Parent: "acme#tom", Holder: pk, Role: "buyer", Kinds: kinds, CeilingEUR: 5000, IssuedAt: now.Unix() - 50, Expires: now.Unix() + 86400*7}
	check := func(d, b int64) error {
		dd, bb := director, buyer
		dd.DailyEUR, bb.DailyEUR = d, b
		_, err := VerifyChain([]string{issue(t, dd, root), issue(t, bb, tom)}, roots, now)
		return err
	}
	for _, c := range []struct {
		director, buyer int64
		ok              bool
	}{{0, 0, true}, {0, 7500, true}, {20000, 7500, true}, {20000, 20000, true}, {20000, 25000, false}, {20000, 0, false}, {0, -1, false}} {
		if err := check(c.director, c.buyer); (err == nil) != c.ok {
			t.Errorf("director %d, buyer %d: %v", c.director, c.buyer, err)
		}
	}
	entries, err := VerifyChain([]string{issue(t, director, root), issue(t, func() Entry { b := buyer; b.DailyEUR = 7500; return b }(), tom)}, roots, now)
	if err != nil || entries[1].DailyEUR != 7500 {
		t.Fatalf("%v %+v", err, entries)
	}
}

// An entry may carry the holder's encryption key; it must be a P-256 point whose kid is the
// start of its SHA-256, and a chain with one holds like any other.
func TestAnEncryptionKeyRidesInTheSignedEntry(t *testing.T) {
	root := ed25519.NewKeyFromSeed([]byte("acme-root-seed-acme-root-seed-32"))
	roots := map[string]ed25519.PublicKey{"acme": root.Public().(ed25519.PublicKey)}
	_, holder := ec(t)
	_, encJWK := ec(t)
	k := &EncKey{Kty: "EC", Crv: "P-256", X: encJWK.X, Y: encJWK.Y}
	pub, _ := encJWK.ECDSA()
	point, _ := pub.Bytes()
	k.Kid = EncKid(point)
	e := Entry{ID: "acme#shane", Org: "acme", Parent: "acme", Holder: holder, CredentialID: "Y3JlZA", Role: "buyer", Kinds: []string{"odoo.read"}, Enc: k, IssuedAt: now.Unix() - 10, Expires: now.Unix() + 600}
	entries, err := VerifyChain([]string{issue(t, e, root)}, roots, now)
	if err != nil || entries[0].Enc == nil || entries[0].Enc.Kid != k.Kid {
		t.Fatalf("%v %+v", err, entries)
	}
	bad := *k
	bad.Kid = "AAAAAAAAAAAAAAAAAAAAAA"
	e.Enc = &bad
	if _, err := VerifyChain([]string{issue(t, e, root)}, roots, now); err == nil || !strings.Contains(err.Error(), "kid") {
		t.Fatalf("a kid that is not the key's: %v", err)
	}
}

// An observer acts on nothing, has a key, and looks inside its organisation until its entry
// ends; only the root gives a view of the whole organisation. It sees a holder when its view
// lies on the holder's chain and whoever signed it stands at or above that point.
func TestAnObserverSeesOnlyWhatItsSignerMayShow(t *testing.T) {
	root := ed25519.NewKeyFromSeed([]byte("acme-root-seed-acme-root-seed-32"))
	tom := ed25519.NewKeyFromSeed([]byte("tom-seed-tom-seed-tom-seed-tom-3"))
	anna := ed25519.NewKeyFromSeed([]byte("anna-seed-anna-seed-anna-seed-32"))
	roots := map[string]ed25519.PublicKey{"acme": root.Public().(ed25519.PublicKey)}
	_, shanePK := ec(t)
	_, encJWK := ec(t)
	pub, _ := encJWK.ECDSA()
	point, _ := pub.Bytes()
	enc := &EncKey{Kty: "EC", Crv: "P-256", X: encJWK.X, Y: encJWK.Y, Kid: EncKid(point)}
	kinds := []string{"odoo.read", "odoo.order_draft"}
	exp := now.Unix() + 86400
	dir := func(id string, k ed25519.PrivateKey) Entry {
		return Entry{ID: id, Org: "acme", Parent: "acme", Holder: okp(k.Public().(ed25519.PublicKey)), Role: "director", Kinds: kinds, CeilingEUR: 25000, MayDelegate: true, IssuedAt: now.Unix() - 10, Expires: exp}
	}
	tomTok, annaTok := issue(t, dir("acme#tom", tom), root), issue(t, dir("acme#anna", anna), root)
	shane := Entry{ID: "acme#shane", Org: "acme", Parent: "acme#tom", Holder: shanePK, CredentialID: "Y3JlZA", Role: "buyer", Kinds: kinds, CeilingEUR: 5000, IssuedAt: now.Unix() - 5, Expires: exp}
	holder, err := VerifyChain([]string{tomTok, issue(t, shane, tom)}, roots, now)
	if err != nil {
		t.Fatal(err)
	}
	obs := func(id, parent, under, detail string) Entry {
		return Entry{ID: id, Org: "acme", Parent: parent, Holder: okp(other(t)), Role: RoleObserver, Kinds: []string{}, Enc: enc,
			Sees: &Sees{Under: under, Detail: detail, Until: exp}, IssuedAt: now.Unix() - 5, Expires: exp}
	}
	chainOf := func(e Entry) ([]Entry, error) {
		switch e.Parent {
		case "acme":
			return VerifyChain([]string{issue(t, e, root)}, roots, now)
		case "acme#tom":
			return VerifyChain([]string{tomTok, issue(t, e, tom)}, roots, now)
		default:
			return VerifyChain([]string{annaTok, issue(t, e, anna)}, roots, now)
		}
	}
	for _, c := range []struct {
		name string
		e    Entry
		sees bool
	}{
		{"the insurer, under the whole of acme, from the root", obs("acme#obs-leiestad", "acme", "acme", "summary"), true},
		{"Tom's assistant, under Tom", obs("acme#obs-assistant", "acme#tom", "acme#tom", "full"), true},
		{"Tom's view of Shane alone", obs("acme#obs-shane", "acme#tom", "acme#shane", "full"), true},
		{"Tom's view of someone not on Shane's chain", obs("acme#obs-robby", "acme#tom", "acme#robby", "full"), false},
		{"Anna's view of Tom's part", obs("acme#obs-anna", "acme#anna", "acme#tom", "full"), false},
	} {
		chain, err := chainOf(c.e)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := Covers(chain, holder, now); got != c.sees {
			t.Errorf("%s: sees %v", c.name, got)
		}
	}
	// Ended, the view sees nothing.
	ended := obs("acme#obs-old", "acme", "acme", "summary")
	ended.Sees.Until = now.Unix() + 1
	if chain, _ := chainOf(ended); Covers(chain, holder, now.Add(time.Minute)) {
		t.Error("an ended view still sees")
	}
	refused := map[string]Entry{
		"the whole organisation from a director": obs("acme#obs-x", "acme#tom", "acme", "full"),
		"kinds": func() Entry {
			e := obs("acme#obs-x", "acme", "acme", "full")
			e.Kinds = []string{"odoo.read"}
			return e
		}(),
		"no key":            func() Entry { e := obs("acme#obs-x", "acme", "acme", "full"); e.Enc = nil; return e }(),
		"another detail":    obs("acme#obs-x", "acme", "acme", "everything"),
		"outside the org":   obs("acme#obs-x", "acme", "other#tom", "full"),
		"past its entry":    func() Entry { e := obs("acme#obs-x", "acme", "acme", "full"); e.Sees.Until = exp + 1; return e }(),
		"a delegator":       func() Entry { e := obs("acme#obs-x", "acme", "acme", "full"); e.MayDelegate = true; return e }(),
		"a view on a buyer": func() Entry { e := shane; e.Sees = &Sees{Under: "acme", Detail: "full", Until: exp}; return e }(),
	}
	for name, e := range refused {
		if _, err := chainOf(e); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
}

func other(t *testing.T) ed25519.PublicKey {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// A revocation signed by whoever signed the entry ends it; one signed by anyone else, or naming
// another entry, is ignored.
func TestARevokedEntryNoLongerHolds(t *testing.T) {
	root := ed25519.NewKeyFromSeed([]byte("acme-root-seed-acme-root-seed-32"))
	tom := ed25519.NewKeyFromSeed([]byte("tom-seed-tom-seed-tom-seed-tom-3"))
	roots := map[string]ed25519.PublicKey{"acme": root.Public().(ed25519.PublicKey)}
	_, pk := ec(t)
	tomTok := issue(t, Entry{ID: "acme#tom", Org: "acme", Parent: "acme", Holder: okp(tom.Public().(ed25519.PublicKey)), Role: "director", Kinds: []string{"odoo.read"}, MayDelegate: true, IssuedAt: now.Unix() - 9, Expires: now.Unix() + 999}, root)
	oldTok := issue(t, Entry{ID: "acme#shane", Org: "acme", Parent: "acme#tom", Holder: pk, CredentialID: "b2xk", Role: "buyer", Kinds: []string{"odoo.read"}, IssuedAt: now.Unix() - 5, Expires: now.Unix() + 99}, tom)
	chain := []string{tomTok, oldTok}
	entries, err := VerifyChain(chain, roots, now)
	if err != nil {
		t.Fatal(err)
	}
	rv := func(r Revocation, k ed25519.PrivateKey) func(string) string {
		tok, _ := IssueRevocation(r, k)
		return func(d string) string {
			if d == r.Revokes {
				return tok
			}
			return ""
		}
	}
	good := Revocation{Revokes: EntryDigest(oldTok), ID: "acme#shane", By: "acme#tom", IssuedAt: now.Unix()}
	if why := Revoked(chain, entries, roots, rv(good, tom)); !strings.Contains(why, "revoked by acme#tom") {
		t.Fatalf("a revocation by the signer: %q", why)
	}
	other := ed25519.NewKeyFromSeed([]byte("other-seed-other-seed-other-see!"))
	for name, lookup := range map[string]func(string) string{
		"signed by someone else": rv(good, other),
		"by another name":        rv(Revocation{Revokes: good.Revokes, ID: "acme#shane", By: "acme#anna", IssuedAt: now.Unix()}, tom),
		"for another id":         rv(Revocation{Revokes: good.Revokes, ID: "acme#robby", By: "acme#tom", IssuedAt: now.Unix()}, tom),
		"nothing":                nil,
	} {
		if why := Revoked(chain, entries, roots, lookup); why != "" {
			t.Errorf("%s: %q", name, why)
		}
	}
	// The root ends a director.
	byRoot := Revocation{Revokes: EntryDigest(tomTok), ID: "acme#tom", By: "acme", IssuedAt: now.Unix()}
	if why := Revoked(chain, entries, roots, rv(byRoot, root)); why == "" {
		t.Fatal("the root's revocation of a director")
	}
}
