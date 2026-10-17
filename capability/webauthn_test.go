package capability

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/abovebeyond-ai/control/canonical"
)

var party = Party{RPID: "bextrust.abovebeyond.ai", Origins: []string{"https://bextrust.abovebeyond.ai", "android:apk-key-hash:abc"}}

// assertion is what a phone hands back for a get: authenticatorData, clientDataJSON and the
// signature, here made in the test with a key of its own.
type assertion struct {
	rpID, typ, origin, challenge string
	flags                        byte
	crossOrigin                  bool
}

func passkeyToken(t *testing.T, key *ecdsa.PrivateKey, raw []byte, a assertion) string {
	t.Helper()
	rp := sha256.Sum256([]byte(a.rpID))
	auth := append(append([]byte{}, rp[:]...), a.flags, 0, 0, 0, 1)
	if a.challenge == "" {
		a.challenge = Challenge(raw)
	}
	cd, _ := json.Marshal(map[string]any{"type": a.typ, "challenge": a.challenge, "origin": a.origin, "crossOrigin": a.crossOrigin})
	cdHash := sha256.Sum256(cd)
	signed := sha256.Sum256(append(append([]byte{}, auth...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, key, signed[:])
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return PasskeyPrefix + "." + enc(raw) + "." + enc(auth) + "." + enc(cd) + "." + enc(sig)
}

// A passkey word holds when the phone signed this payload's digest, as a get, from an origin
// the gateway accepts, for its relying party, with the person present and verified; then it is
// held to gateway, agent and time like any capability. Each missing piece is refused.
func TestAPasskeyWordIsHeldToItsPayloadPartyAndPerson(t *testing.T) {
	elise, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Unix(1_792_300_000, 0)
	p := Payload{Issuer: "acme#elise", Subject: "did:web:bextrust.abovebeyond.ai:acme#procurement-agent", Audience: "https://gw.example/control",
		Task: Task{Project: "acme"}, Kinds: []string{"odoo.read"}, Resources: []string{"odoo:acme/*"}, IssuedAt: now.Unix(), Expires: now.Add(time.Hour).Unix(), ID: "m-1"}
	raw, _ := canonical.Encode(p)
	good := assertion{rpID: party.RPID, typ: "webauthn.get", origin: "https://bextrust.abovebeyond.ai", flags: flagUP | flagUV}
	tok := passkeyToken(t, elise, raw, good)
	got, err := VerifyPasskey(tok, &elise.PublicKey, party, p.Audience, p.Subject, now)
	if err != nil || !got.Covers("odoo.read", "odoo:acme/purchase.order") || got.Covers("odoo.order_draft", "odoo:acme/purchase.order") {
		t.Fatalf("%v %+v", err, got)
	}
	// The app signs from its own origin, the hash of its signing certificate.
	app := good
	app.origin = "android:apk-key-hash:abc"
	if _, err := VerifyPasskey(passkeyToken(t, elise, raw, app), &elise.PublicKey, party, p.Audience, p.Subject, now); err != nil {
		t.Fatal(err)
	}
	with := func(f func(a *assertion)) string {
		a := good
		f(&a)
		return passkeyToken(t, elise, raw, a)
	}
	wider := p
	wider.Kinds = []string{"odoo.read", "odoo.order_draft"}
	widerRaw, _ := canonical.Encode(wider)
	parts := strings.Split(tok, ".")
	cases := map[string]struct {
		tok      string
		key      *ecdsa.PublicKey
		aud, sub string
		at       time.Time
	}{
		"another key":        {tok, &other.PublicKey, p.Audience, p.Subject, now},
		"another challenge":  {with(func(a *assertion) { a.challenge = Challenge([]byte("other")) }), &elise.PublicKey, p.Audience, p.Subject, now},
		"a create":           {with(func(a *assertion) { a.typ = "webauthn.create" }), &elise.PublicKey, p.Audience, p.Subject, now},
		"another origin":     {with(func(a *assertion) { a.origin = "https://evil.example" }), &elise.PublicKey, p.Audience, p.Subject, now},
		"a frame":            {with(func(a *assertion) { a.crossOrigin = true }), &elise.PublicKey, p.Audience, p.Subject, now},
		"another party":      {with(func(a *assertion) { a.rpID = "evil.example" }), &elise.PublicKey, p.Audience, p.Subject, now},
		"nobody present":     {with(func(a *assertion) { a.flags = flagUV }), &elise.PublicKey, p.Audience, p.Subject, now},
		"nobody verified":    {with(func(a *assertion) { a.flags = flagUP }), &elise.PublicKey, p.Audience, p.Subject, now},
		"another gateway":    {tok, &elise.PublicKey, "https://elsewhere", p.Subject, now},
		"another agent":      {tok, &elise.PublicKey, p.Audience, "did:example:other", now},
		"expired":            {tok, &elise.PublicKey, p.Audience, p.Subject, now.Add(2 * time.Hour)},
		"a widened payload":  {strings.Join([]string{parts[0], base64.RawURLEncoding.EncodeToString(widerRaw), parts[2], parts[3], parts[4]}, "."), &elise.PublicKey, p.Audience, p.Subject, now},
		"an Ed25519 token":   {"eyJ9.sig", &elise.PublicKey, p.Audience, p.Subject, now},
		"no key":             {tok, nil, p.Audience, p.Subject, now},
		"not canonical JSON": {strings.Join([]string{parts[0], base64.RawURLEncoding.EncodeToString(append([]byte(" "), raw...)), parts[2], parts[3], parts[4]}, "."), &elise.PublicKey, p.Audience, p.Subject, now},
	}
	for name, c := range cases {
		if _, err := VerifyPasskey(c.tok, c.key, party, c.aud, c.sub, c.at); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
	if !IsPasskey(tok) || IsPasskey("abc.def") {
		t.Fatal("IsPasskey")
	}
}
