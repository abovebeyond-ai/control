package relying

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/abovebeyond-ai/control/attest"
	"github.com/abovebeyond-ai/control/capability"
	"github.com/abovebeyond-ai/control/gateway"
	"github.com/abovebeyond-ai/control/log"
	"github.com/abovebeyond-ai/control/policy"
	"github.com/google/go-tdx-guest/testing/testdata"
)

// A record from an attested gateway, with the principal's capability, holds at the far
// end; the wrong repository, a refusal, another capability or a stale record do not.
func TestTheFarEndHoldsARecordAndItsCapability(t *testing.T) {
	principal := ed25519.NewKeyFromSeed([]byte("principal-seed-principal-seed-32"))
	gwSeed, _ := hex.DecodeString(strings.Repeat("11", 32))
	gwKey := ed25519.NewKeyFromSeed(gwSeed)
	pub := gwKey.Public().(ed25519.PublicKey)
	raw := append([]byte(nil), testdata.RawQuote...)
	rd := attest.ReportDataForKey(pub)
	copy(raw[attest.ReportDataOffset:], rd[:])
	own, _ := attest.FromRaw(raw, "sample", pub)
	now := time.Unix(1_800_000_000, 0)
	did := "did:example:ab"
	agent := did + "#agent-fix"
	store, _ := log.Open(t.TempDir())
	g, err := gateway.Open(gateway.Config{Issuer: "https://gw.example/control", Agent: agent, Attestation: own, Store: store, Key: gwKey, Clock: func() time.Time { return now },
		Policy: policy.Policy{Grant: policy.Grant{Principal: did, Kinds: []string{"workflow.dispatch", "pull.open"}, Resources: []string{"o/r"}, MaxPerKind: 3, PrincipalKey: hex.EncodeToString(principal.Public().(ed25519.PublicKey))}, PathAware: true}})
	if err != nil {
		t.Fatal(err)
	}
	capTok, _ := capability.Issue(capability.Payload{Issuer: did + "#portal", Subject: agent, Audience: "https://gw.example/control", Task: capability.Task{Playbook: "elixir-fix", Project: "demo"},
		Kinds: []string{"workflow.dispatch", "pull.open"}, Resources: []string{"o/r"}, IssuedAt: now.Unix(), Expires: now.Add(2 * time.Hour).Unix(), ID: "01J"}, principal)
	v := g.SubmitWith("r", policy.Action{Kind: "workflow.dispatch", Resource: "o/r", Params: map[string]any{"workflow": "w", "ref": "main"}}, did, nil, nil, nil, nil, capTok)
	if !v.Allowed() {
		t.Fatal(v.Reason)
	}
	// The derived did:web document names the did:webvh form as an alias; agents are under it.
	keys := Keys{Gateway: pub, Principal: principal.Public().(ed25519.PublicKey), DID: "did:web:example", Aliases: []string{did}}
	tok, err := DecodeToken(EncodeToken(v.Token))
	if err != nil {
		t.Fatal(err)
	}
	r := Check(tok, capTok, keys, Options{Repository: "o/r", Kind: "workflow.dispatch", MaxAge: 3 * time.Hour, MRTD: own.MRTD, Now: now.Add(time.Minute)})
	if !r.OK {
		t.Fatalf("must hold: %v", r.Reasons)
	}
	cases := map[string]Options{
		"other repository": {Repository: "o/x", Kind: "workflow.dispatch", MaxAge: 3 * time.Hour, Now: now},
		"other kind":       {Repository: "o/r", Kind: "pull.open", MaxAge: 3 * time.Hour, Now: now},
		"stale":            {Repository: "o/r", Kind: "workflow.dispatch", MaxAge: time.Minute, Now: now.Add(time.Hour)},
		"other MRTD":       {Repository: "o/r", Kind: "workflow.dispatch", MaxAge: 3 * time.Hour, MRTD: strings.Repeat("0", 96), Now: now},
	}
	for name, o := range cases {
		if Check(tok, capTok, keys, o).OK {
			t.Errorf("%s: must refuse", name)
		}
	}
	// A merge check days later: the capability has expired, and that is fine; it must
	// still be the one the record names.
	late := Check(tok, capTok, keys, Options{Repository: "o/r", Kind: "workflow.dispatch", Now: now.Add(72 * time.Hour)})
	if !late.OK {
		t.Fatalf("a merge check must accept an expired capability that the record names: %v", late.Reasons)
	}
	otherCap, _ := capability.Issue(capability.Payload{Issuer: did + "#portal", Subject: agent, Audience: "https://gw.example/control", Kinds: []string{"workflow.dispatch"}, Resources: []string{"o/r"}, IssuedAt: now.Unix(), Expires: now.Add(2 * time.Hour).Unix(), ID: "02K"}, principal)
	if Check(tok, otherCap, keys, Options{Repository: "o/r", Kind: "workflow.dispatch", Now: now}).OK {
		t.Error("another capability than the record names must refuse")
	}
	// A refusal is a record too, and the far end refuses to act on it.
	d := g.SubmitWith("r", policy.Action{Kind: "pull.open", Resource: "o/r", Params: map[string]any{"branch": "b"}}, did, nil, nil, nil, nil, capTok)
	if Check(d.Token, capTok, keys, Options{Repository: "o/r", Kind: "pull.open", Now: now}).OK {
		t.Error("a DENY record must not pass the far end")
	}
	// The pull request footer round-trips.
	e, c, err := FromBody("Security: update 2 packages\n\nsome text" + Footer(EncodeToken(v.Token), capTok))
	if err != nil || c != capTok || e != EncodeToken(v.Token) {
		t.Fatalf("footer: %v", err)
	}
}
