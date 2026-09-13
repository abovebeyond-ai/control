package relying

import (
	"context"
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

// A successor identity: the same principal under a new identifier (the first log ended
// on 13 September 2026). The far end configured with the old DID accepts a record by an
// agent of the successor only when the successor's document names the old DID in its
// alsoKnownAs AND carries the same #key-1; and it verifies the capability against the
// key its issuer names in that document, the operator's #operator among them, never
// against a key of a document that merely claims the predecessor.
func TestASuccessorIdentityIsAcceptedOnItsOwnKeyAndTheOperatorsWord(t *testing.T) {
	identity := ed25519.NewKeyFromSeed([]byte("identity-seed-identity-seed-32!!"))
	operator := ed25519.NewKeyFromSeed([]byte("operator-one-operator-one-seed32"))
	portal := ed25519.NewKeyFromSeed([]byte("principal-seed-principal-seed-32"))
	gwSeed, _ := hex.DecodeString(strings.Repeat("11", 32))
	gwKey := ed25519.NewKeyFromSeed(gwSeed)
	pub := gwKey.Public().(ed25519.PublicKey)
	raw := append([]byte(nil), testdata.RawQuote...)
	rd := attest.ReportDataForKey(pub)
	copy(raw[attest.ReportDataOffset:], rd[:])
	own, _ := attest.FromRaw(raw, "sample", pub)
	now := time.Unix(1_800_000_000, 0)
	old, next := "did:webvh:QmOld:example.org", "did:webvh:QmNew:example.org:id"
	agent := next + "#agent-workbench"
	store, _ := log.Open(t.TempDir())
	g, err := gateway.Open(gateway.Config{Issuer: "https://gw.example/control", Agent: agent, Attestation: own, Store: store, Key: gwKey, Clock: func() time.Time { return now },
		Policy: policy.Policy{Grant: policy.Grant{Principal: next, Kinds: []string{"pull.open"}, Resources: []string{"o/r"}, MaxPerKind: 3,
			PrincipalKey: hex.EncodeToString(portal.Public().(ed25519.PublicKey)), PrincipalKeys: map[string]string{next + "#operator": hex.EncodeToString(operator.Public().(ed25519.PublicKey))}}, PathAware: true}})
	if err != nil {
		t.Fatal(err)
	}
	capTok, _ := capability.Issue(capability.Payload{Issuer: next + "#operator", Subject: agent, Audience: "https://gw.example/control", Task: capability.Task{Playbook: "workbench", Project: "demo"},
		Kinds: []string{"pull.open"}, Resources: []string{"o/r"}, IssuedAt: now.Unix(), Expires: now.Add(2 * time.Hour).Unix(), ID: "adm-1"}, operator)
	v := g.SubmitWith("r", policy.Action{Kind: "pull.open", Resource: "o/r", Params: map[string]any{"branch": "b", "base": "main"}}, next, nil, nil, nil, nil, capTok)
	if !v.Allowed() {
		t.Fatal(v.Reason)
	}
	tok, _ := DecodeToken(EncodeToken(v.Token))
	pk := func(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }
	// The old document, as the far end is configured: did:web with the old did:webvh as alias.
	oldKeys := Keys{Gateway: pub, Principal: pk(portal), DID: "did:web:example.org", Aliases: []string{old}, Methods: map[string]ed25519.PublicKey{"key-1": pk(identity), "control-gateway": pub, "portal": pk(portal)}}
	successor := Keys{Gateway: pub, Principal: pk(portal), DID: "did:web:example.org:id", Aliases: []string{old, next}, Methods: map[string]ed25519.PublicKey{"key-1": pk(identity), "control-gateway": pub, "portal": pk(portal), "operator": pk(operator)}}
	impostor := Keys{Gateway: pub, Principal: pk(portal), DID: "did:web:example.org:id", Aliases: []string{old, next}, Methods: map[string]ed25519.PublicKey{"key-1": pk(operator), "control-gateway": pub, "portal": pk(portal), "operator": pk(operator)}}
	served := successor
	oldKeys.resolve = func(ctx context.Context, url string) (Keys, error) {
		if url != "https://example.org/id/did.json" {
			t.Fatalf("the successor's document is fetched at its path, not %s", url)
		}
		return served, nil
	}
	if r := CheckIn(context.Background(), tok, capTok, oldKeys, Options{Repository: "o/r", Kind: "pull.open", Now: now}); !r.OK {
		t.Fatalf("the successor's agent, admitted by #operator, must hold: %v", r.Reasons)
	}
	// Without the shared identity key the claim of succession is anyone's.
	served = impostor
	oldKeys.Successors = nil
	if r := CheckIn(context.Background(), tok, capTok, oldKeys, Options{Repository: "o/r", Kind: "pull.open", Now: now}); r.OK {
		t.Fatal("a document that claims the predecessor without its #key-1 must be refused")
	}
	// A capability signed by Portal's key but naming #operator as issuer is refused.
	forged, _ := capability.Issue(capability.Payload{Issuer: next + "#operator", Subject: agent, Audience: "https://gw.example/control", Task: capability.Task{Playbook: "workbench", Project: "demo"},
		Kinds: []string{"pull.open"}, Resources: []string{"o/r"}, IssuedAt: now.Unix(), Expires: now.Add(2 * time.Hour).Unix(), ID: "adm-1"}, portal)
	served = successor
	oldKeys.Successors = nil
	if r := CheckIn(context.Background(), tok, forged, oldKeys, Options{Repository: "o/r", Kind: "pull.open", Now: now}); r.OK {
		t.Fatal("a capability that names #operator but carries Portal's signature must be refused")
	}
	if DocumentURL("did:webvh:QmX:abovebeyond.ai") != "https://abovebeyond.ai/.well-known/did.json" || DocumentURL("did:webvh:QmX:abovebeyond.ai:id") != "https://abovebeyond.ai/id/did.json" || DocumentURL("did:web:abovebeyond.ai:id") != "https://abovebeyond.ai/id/did.json" {
		t.Fatal("document URLs follow the path")
	}
}
