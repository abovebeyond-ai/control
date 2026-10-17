package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abovebeyond-ai/control/attest"
	"github.com/abovebeyond-ai/control/canonical"
	"github.com/abovebeyond-ai/control/capability"
	"github.com/abovebeyond-ai/control/effects"
	"github.com/abovebeyond-ai/control/gateway"
	"github.com/abovebeyond-ai/control/log"
	"github.com/abovebeyond-ai/control/policy"
	"github.com/abovebeyond-ai/control/registry"
)

const csImage = "sha256:abababababababababababababababababababababababababababababababab"

// sealProvision is acme-admin's side: seal the files to the gateway's provisioning key, after
// checking the record key signed it, and sign the envelope with the org's root.
func sealProvision(t *testing.T, keyAnswer map[string]any, recordKey ed25519.PublicKey, root ed25519.PrivateKey, files map[string]string) provisionEnvelope {
	t.Helper()
	raw, _ := json.Marshal(keyAnswer["key"])
	var k registry.EncKey
	if err := json.Unmarshal(raw, &k); err != nil {
		t.Fatal(err)
	}
	in, _ := provisionKeyBytes(k)
	sig, _ := hex.DecodeString(keyAnswer["sig"].(string))
	if !ed25519.Verify(recordKey, in, sig) {
		t.Fatal("the provisioning key is not signed by the record key")
	}
	plain, _ := json.Marshal(map[string]any{"v": 1, "files": files})
	aad, _ := canonical.Encode(map[string]any{"kid": k.Kid})
	enc, ct, err := hpkeSeal(k, provisionInfo, aad, plain)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	e := provisionEnvelope{Org: "acme", Kid: k.Kid, Enc: b64(enc), CT: b64(ct)}
	signed, _ := provisionSigned(e)
	e.Sig = hex.EncodeToString(ed25519.Sign(root, signed))
	return e
}

func TestAGatewayInConfidentialSpaceIsProvisionedByTheOrgAndSaysSoInItsRecords(t *testing.T) {
	var mu sync.Mutex
	relayAuth := []string{}
	odoo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "bearer provisioned-secret" {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`[{"id":7,"name":"P00007","state":"draft","amount_total":1222.5}]`))
	}))
	defer odoo.Close()
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		relayAuth = append(relayAuth, r.URL.Path+" "+r.Header.Get("Authorization"))
		mu.Unlock()
		w.WriteHeader(404)
	}))
	defer relay.Close()

	google, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := &attest.JWKS{Keys: map[string]*rsa.PublicKey{"g1": &google.PublicKey}, At: time.Now()}
	tokens := func(_ context.Context, aud string, nonces []string) (string, error) {
		c := attest.CSClaimsFor(csImage, nil, aud, time.Now())
		c["eat_nonce"] = nonces
		return attest.SignCSToken(google, "g1", c)
	}

	now := time.Now()
	root := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xac}, 32))
	tom := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x70}, 32))
	elise, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kinds := policy.Builtin.Of(policy.OdooAdapter)
	tomTok, _ := registry.Issue(registry.Entry{ID: "acme#tom", Org: "acme", Parent: "acme", Holder: registry.JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(tom.Public().(ed25519.PublicKey))},
		Role: "director", Kinds: kinds, CeilingEUR: 50000, MayDelegate: true, IssuedAt: now.Unix() - 60, Expires: now.Unix() + 86400}, root)
	eliseTok, _ := registry.Issue(registry.Entry{ID: "acme#elise", Org: "acme", Parent: "acme#tom", Holder: p256JWK(elise), CredentialID: "Y3JlZA",
		Role: "buyer", Kinds: kinds, CeilingEUR: 5000, IssuedAt: now.Unix() - 60, Expires: now.Unix() + 86400}, tom)

	key, _ := memoryKey()
	dir := t.TempDir()
	agent := "did:web:bextrust.abovebeyond.ai:acme#procurement-agent"
	issuer := "http://acme-gate:8080"
	cfg := config{Issuer: issuer, Store: csStore(filepath.Join(dir, "store"), key.Public().(ed25519.PublicKey)), Secrets: filepath.Join(dir, "none"), RelayURL: relay.URL,
		RelayToken: "relay-door", Attestation: attestationCS, ClientToken: "c",
		Orgs: map[string]string{"acme": hex.EncodeToString(root.Public().(ed25519.PublicKey))}, Passkey: odooParty,
		Agents: map[string]struct {
			Grant policy.Grant `json:"grant"`
		}{agent: {Grant: policy.Grant{Principal: "acme", Kinds: kinds, Resources: []string{"odoo:acme/*"}, Org: "acme", Asks: "acme#elise"}}}}
	store, _ := log.Open(cfg.Store)
	s := &service{cfg: cfg, key: key, store: store, effects: effects.Registry{}, gateways: map[string]*gateway.Gateway{}}
	s.prov, _ = newProvisioner()
	s.effects.Add(effects.Odoo{SecretsDir: cfg.Secrets, Instances: map[string]effects.OdooInstance{"acme": {Base: odoo.URL, DB: "acme"}}, Provisioned: s.prov.key, OnlyProvisioned: true})
	var err error
	if s.attested, err = csAttest(cfg, key, tokens); err != nil {
		t.Fatal(err)
	}
	// The record a stranger reads verifies under "Google's" keys, for this image and this key.
	if err := attest.Verify(context.Background(), s.attested, attest.Options{ImageDigest: csImage, JWKS: jwks}); err != nil {
		t.Fatalf("the gateway's own attestation: %v", err)
	}

	call := func(handler http.HandlerFunc, path string, body any) (int, map[string]any) {
		method, rd := "GET", (*bytes.Reader)(nil)
		if body != nil {
			raw, _ := json.Marshal(body)
			method, rd = "POST", bytes.NewReader(raw)
		}
		var req *http.Request
		if rd == nil {
			req = httptest.NewRequest(method, path, nil)
		} else {
			req = httptest.NewRequest(method, path, rd)
		}
		rec := httptest.NewRecorder()
		handler(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	mandate, _ := canonical.Encode(capability.Payload{Issuer: "acme#elise", Subject: agent, Audience: issuer, Task: capability.Task{Project: "acme"},
		Kinds: []string{"odoo.read"}, Resources: []string{"odoo:acme/*"}, IssuedAt: now.Unix(), Expires: now.Add(8 * time.Hour).Unix(), ID: "mandate-cs"})
	read := submitRequest{Agent: agent, Action: policy.Action{Kind: "odoo.read", Resource: "odoo:acme/purchase.order", Params: map[string]any{"model": "purchase.order", "domain": []any{}}},
		Capability: signWord(t, elise, mandate), Chain: []string{tomTok, eliseTok}}

	// Before Acme provisions it, the gate refuses Odoo work and says why.
	if code, out := call(s.submit, "/v1/submit", read); code != 503 || !strings.Contains(out["error"].(string), "not provisioned") {
		t.Fatalf("before provisioning: %d %v", code, out)
	}

	_, keyAnswer := call(s.provisionKey, "/v1/provision-key", nil)
	recordKey := key.Public().(ed25519.PublicKey)
	files := map[string]string{"odoo-key-acme": "provisioned-secret\n", "odoo-key-acme-procurement-agent": "provisioned-secret"}
	e := sealProvision(t, keyAnswer, recordKey, root, files)

	// Not Acme's root: refused. A file the gate does not take: refused.
	stranger := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x55}, 32))
	if code, _ := call(s.provision, "/v1/provision", sealProvision(t, keyAnswer, recordKey, stranger, files)); code != 403 {
		t.Fatalf("an envelope signed by a stranger: %d", code)
	}
	if code, out := call(s.provision, "/v1/provision", sealProvision(t, keyAnswer, recordKey, root, map[string]string{"../control-signing.key": "x"})); code != 400 {
		t.Fatalf("a file name the gate does not take: %d %v", code, out)
	}
	tampered := e
	tampered.CT = tampered.CT[:len(tampered.CT)-2] + "AA"
	if code, _ := call(s.provision, "/v1/provision", tampered); code != 403 {
		t.Fatalf("a tampered envelope: %d", code)
	}
	code, out := call(s.provision, "/v1/provision", e)
	if code != 200 || len(out["provisioned"].([]any)) != 2 {
		t.Fatalf("provision: %d %v", code, out)
	}
	g, _ := s.gateway(agent)
	recs, _ := s.store.Records(agent)
	if len(recs) != 1 {
		t.Fatalf("one record of the provisioning, got %d", len(recs))
	}
	raw, _ := json.Marshal(recs[0])
	if strings.Contains(string(raw), "provisioned-secret") || !strings.Contains(string(raw), `"control_action":"provision-`) {
		t.Fatalf("the provisioning record: %s", raw)
	}

	// Now the read goes to Odoo with the provisioned key.
	if code, out := call(s.submit, "/v1/submit", read); code != 200 || out["verdict"] != "ALLOW" {
		t.Fatalf("a read after provisioning: %d %v", code, out)
	}
	recs, _ = s.store.Records(agent)
	att := recs[len(recs)-1]["submods"].(map[string]any)["attestation"].(map[string]any)
	want := canonical.Tag(canonical.SHA256([]byte(s.attested.Token)))
	if att["platform"] != attest.PlatformGCPTDX || att["software"] != attest.SoftwareCS || att["image_digest"] != csImage || att["token"] != want ||
		att["measurement"] != "sha-256:"+strings.TrimPrefix(csImage, "sha256:") {
		t.Fatalf("the record's attestation: %v", att)
	}
	cp, _ := g.Checkpoint()
	if cp.Attestation != want {
		t.Fatalf("the checkpoint names attestation %s, not the token %s", cp.Attestation, want)
	}

	// The daily token: a new one for the same key and image is taken; the records name it.
	next, err := csAttest(cfg, key, tokens)
	if err != nil || s.setAttestation(next) != nil {
		t.Fatal("a new token for the same key did not take", err)
	}
	if code, _ := call(s.submit, "/v1/submit", read); code != 200 {
		t.Fatal("a read after the new token")
	}
	recs, _ = s.store.Records(agent)
	att = recs[len(recs)-1]["submods"].(map[string]any)["attestation"].(map[string]any)
	if att["token"] != canonical.Tag(canonical.SHA256([]byte(next.Token))) {
		t.Fatal("the record after the daily token does not name it")
	}
	// A token of another image is not taken.
	otherImage := func(_ context.Context, aud string, nonces []string) (string, error) {
		c := attest.CSClaimsFor("sha256:cd", nil, aud, time.Now())
		c["eat_nonce"] = nonces
		return attest.SignCSToken(google, "g1", c)
	}
	if r, err := csAttest(cfg, key, otherImage); err != nil || s.setAttestation(r) == nil {
		t.Fatal("a token of another image replaced the attestation")
	}

	// Every relay call carries the relay token: an announcement, a chain, a receipt.
	s.announce(map[string]any{"pending": "p1"})
	_, _ = s.relayChain("acme#elise")
	_, _ = s.postReceipt([]byte(`{}`))
	mu.Lock()
	defer mu.Unlock()
	if len(relayAuth) == 0 {
		t.Fatal("the relay was never called")
	}
	for _, a := range relayAuth {
		if !strings.HasSuffix(a, " Bearer relay-door") {
			t.Fatalf("a relay call without the relay token: %q", a)
		}
	}
}

func TestAProvisioningEnvelopeOpensOnlyWithItsKey(t *testing.T) {
	p, _ := newProvisioner()
	other, _ := ecdh.P256().GenerateKey(rand.Reader)
	if _, err := p.open(provisionEnvelope{Kid: "nope"}); err == nil || !strings.Contains(err.Error(), "restarted") {
		t.Fatalf("an envelope for another kid: %v", err)
	}
	k := *encKeyOf(t, other)
	plain, _ := json.Marshal(map[string]any{"v": 1, "files": map[string]string{"odoo-key-acme": "x"}})
	aad, _ := canonical.Encode(map[string]any{"kid": p.pub.Kid})
	enc, ct, _ := hpkeSeal(k, provisionInfo, aad, plain)
	b64 := base64.RawURLEncoding.EncodeToString
	if _, err := p.open(provisionEnvelope{Kid: p.pub.Kid, Enc: b64(enc), CT: b64(ct)}); err == nil {
		t.Fatal("an envelope sealed to another key opened")
	}
}
