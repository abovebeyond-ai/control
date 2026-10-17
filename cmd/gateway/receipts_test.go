package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/cryptotest"
	"time"

	"github.com/abovebeyond-ai/control/effects"
	"github.com/abovebeyond-ai/control/gateway"
	"github.com/abovebeyond-ai/control/log"
	"github.com/abovebeyond-ai/control/policy"
	"github.com/abovebeyond-ai/control/registry"
)

func encKeyOf(t *testing.T, priv *ecdh.PrivateKey) *registry.EncKey {
	t.Helper()
	point := priv.PublicKey().Bytes()
	b64 := base64.RawURLEncoding.EncodeToString
	return &registry.EncKey{Kty: "EC", Crv: "P-256", X: b64(point[1:33]), Y: b64(point[33:]), Kid: registry.EncKid(point)}
}

// The vector the phone's opener is tested against (docs/hpke-vector.json in gate-demo-box): a
// fixed recipient key, a fixed plaintext, and the ephemeral key drawn from a seeded source, so
// the envelope is the same on every run. HPKE_VECTOR_OUT=<path> writes it.
func TestASealedReceiptOpensWithTheHoldersKeyOnly(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 2026)
	privRaw, _ := hex.DecodeString("1f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c5b6a7988")
	priv, err := ecdh.P256().NewPrivateKey(privRaw)
	if err != nil {
		t.Fatal(err)
	}
	key := encKeyOf(t, priv)
	plaintext := []byte(`{"agent":"did:web:bextrust.abovebeyond.ai:acme#procurement-agent","at":1792265331,"holder":"acme#shane","id":"did:web:bextrust.abovebeyond.ai:acme#procurement-agent/8","kind":"odoo.read","v":1,"verdict":"ALLOW"}`)
	e, err := sealReceipt(*key, "acme#shane", "did:web:bextrust.abovebeyond.ai:acme#procurement-agent/8", 1792265331, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := openReceipt(priv, e)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("%v %s", err, got)
	}
	// Moved to another holder, id or time, it does not open: the header is the aad.
	for _, moved := range []envelope{{Holder: "acme#robby", ID: e.ID, At: e.At, Kid: e.Kid, Enc: e.Enc, CT: e.CT}, {Holder: e.Holder, ID: e.ID + "0", At: e.At, Kid: e.Kid, Enc: e.Enc, CT: e.CT}, {Holder: e.Holder, ID: e.ID, At: e.At + 1, Kid: e.Kid, Enc: e.Enc, CT: e.CT}} {
		if _, err := openReceipt(priv, moved); err == nil {
			t.Fatalf("a moved envelope opened: %+v", moved)
		}
	}
	other, _ := ecdh.P256().GenerateKey(rand.Reader)
	if _, err := openReceipt(other, e); err == nil {
		t.Fatal("another key opened it")
	}
	again, _ := sealReceipt(*key, e.Holder, e.ID, e.At, plaintext)
	if again.Enc == e.Enc {
		t.Fatal("two seals shared an ephemeral key")
	}
	if out := os.Getenv("HPKE_VECTOR_OUT"); out != "" {
		aad, _ := receiptAAD(e.Holder, e.ID, e.At, e.Kid)
		raw, _ := json.MarshalIndent(map[string]any{
			"about":                 "One sealed receipt (docs/contract.md, sealed receipts), from control's cmd/gateway/receipts_test.go. HPKE base mode, KEM 0x0010 DHKEM(P-256, HKDF-SHA256), KDF 0x0001 HKDF-SHA256, AEAD 0x0001 AES-128-GCM. Open: decapsulate enc with the recipient key, open ct with aad and info, compare with plaintext.",
			"recipient_private_hex": hex.EncodeToString(privRaw),
			"recipient_public":      key,
			"info":                  receiptInfo,
			"aad":                   string(aad),
			"envelope":              e,
			"enc_hex":               hexOf(e.Enc),
			"ct_hex":                hexOf(e.CT),
			"plaintext":             string(plaintext),
		}, "", "  ")
		if err := os.WriteFile(out, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func hexOf(b64 string) string {
	raw, _ := base64.RawURLEncoding.DecodeString(b64)
	return hex.EncodeToString(raw)
}

// Every action under an organisation's grant ends in a receipt: a read refused for want of a
// mandate goes to the holder the grant asks, whose key the gate reads from their chain at the
// relay and verifies from the pinned root; a draft on a word goes to the word's signer, whose
// key the verified chain carried. Each is sealed to the holder and to the audit key, carries
// the action's three signed records, and opens to what happened. A relay that is away keeps the
// envelopes in the outbox until it is back.
func TestEveryActionEndsInASealedReceipt(t *testing.T) {
	odoo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimPrefix(r.URL.Path, "/json/2/") {
		case "product.product/read":
			_, _ = w.Write([]byte(`[{"id":19,"display_name":"Corner Desk","standard_price":600.0,"purchase_ok":true}]`))
		case "purchase.order/create":
			_, _ = w.Write([]byte(`[13]`))
		case "purchase.order/read":
			_, _ = w.Write([]byte(`[{"id":13,"name":"P00013","state":"draft","amount_total":1200.0,"currency_id":[1,"EUR"],"company_id":[1,"Acme"],"order_line":[30]}]`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer odoo.Close()

	now := time.Now()
	root := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xac}, 32))
	tom := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x70}, 32))
	shane, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	phone, _ := ecdh.P256().GenerateKey(rand.Reader)
	audit, _ := ecdh.P256().GenerateKey(rand.Reader)
	kinds := policy.Builtin.Of(policy.OdooAdapter)
	tomTok, _ := registry.Issue(registry.Entry{ID: "acme#tom", Org: "acme", Parent: "acme", Holder: registry.JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(tom.Public().(ed25519.PublicKey))},
		Role: "director", Kinds: kinds, CeilingEUR: 25000, MayDelegate: true, IssuedAt: now.Unix() - 60, Expires: now.Unix() + 86400}, root)
	shaneTok, _ := registry.Issue(registry.Entry{ID: "acme#shane", Org: "acme", Parent: "acme#tom", Holder: p256JWK(shane), CredentialID: "Y3JlZA", Role: "buyer", Kinds: kinds,
		CeilingEUR: 5000, Enc: encKeyOf(t, phone), IssuedAt: now.Unix() - 60, Expires: now.Unix() + 86400}, tom)
	chain := []string{tomTok, shaneTok}

	var mu sync.Mutex
	var got []envelope
	relayUp := true
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/api/registry/acme#shane":
			_ = json.NewEncoder(w).Encode(map[string]any{"chain": chain})
		case r.URL.Path == "/api/receipts" && !relayUp:
			w.WriteHeader(503)
		case r.URL.Path == "/api/receipts":
			var e envelope
			_ = json.NewDecoder(r.Body).Decode(&e)
			got = append(got, e)
			w.WriteHeader(201)
		default:
			w.WriteHeader(201)
		}
	}))
	defer relay.Close()

	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets")
	_ = os.MkdirAll(secrets, 0o700)
	_ = os.WriteFile(filepath.Join(secrets, "odoo-key-acme"), []byte("odoo-secret\n"), 0o600)
	store, _ := log.Open(filepath.Join(dir, "store"))
	agent := "did:web:bextrust.abovebeyond.ai:acme#procurement-agent"
	issuer := "https://gate.example/control"
	gateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	s := &service{key: gateKey, store: store, effects: effects.Registry{}, gateways: map[string]*gateway.Gateway{}, receipts: &outbox{kick: make(chan struct{}, 1)},
		cfg: config{Issuer: issuer, Store: filepath.Join(dir, "store"), Secrets: secrets, RelayURL: relay.URL, AuditEnc: encKeyOf(t, audit),
			Orgs: map[string]string{"acme": hex.EncodeToString(root.Public().(ed25519.PublicKey))}, Passkey: odooParty,
			Agents: map[string]struct {
				Grant policy.Grant `json:"grant"`
			}{agent: {Grant: policy.Grant{Principal: "acme", Kinds: kinds, Resources: []string{"odoo:acme/*"}, Org: "acme", Asks: "acme#shane"}}}}}
	s.effects.Add(effects.Odoo{SecretsDir: secrets, Instances: map[string]effects.OdooInstance{"acme": {Base: odoo.URL, DB: "acme"}}})

	post := func(handler http.HandlerFunc, path, id string, body any) map[string]any {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest("POST", path, bytes.NewReader(raw))
		req.SetPathValue("id", id)
		rec := httptest.NewRecorder()
		handler(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}
	open := func(e envelope, key *ecdh.PrivateKey) map[string]any {
		t.Helper()
		raw, err := openReceipt(key, e)
		if err != nil {
			t.Fatalf("%s for %s: %v", e.ID, e.Holder, err)
		}
		var p map[string]any
		_ = json.Unmarshal(raw, &p)
		return p
	}

	// A read without a mandate: refused, and the refusal reaches Shane and Acme's audit.
	read := policy.Action{Kind: "odoo.read", Resource: "odoo:acme/purchase.order", Params: map[string]any{"model": "purchase.order"}}
	if out := post(s.submit, "/v1/submit", "", submitRequest{Agent: agent, Action: read}); out["verdict"] != "DENY" {
		t.Fatalf("%v", out)
	}
	s.flushReceipts()
	if len(got) != 2 || got[0].Holder == got[1].Holder {
		t.Fatalf("one envelope for Shane, one for the audit: %+v", got)
	}
	for _, e := range got {
		key := phone
		if e.Holder == "acme#audit" {
			key = audit
		}
		p := open(e, key)
		if p["holder"] != "acme#shane" || p["verdict"] != "DENY" || p["asked"] != false || p["kind"] != "odoo.read" || len(p["records"].([]any)) != 3 || p["gate_key"] != hex.EncodeToString(gateKey.Public().(ed25519.PublicKey)) || p["id"] != e.ID {
			t.Fatalf("%v", p)
		}
	}

	// A draft on Shane's word: the key comes with the verified chain, and the relay is away.
	got, relayUp = nil, false
	draft := policy.Action{Kind: "odoo.order_draft", Resource: "odoo:acme/purchase.order", Params: map[string]any{"partner_id": float64(8), "lines": []any{map[string]any{"product_id": float64(19), "qty": float64(2)}}}}
	asked := post(s.submit, "/v1/submit", "", submitRequest{Agent: agent, Action: draft})
	payload, _ := base64.RawURLEncoding.DecodeString(asked["payload"].(string))
	out := post(s.word, "/v1/pending/x/word", asked["pending"].(string), map[string]any{"capability": signWord(t, shane, payload), "chain": chain})
	if out["verdict"] != "ALLOW" {
		t.Fatalf("%v", out)
	}
	s.flushReceipts()
	waiting, _ := filepath.Glob(filepath.Join(s.outboxDir(), "env-*.json"))
	if len(got) != 0 || len(waiting) != 2 {
		t.Fatalf("with the relay away the envelopes wait: %d delivered, %d waiting", len(got), len(waiting))
	}
	mu.Lock()
	relayUp = true
	mu.Unlock()
	s.flushReceipts()
	if len(got) != 2 {
		t.Fatalf("delivered once the relay is back: %+v", got)
	}
	for _, e := range got {
		if e.Holder != "acme#shane" {
			continue
		}
		p := open(e, phone)
		effect := p["effect"].(map[string]any)
		cc := p["chain"].(map[string]any)
		if p["asked"] != true || p["verdict"] != "ALLOW" || effect["name"] != "P00013" || effect["ok"] != true || cc["ceiling_eur"] != float64(5000) || len(cc["entries"].([]any)) != 2 {
			t.Fatalf("%v", p)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(s.outboxDir(), "*")); len(left) != 0 {
		t.Fatalf("the outbox is empty once delivered: %v", left)
	}
}
