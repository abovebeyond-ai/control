package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/cryptotest"
	"time"

	"github.com/abovebeyond-ai/control/canonical"
	"github.com/abovebeyond-ai/control/capability"
	"github.com/abovebeyond-ai/control/effects"
	"github.com/abovebeyond-ai/control/evidence"
	"github.com/abovebeyond-ai/control/gateway"
	"github.com/abovebeyond-ai/control/log"
	"github.com/abovebeyond-ai/control/merkle"
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

// Every action under an organisation's grant ends in receipts: for the person it was taken for,
// for their managers who hold a key, for the observers whose view covers them (a supplier only
// for its own orders, an insurer as a summary), and for the audit key. Each is signed by the
// gate, numbered per recipient, and carries the proof of the action's records into the
// checkpoint that closes the action, which the gate serves among its action ends. A relay that
// is away keeps the envelopes in the outbox until it is back.
func TestEveryActionEndsInSealedReceipts(t *testing.T) {
	odoo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			VL []map[string]any `json:"vals_list"`
		}
		switch strings.TrimPrefix(r.URL.Path, "/json/2/") {
		case "product.product/read":
			_, _ = w.Write([]byte(`[{"id":19,"display_name":"Hops Saaz","default_code":"BEER-HOP-SAAZ","standard_price":24.5,"purchase_ok":true}]`))
		case "res.partner/read":
			_, _ = w.Write([]byte(`[{"id":76,"name":"Hopperij Westland"}]`))
		case "purchase.order/search_read":
			_, _ = w.Write([]byte(`[]`))
		case "purchase.order/create":
			_ = json.NewDecoder(r.Body).Decode(&in)
			_, _ = w.Write([]byte(`[13]`))
		case "purchase.order/read":
			_, _ = w.Write([]byte(`[{"id":13,"name":"P00013","state":"draft","amount_total":49.0,"currency_id":[1,"EUR"],"company_id":[1,"Acme"],"partner_id":[76,"Hopperij Westland"],"order_line":[30]}]`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer odoo.Close()

	now := time.Now()
	exp := now.Unix() + 86400
	root := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xac}, 32))
	tom := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x70}, 32))
	shane, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keys := map[string]*ecdh.PrivateKey{}
	for _, id := range []string{"acme#shane", "acme#tom", "acme#audit", "acme#obs-leiestad", "acme#obs-hopperij", "acme#obs-robby"} {
		keys[id], _ = ecdh.P256().GenerateKey(rand.Reader)
	}
	kinds := policy.Builtin.Of(policy.OdooAdapter)
	okp := func(k ed25519.PrivateKey) registry.JWK {
		return registry.JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(k.Public().(ed25519.PublicKey))}
	}
	tomTok, _ := registry.Issue(registry.Entry{ID: "acme#tom", Org: "acme", Parent: "acme", Holder: okp(tom), Role: "director", Kinds: kinds, CeilingEUR: 25000, MayDelegate: true,
		Enc: encKeyOf(t, keys["acme#tom"]), IssuedAt: now.Unix() - 60, Expires: exp}, root)
	shaneTok, _ := registry.Issue(registry.Entry{ID: "acme#shane", Org: "acme", Parent: "acme#tom", Holder: p256JWK(shane), CredentialID: "Y3JlZA", Role: "buyer", Kinds: kinds,
		CeilingEUR: 5000, Enc: encKeyOf(t, keys["acme#shane"]), IssuedAt: now.Unix() - 60, Expires: exp}, tom)
	chain := []string{tomTok, shaneTok}
	observer := func(id string, signer ed25519.PrivateKey, parent, under, detail string, partners []int64) []string {
		e := registry.Entry{ID: id, Org: "acme", Parent: parent, Holder: okp(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(len(id))}, 32))), Role: registry.RoleObserver, Kinds: []string{},
			Enc: encKeyOf(t, keys[id]), Sees: &registry.Sees{Under: under, Detail: detail, Partners: partners, Until: exp}, IssuedAt: now.Unix() - 60, Expires: exp}
		tok, err := registry.Issue(e, signer)
		if err != nil {
			t.Fatal(err)
		}
		if parent == "acme" {
			return []string{tok}
		}
		return []string{tomTok, tok}
	}
	observers := [][]string{
		observer("acme#obs-leiestad", root, "acme", "acme", "summary", nil),
		observer("acme#obs-hopperij", tom, "acme#tom", "acme#tom", "full", []int64{76}),
		observer("acme#obs-robby", tom, "acme#tom", "acme#robby", "full", nil), // not on Shane's chain
	}

	var mu sync.Mutex
	var got []envelope
	var announced []map[string]any
	relayUp := true
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/api/registry/acme#shane":
			_ = json.NewEncoder(w).Encode(map[string]any{"chain": chain})
		case r.URL.Path == "/api/registry" && r.URL.Query().Get("role") == "observer":
			_ = json.NewEncoder(w).Encode(map[string]any{"chains": observers})
		case r.URL.Path == "/api/requests":
			var a map[string]any
			_ = json.NewDecoder(r.Body).Decode(&a)
			announced = append(announced, a)
			w.WriteHeader(201)
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
		cfg: config{Issuer: issuer, Store: filepath.Join(dir, "store"), Secrets: secrets, RelayURL: relay.URL, AuditEnc: encKeyOf(t, keys["acme#audit"]),
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
	opened := func() map[string]map[string]any {
		t.Helper()
		out := map[string]map[string]any{}
		for _, e := range got {
			raw, err := openReceipt(keys[e.Holder], e)
			if err != nil {
				t.Fatalf("%s for %s: %v", e.ID, e.Holder, err)
			}
			var p map[string]any
			_ = json.Unmarshal(raw, &p)
			// The gate's signature over the plaintext without it.
			sig, _ := hex.DecodeString(p["sig"].(string))
			var body map[string]any
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.UseNumber()
			_ = dec.Decode(&body)
			delete(body, "sig")
			signed, _ := canonical.Encode(body)
			if !ed25519.Verify(gateKey.Public().(ed25519.PublicKey), signed, sig) {
				t.Fatalf("%s for %s is not signed by the gate", e.ID, e.Holder)
			}
			if p["recipient"] != e.Holder || p["id"] != e.ID {
				t.Fatalf("the plaintext names %v/%v, the header %s/%s", p["recipient"], p["id"], e.Holder, e.ID)
			}
			out[e.Holder] = p
		}
		return out
	}
	// checkInclusion holds each step's proof to the checkpoint, and the checkpoint to the gate.
	checkInclusion := func(p map[string]any) {
		t.Helper()
		inc := p["inclusion"].(map[string]any)
		cpRaw, _ := json.Marshal(inc["checkpoint"])
		var cp gateway.Checkpoint
		_ = json.Unmarshal(cpRaw, &cp)
		if !gateway.VerifyCheckpoint(cp, gateKey.Public().(ed25519.PublicKey)) || float64(cp.TreeSize) != inc["tree_size"] {
			t.Fatalf("the checkpoint: %+v", cp)
		}
		root, _ := canonical.Untag(cp.Root)
		rootRaw, _ := hex.DecodeString(root)
		for i, st := range inc["steps"].([]any) {
			step := st.(map[string]any)
			lf := inc["leaves"].([]any)[i].(map[string]any)
			snap, _ := canonical.Untag(lf["snapshot"].(string))
			leaf, _ := evidence.Leaf(snap, lf["verdict"].(string))
			var proof [][]byte
			for _, h := range step["proof"].([]any) {
				b, _ := hex.DecodeString(h.(string))
				proof = append(proof, b)
			}
			if !merkle.VerifyInclusion(int(step["step"].(float64)), cp.TreeSize, merkle.LeafHash(leaf), proof, rootRaw) {
				t.Fatalf("step %v is not in the checkpoint", step["step"])
			}
		}
	}

	// A read without a mandate: refused; the receipt goes to Shane, Tom, the insurer and the
	// audit, not to Hopperij (no order of theirs) and not to the view of Robby.
	read := policy.Action{Kind: "odoo.read", Resource: "odoo:acme/purchase.order", Params: map[string]any{"model": "purchase.order"}}
	if out := post(s.submit, "/v1/submit", "", submitRequest{Agent: agent, Action: read}); out["verdict"] != "DENY" {
		t.Fatalf("%v", out)
	}
	s.flushReceipts()
	p := opened()
	if len(p) != 4 || p["acme#shane"] == nil || p["acme#tom"] == nil || p["acme#obs-leiestad"] == nil || p["acme#audit"] == nil {
		t.Fatalf("recipients: %v", keysOf(p))
	}
	if p["acme#tom"]["role"] != "manager" || p["acme#tom"]["detail"] != "full" || p["acme#shane"]["asked"] != false || len(p["acme#shane"]["records"].([]any)) != 3 {
		t.Fatalf("%v", p["acme#tom"])
	}
	sum := p["acme#obs-leiestad"]
	for _, k := range []string{"params", "records", "reason", "resource", "effect", "outcome", "chain", "authority"} {
		if _, ok := sum[k]; ok {
			t.Fatalf("a summary carries %s: %v", k, sum)
		}
	}
	if sum["reason_class"] != "refused" || sum["detail"] != "summary" || sum["seq"] != float64(1) {
		t.Fatalf("%v", sum)
	}
	checkInclusion(sum)
	checkInclusion(p["acme#shane"])

	// A draft on Shane's word for Hopperij's hops, with the relay away for a while: Hopperij
	// gets this one, in full; the envelopes wait and go once the relay is back.
	got, relayUp = nil, false
	draft := policy.Action{Kind: "odoo.order_draft", Resource: "odoo:acme/purchase.order", Params: map[string]any{"partner_id": float64(76), "lines": []any{map[string]any{"product_id": float64(19), "qty": float64(2)}}}}
	asked := post(s.submit, "/v1/submit", "", submitRequest{Agent: agent, Action: draft, Reason: "Saaz is below its reorder point",
		Reasoning: reasoning{"Saaz stock is 18 kg against a reorder point of 40.", "Hopperij Westland has the shortest lead-time."}})
	// The relay is told who, until when, and the bytes to sign; the request itself is sealed.
	for i := 0; i < 200; i++ {
		mu.Lock()
		n := len(announced)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	ann := announced[0]
	mu.Unlock()
	rawAnn, _ := json.Marshal(ann)
	for _, leak := range []string{"Hopperij", "Saaz", "partner_id", "24.5", "reorder", "lead-time", "odoo.order_draft"} {
		if strings.Contains(string(rawAnn), leak) {
			t.Fatalf("the announcement carries %q: %s", leak, rawAnn)
		}
	}
	if ann["holder"] != "acme#shane" || ann["payload"] == "" || len(ann["sealed"].([]any)) != 2 {
		t.Fatalf("%s", rawAnn)
	}
	for _, x := range ann["sealed"].([]any) {
		env := x.(map[string]any)
		if env["holder"] != "acme#shane" {
			continue
		}
		k, _ := hpke.NewDHKEMPrivateKey(keys["acme#shane"])
		enc, _ := base64.RawURLEncoding.DecodeString(env["enc"].(string))
		ct, _ := base64.RawURLEncoding.DecodeString(env["ct"].(string))
		aad, _ := canonical.Encode(map[string]any{"holder": "acme#shane", "pending": env["pending"], "exp": int64(env["exp"].(float64)), "kid": env["kid"]})
		rcpt, err := hpke.NewRecipient(enc, k, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte("bextrust request v1"))
		if err != nil {
			t.Fatal(err)
		}
		plain, err := rcpt.Open(aad, ct)
		if err != nil {
			t.Fatalf("the phone cannot open its request: %v", err)
		}
		var p map[string]any
		_ = json.Unmarshal(plain, &p)
		d := p["display"].(map[string]any)
		line := d["lines"].([]any)[0].(map[string]any)
		if d["partner"] != "Hopperij Westland" || line["code"] != "BEER-HOP-SAAZ" || line["unit_cost"] != "24.50" || p["reason"] != "Saaz is below its reorder point" || p["act"] != capability.ActDigest(draft) ||
			fmt.Sprint(p["reasoning"]) != "[Saaz stock is 18 kg against a reorder point of 40. Hopperij Westland has the shortest lead-time.]" {
			t.Fatalf("%s", plain)
		}
		var body map[string]any
		dec := json.NewDecoder(bytes.NewReader(plain))
		dec.UseNumber()
		_ = dec.Decode(&body)
		sig, _ := hex.DecodeString(body["sig"].(string))
		delete(body, "sig")
		signed, _ := canonical.Encode(body)
		if !ed25519.Verify(gateKey.Public().(ed25519.PublicKey), signed, sig) {
			t.Fatal("the request is not signed by the gate")
		}
	}
	payload, _ := base64.RawURLEncoding.DecodeString(asked["payload"].(string))
	if out := post(s.word, "/v1/pending/x/word", asked["pending"].(string), map[string]any{"capability": signWord(t, shane, payload), "chain": chain}); out["verdict"] != "ALLOW" {
		t.Fatalf("%v", out)
	}
	s.flushReceipts()
	waiting, _ := filepath.Glob(filepath.Join(s.outboxDir(), "env-*.json"))
	if len(got) != 0 || len(waiting) != 5 {
		t.Fatalf("with the relay away the envelopes wait: %d delivered, %d waiting", len(got), len(waiting))
	}
	mu.Lock()
	relayUp = true
	mu.Unlock()
	s.flushReceipts()
	p = opened()
	if len(p) != 5 || p["acme#obs-hopperij"] == nil {
		t.Fatalf("recipients: %v", keysOf(p))
	}
	hop := p["acme#obs-hopperij"]
	if hop["detail"] != "full" || hop["effect"].(map[string]any)["name"] != "P00013" || hop["authority"] == nil || hop["outcome"] == nil || hop["seq"] != float64(1) {
		t.Fatalf("%v", hop)
	}
	if p["acme#shane"]["seq"] != float64(2) || p["acme#shane"]["asked"] != true || p["acme#obs-leiestad"]["amount_total"] != "49.00" || p["acme#obs-leiestad"]["reason_class"] != "within grant" {
		t.Fatalf("%v %v", p["acme#shane"]["seq"], p["acme#obs-leiestad"])
	}
	// The agent's reasoning goes into the receipt of the step in full, and never into a summary.
	if r, _ := hop["reasoning"].([]any); len(r) != 2 || p["acme#shane"]["reasoning"] == nil {
		t.Fatalf("the receipt does not carry the reasoning: %v", hop)
	}
	if _, ok := p["acme#obs-leiestad"]["reasoning"]; ok {
		t.Fatalf("a summary carries the reasoning: %v", p["acme#obs-leiestad"])
	}
	checkInclusion(hop)
	// SEALED_SAMPLE_OUT=<path> writes these plaintexts for the anchor's checker to read
	// (gate-demo-box/anchor/verify, TestControlsSealedReceiptsCheckOut).
	if path := os.Getenv("SEALED_SAMPLE_OUT"); path != "" {
		var full, summary json.RawMessage
		for _, e := range got {
			raw, _ := openReceipt(keys[e.Holder], e)
			switch e.Holder {
			case "acme#obs-hopperij":
				full = raw
			case "acme#obs-leiestad":
				summary = raw
			}
		}
		out, _ := json.MarshalIndent(map[string]any{"about": "Two opened receipts from control's cmd/gateway/receipts_test.go: a supplier's full one and an insurer's summary.",
			"gate_key": hex.EncodeToString(gateKey.Public().(ed25519.PublicKey)), "root": hex.EncodeToString(root.Public().(ed25519.PublicKey)), "full": full, "summary": summary}, "", "  ")
		_ = os.WriteFile(path, append(out, '\n'), 0o644)
	}
	if left, _ := filepath.Glob(filepath.Join(s.outboxDir(), "*.json")); len(left) != 1 || filepath.Base(left[0]) != "seq.json" {
		t.Fatalf("the outbox keeps only its counts once delivered: %v", left)
	}

	// The gate serves the checkpoint every receipt names among its action ends, and proves the
	// log only grew between two of them.
	g, _ := s.gateway(agent)
	ends, err := g.ActionEnds(0, 100)
	if err != nil || len(ends) != 2 || ends[0].TreeSize != 3 || ends[1].TreeSize != 6 {
		t.Fatalf("%v %+v", err, ends)
	}
	if ends[1].Root != hop["inclusion"].(map[string]any)["checkpoint"].(map[string]any)["root"] {
		t.Fatal("the receipt's checkpoint is not the action end the gate serves")
	}
	proof, err := g.Consistency(3, 6)
	if err != nil {
		t.Fatal(err)
	}
	var raw [][]byte
	for _, h := range proof {
		b, _ := hex.DecodeString(h)
		raw = append(raw, b)
	}
	r3, _ := canonical.Untag(ends[0].Root)
	r6, _ := canonical.Untag(ends[1].Root)
	b3, _ := hex.DecodeString(r3)
	b6, _ := hex.DecodeString(r6)
	if !merkle.VerifyConsistency(3, 6, b3, b6, raw) {
		t.Fatal("the consistency proof does not hold")
	}
}

func keysOf(m map[string]map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// The agent's reasoning is kept as at most eight sentences of at most 300 characters, trimmed;
// anything else in its place is left out, never a reason to refuse the submission.
func TestTheReasoningIsKeptShortAndOnlyAsText(t *testing.T) {
	long := strings.Repeat("é", 310)
	var req submitRequest
	body := `{"agent":"a","reasoning":["  first  ", 7, "", {"x":1}, "` + long + `", "3", "4", "5", "6", "7", "8", "9"]}`
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatal(err)
	}
	r := req.Reasoning
	if len(r) != 8 || r[0] != "first" || r[1] != strings.Repeat("é", 300) || r[7] != "8" {
		t.Fatalf("%q", r)
	}
	for _, odd := range []string{`"one line"`, `{"a":"b"}`, `null`, `[1,2]`} {
		var req submitRequest
		if err := json.Unmarshal([]byte(`{"agent":"a","reasoning":`+odd+`}`), &req); err != nil || req.Reasoning != nil {
			t.Fatalf("%s: %v %q", odd, err, req.Reasoning)
		}
	}
	// It is written back as the list it was kept as.
	raw, _ := json.Marshal(submitRequest{Agent: "a", Reasoning: reasoning{"x"}})
	if !strings.Contains(string(raw), `"reasoning":["x"]`) {
		t.Fatalf("%s", raw)
	}
}
