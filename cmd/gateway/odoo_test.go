package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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
	"time"

	"github.com/abovebeyond-ai/control/canonical"
	"github.com/abovebeyond-ai/control/capability"
	"github.com/abovebeyond-ai/control/effects"
	"github.com/abovebeyond-ai/control/gateway"
	"github.com/abovebeyond-ai/control/log"
	"github.com/abovebeyond-ai/control/policy"
	"github.com/abovebeyond-ai/control/registry"
)

var odooParty = capability.Party{RPID: "bextrust.abovebeyond.ai", Origins: []string{"https://bextrust.abovebeyond.ai"}}

// signWord is what the phone does: sign the challenge of these payload bytes with the passkey,
// and what the relay does: put the parts together as a wa1 token.
func signWord(t *testing.T, key *ecdsa.PrivateKey, raw []byte) string {
	t.Helper()
	rp := sha256.Sum256([]byte(odooParty.RPID))
	auth := append(append([]byte{}, rp[:]...), 0x05, 0, 0, 0, 9)
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": capability.Challenge(raw), "origin": odooParty.Origins[0]})
	cdHash := sha256.Sum256(cd)
	signed := sha256.Sum256(append(append([]byte{}, auth...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, key, signed[:])
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return capability.PasskeyPrefix + "." + enc(raw) + "." + enc(auth) + "." + enc(cd) + "." + enc(sig)
}

func p256JWK(k *ecdsa.PrivateKey) registry.JWK {
	raw, _ := k.PublicKey.Bytes()
	return registry.JWK{Kty: "EC", Crv: "P-256", X: base64.RawURLEncoding.EncodeToString(raw[1:33]), Y: base64.RawURLEncoding.EncodeToString(raw[33:])}
}

// The demo end to end, Odoo faked: Acme's root signs Tom, Tom signs Elise's passkey. The agent
// reads under a mandate Elise signed; a draft waits for her word on that one act, and is
// performed when it comes, refused when she says no, and refused when the ten minutes pass.
// Every one of them is three records, and the Odoo key never leaves the gateway.
func TestTheOdooGateReadsUnderAMandateAndWritesOnAWord(t *testing.T) {
	var mu sync.Mutex
	odooCalls := []string{}
	odoo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "bearer odoo-secret" {
			w.WriteHeader(401)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/json/2/")
		odooCalls = append(odooCalls, path)
		switch path {
		case "purchase.order/search_read":
			_, _ = w.Write([]byte(`[{"id":7,"name":"P00007","state":"draft","amount_total":1222.5}]`))
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
	var announced []map[string]any
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got map[string]any
		_ = json.NewDecoder(r.Body).Decode(&got)
		mu.Lock()
		if r.URL.Path == "/api/requests" {
			announced = append(announced, got)
		}
		mu.Unlock()
		w.WriteHeader(201)
	}))
	defer relay.Close()

	now := time.Now()
	root := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xac}, 32))
	tom := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x70}, 32))
	elise, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	stranger, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kinds := policy.Builtin.Of(policy.OdooAdapter)
	tomTok, _ := registry.Issue(registry.Entry{ID: "acme#tom", Org: "acme", Parent: "acme", Holder: registry.JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(tom.Public().(ed25519.PublicKey))},
		Role: "director", Kinds: kinds, CeilingEUR: 50000, MayDelegate: true, IssuedAt: now.Unix() - 60, Expires: now.Unix() + 86400}, root)
	eliseTok, _ := registry.Issue(registry.Entry{ID: "acme#elise", Org: "acme", Parent: "acme#tom", Holder: p256JWK(elise), CredentialID: "Y3JlZA",
		Role: "buyer", Kinds: kinds, CeilingEUR: 5000, IssuedAt: now.Unix() - 60, Expires: now.Unix() + 86400}, tom)
	chain := []string{tomTok, eliseTok}

	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets")
	_ = os.MkdirAll(secrets, 0o700)
	_ = os.WriteFile(filepath.Join(secrets, "odoo-key-acme"), []byte("odoo-secret\n"), 0o600)
	store, _ := log.Open(filepath.Join(dir, "store"))
	agent := "did:web:bextrust.abovebeyond.ai:acme#procurement-agent"
	issuer := "https://gate.example/control"
	s := &service{key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)), store: store, effects: effects.Registry{}, gateways: map[string]*gateway.Gateway{},
		cfg: config{Issuer: issuer, Store: filepath.Join(dir, "store"), Secrets: secrets, RelayURL: relay.URL,
			Orgs: map[string]string{"acme": hex.EncodeToString(root.Public().(ed25519.PublicKey))}, Passkey: odooParty,
			Agents: map[string]struct {
				Grant policy.Grant `json:"grant"`
			}{agent: {Grant: policy.Grant{Principal: "acme", Kinds: kinds, Resources: []string{"odoo:acme/*"}, Org: "acme", Asks: "acme#elise"}}}}}
	s.effects.Add(effects.Odoo{SecretsDir: secrets, Instances: map[string]effects.OdooInstance{"acme": {Base: odoo.URL, DB: "acme"}}})

	call := func(handler http.HandlerFunc, path, id string, body any) (int, map[string]any) {
		raw, _ := json.Marshal(body)
		method := "POST"
		if body == nil {
			method = "GET"
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.SetPathValue("id", id)
		rec := httptest.NewRecorder()
		handler(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	submit := func(r submitRequest) (int, map[string]any) {
		r.Agent = agent
		return call(s.submit, "/v1/submit", "", r)
	}
	read := policy.Action{Kind: "odoo.read", Resource: "odoo:acme/purchase.order", Params: map[string]any{"model": "purchase.order", "domain": []any{[]any{"state", "=", "draft"}}}}
	draft := policy.Action{Kind: "odoo.order_draft", Resource: "odoo:acme/purchase.order", Params: map[string]any{"partner_id": float64(8), "lines": []any{map[string]any{"product_id": float64(19), "qty": float64(2)}}}}

	// No mandate, no read.
	if code, out := submit(submitRequest{Action: read}); code != 200 || out["verdict"] != "DENY" || !strings.Contains(out["reason"].(string), "no mandate from a person of acme") {
		t.Fatalf("%d %v", code, out)
	}
	// A mandate for reads, signed on Elise's phone.
	mandate, _ := canonical.Encode(capability.Payload{Issuer: "acme#elise", Subject: agent, Audience: issuer, Task: capability.Task{Project: "acme"},
		Kinds: []string{"odoo.read"}, Resources: []string{"odoo:acme/*"}, IssuedAt: now.Unix(), Expires: now.Add(8 * time.Hour).Unix(), ID: "mandate-1"})
	mandateTok := signWord(t, elise, mandate)
	code, out := submit(submitRequest{Action: read, Capability: mandateTok, Chain: chain})
	if code != 200 || out["verdict"] != "ALLOW" {
		t.Fatalf("%d %v", code, out)
	}
	effect := out["effect"].(map[string]any)
	if len(effect["records"].([]any)) != 1 || effect["detail"].(map[string]any)["count"] != float64(1) {
		t.Fatalf("the rows come back to the hand: %v", effect)
	}
	step := int(out["step"].(float64))
	var kept map[string]any
	if found, _ := store.Attachment(agent, step+1, "outcome", &kept); !found || strings.Contains(mustJSON(kept), "P00007") {
		t.Fatalf("the rows stay off the record: %v", kept)
	}
	if found, _ := store.Attachment(agent, step, "capability", &kept); !found || kept["capability"] != mandateTok || len(kept["chain"].([]any)) != 2 {
		t.Fatalf("the word and its chain are kept beside the record: %v", kept)
	}
	records, _ := store.Records(agent)
	c := records[step].Claims()
	if c["initiating_user"] != "acme#elise" || c["control_chain"].(map[string]any)["role"] != "buyer" || c["control_task"].(map[string]any)["iss"] != "acme#elise" {
		t.Fatalf("the record names the person and the chain: %v", c)
	}
	// The mandate is a period, not an act: it does not carry a write.
	if code, out := submit(submitRequest{Action: draft, Capability: mandateTok, Chain: chain}); out["verdict"] != "DENY" || !strings.Contains(out["reason"].(string), "does not cover") {
		t.Fatalf("%d %v", code, out)
	}
	// A model off the list is refused on its face, without asking anyone.
	if code, out := submit(submitRequest{Action: policy.Action{Kind: "odoo.order_cancel", Resource: "odoo:acme/res.partner", Params: map[string]any{"order": float64(1)}}}); code != 200 || out["verdict"] != "DENY" {
		t.Fatalf("%d %v", code, out)
	}

	// A draft without a word waits for Elise's.
	ask := func() map[string]any {
		t.Helper()
		code, asked := submit(submitRequest{Action: draft})
		if code != 202 || asked["holder"] != "acme#elise" || asked["challenge"] == "" || asked["action"].(map[string]any)["kind"] != "odoo.order_draft" {
			t.Fatalf("%d %v", code, asked)
		}
		return asked
	}
	asked := ask()
	raw, _ := base64.RawURLEncoding.DecodeString(asked["payload"].(string))
	var payload capability.Payload
	_ = json.Unmarshal(raw, &payload)
	if payload.Act != capability.ActDigest(draft) || payload.Expires-payload.IssuedAt != 600 || capability.Challenge(raw) != asked["challenge"] {
		t.Fatalf("the payload names the act for ten minutes: %+v", payload)
	}
	id := asked["pending"].(string)
	if code, st := call(s.pendingState, "/v1/pending/"+id, id, nil); code != 200 || st["state"] != "waiting" || st["record"] != nil {
		t.Fatalf("%d %v", code, st)
	}
	// A stranger's passkey is no word of Elise's: refused on the record, and the write decided.
	if code, out := call(s.word, "/v1/pending/x/word", id, map[string]any{"capability": signWord(t, stranger, raw), "chain": chain}); code != 200 || out["verdict"] != "DENY" || !strings.Contains(out["reason"].(string), "does not verify") {
		t.Fatalf("%d %v", code, out)
	}
	if code, st := call(s.pendingState, "/v1/pending/"+id, id, nil); st["state"] != "done" || st["record"].(map[string]any)["verdict"] != "DENY" {
		t.Fatalf("%d %v", code, st)
	}
	// Asked again, Elise signs on her phone.
	asked = ask()
	raw, _ = base64.RawURLEncoding.DecodeString(asked["payload"].(string))
	id = asked["pending"].(string)
	wordTok := signWord(t, elise, raw)
	code, out = call(s.word, "/v1/pending/x/word", id, map[string]any{"capability": wordTok, "chain": chain})
	if code != 200 || out["verdict"] != "ALLOW" || out["effect"] != nil {
		t.Fatalf("the relay hears the verdict, not the effect: %d %v", code, out)
	}
	// The agent reads the whole answer from the gate.
	if _, st := call(s.pendingState, "/v1/pending/"+id, id, nil); st["record"].(map[string]any)["effect"].(map[string]any)["ok"] != true || st["record"].(map[string]any)["effect"].(map[string]any)["detail"].(map[string]any)["ceiling_eur"] != float64(5000) {
		t.Fatalf("%v", st)
	}
	records, _ = store.Records(agent)
	c = records[int(out["step"].(float64))].Claims()
	if c["initiating_user"] != "acme#elise" || c["control_word"].(map[string]any)["spent"] != true {
		t.Fatalf("the word is named and spent: %v", c)
	}
	// The ceiling is the gateway's addition: the judged parameters are the hand's own.
	want, _ := canonical.Digest(draft.Params)
	if c["control_params"] != canonical.Tag(want) {
		t.Fatalf("the judged parameters changed: %v", c["control_params"])
	}
	if code, st := call(s.pendingState, "/v1/pending/"+id, id, nil); st["state"] != "done" || st["record"].(map[string]any)["verdict"] != "ALLOW" {
		t.Fatalf("%d %v", code, st)
	}
	// The same word twice decides nothing more.
	if code, _ := call(s.word, "/v1/pending/x/word", id, map[string]any{"capability": wordTok, "chain": chain}); code != 409 {
		t.Fatalf("a decided write: %d", code)
	}
	// Nor does it carry the same act submitted again: a word is spent once.
	if code, out := submit(submitRequest{Action: draft, Capability: wordTok, Chain: chain}); out["verdict"] != "DENY" || !strings.Contains(out["reason"].(string), "already spent") {
		t.Fatalf("%d %v", code, out)
	}

	// Elise says no.
	asked = ask()
	id = asked["pending"].(string)
	if code, out := call(s.refuse, "/v1/pending/x/refuse", id, map[string]any{"by": "acme#elise"}); code != 200 || out["verdict"] != "DENY" || out["reason"] != "refused by acme#elise" {
		t.Fatalf("%d %v", code, out)
	}
	if _, st := call(s.pendingState, "/v1/pending/"+id, id, nil); st["state"] != "refused" {
		t.Fatalf("%v", st)
	}
	// Elise does not answer in time.
	asked = ask()
	id = asked["pending"].(string)
	s.sweepOnce(time.Now().Add(wordWindow + time.Second))
	if _, st := call(s.pendingState, "/v1/pending/"+id, id, nil); st["state"] != "expired" || !strings.Contains(st["record"].(map[string]any)["reason"].(string), "no word from acme#elise") {
		t.Fatalf("%v", st)
	}

	mu.Lock()
	defer mu.Unlock()
	creates := 0
	for _, c := range odooCalls {
		if c == "purchase.order/create" {
			creates++
		}
	}
	if creates != 1 {
		t.Fatalf("one draft was created, for the one word that held: %v", odooCalls)
	}
	// Announcements go out in the background; give them a moment.
	for i := 0; i < 100 && len(announced) < 4; i++ {
		mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		mu.Lock()
	}
	if len(announced) != 4 || announced[0]["holder"] != "acme#elise" || announced[0]["payload"] == "" {
		t.Fatalf("the relay is told of every word wanted: %v", announced)
	}
	records, _ = store.Records(agent)
	if len(records)%3 != 0 {
		t.Fatalf("every action is three records: %d", len(records))
	}
	for i := 0; i < len(records); i += 3 {
		if records[i].Claims()["control_phase"] != "request" || records[i+2].Claims()["control_phase"] != "result" {
			t.Fatalf("record %d: %v", i, records[i].Claims()["control_phase"])
		}
	}
}

// A grant that listens to an organisation needs its root pinned and the passkey's party named,
// or the gateway does not start.
func TestAnOrgGrantNeedsItsRootAndParty(t *testing.T) {
	c := config{Agents: map[string]struct {
		Grant policy.Grant `json:"grant"`
	}{"a": {Grant: policy.Grant{Org: "acme"}}}}
	if _, err := c.orgKeys(); err == nil || !strings.Contains(err.Error(), "no root key") {
		t.Fatalf("%v", err)
	}
	c.Orgs = map[string]string{"acme": strings.Repeat("ab", 32)}
	if _, err := c.orgKeys(); err == nil || !strings.Contains(err.Error(), "rp_id") {
		t.Fatalf("%v", err)
	}
	c.Passkey = odooParty
	if _, err := c.orgKeys(); err != nil {
		t.Fatal(err)
	}
	c.Orgs["acme"] = "nothex"
	if _, err := c.orgKeys(); err == nil {
		t.Fatal("a root that is no key")
	}
}

func mustJSON(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

// A buyer with a daily allowance: the first draft fits and is counted, the record names the
// allowance and the day as it stood; the second would take the day over and Odoo is not asked
// to create it. The day's sum is kept in the store, so a gateway started again knows it.
func TestADailyAllowanceHoldsAcrossDrafts(t *testing.T) {
	var mu sync.Mutex
	creates := 0
	odoo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch strings.TrimPrefix(r.URL.Path, "/json/2/") {
		case "product.product/read":
			_, _ = w.Write([]byte(`[{"id":19,"display_name":"Corner Desk","standard_price":600.0,"purchase_ok":true}]`))
		case "purchase.order/create":
			creates++
			_, _ = w.Write([]byte(`[13]`))
		case "purchase.order/read":
			_, _ = w.Write([]byte(`[{"id":13,"name":"P00013","state":"draft","amount_total":1200.0,"currency_id":[1,"EUR"],"company_id":[1,"Acme"],"order_line":[30]}]`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer odoo.Close()
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(201) }))
	defer relay.Close()

	now := time.Now()
	root := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xac}, 32))
	tom := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x70}, 32))
	shane, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kinds := policy.Builtin.Of(policy.OdooAdapter)
	tomTok, _ := registry.Issue(registry.Entry{ID: "acme#tom", Org: "acme", Parent: "acme", Holder: registry.JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(tom.Public().(ed25519.PublicKey))},
		Role: "director", Kinds: kinds, CeilingEUR: 25000, MayDelegate: true, IssuedAt: now.Unix() - 60, Expires: now.Unix() + 86400}, root)
	shaneTok, _ := registry.Issue(registry.Entry{ID: "acme#shane", Org: "acme", Parent: "acme#tom", Holder: p256JWK(shane), Role: "buyer", Kinds: kinds,
		CeilingEUR: 5000, DailyEUR: 2000, IssuedAt: now.Unix() - 60, Expires: now.Unix() + 86400}, tom)
	chain := []string{tomTok, shaneTok}

	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets")
	_ = os.MkdirAll(secrets, 0o700)
	_ = os.WriteFile(filepath.Join(secrets, "odoo-key-acme"), []byte("odoo-secret\n"), 0o600)
	store, _ := log.Open(filepath.Join(dir, "store"))
	agent := "did:web:bextrust.abovebeyond.ai:acme#procurement-agent"
	issuer := "https://gate.example/control"
	s := &service{key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)), store: store, effects: effects.Registry{}, gateways: map[string]*gateway.Gateway{},
		cfg: config{Issuer: issuer, Store: filepath.Join(dir, "store"), Secrets: secrets, RelayURL: relay.URL,
			Orgs: map[string]string{"acme": hex.EncodeToString(root.Public().(ed25519.PublicKey))}, Passkey: odooParty,
			Agents: map[string]struct {
				Grant policy.Grant `json:"grant"`
			}{agent: {Grant: policy.Grant{Principal: "acme", Kinds: kinds, Resources: []string{"odoo:acme/*"}, Org: "acme", Asks: "acme#shane"}}}}}
	s.effects.Add(effects.Odoo{SecretsDir: secrets, Instances: map[string]effects.OdooInstance{"acme": {Base: odoo.URL, DB: "acme"}}})

	draft := policy.Action{Kind: "odoo.order_draft", Resource: "odoo:acme/purchase.order", Params: map[string]any{"partner_id": float64(8), "lines": []any{map[string]any{"product_id": float64(19), "qty": float64(2)}}}}
	approve := func() map[string]any {
		t.Helper()
		raw, _ := json.Marshal(submitRequest{Agent: agent, Action: draft})
		rec := httptest.NewRecorder()
		s.submit(rec, httptest.NewRequest("POST", "/v1/submit", bytes.NewReader(raw)))
		var asked map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &asked)
		payload, _ := base64.RawURLEncoding.DecodeString(asked["payload"].(string))
		id := asked["pending"].(string)
		body, _ := json.Marshal(map[string]any{"capability": signWord(t, shane, payload), "chain": chain})
		req := httptest.NewRequest("POST", "/v1/pending/x/word", bytes.NewReader(body))
		req.SetPathValue("id", id)
		rec = httptest.NewRecorder()
		s.word(rec, req)
		// The agent's view: the whole record, from the gate.
		st := httptest.NewRequest("GET", "/v1/pending/"+id, nil)
		st.SetPathValue("id", id)
		rec = httptest.NewRecorder()
		s.pendingState(rec, st)
		var out struct {
			Record map[string]any `json:"record"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out.Record
	}

	out := approve()
	detail := out["effect"].(map[string]any)["detail"].(map[string]any)
	if out["verdict"] != "ALLOW" || out["effect"].(map[string]any)["ok"] != true || detail["daily_eur"] != float64(2000) || detail["spent_today_eur"] != "1200.00" {
		t.Fatalf("%v", out)
	}
	records, _ := store.Records(agent)
	cc := records[int(out["step"].(float64))].Claims()["control_chain"].(map[string]any)
	if fmt.Sprint(cc["daily_eur"]) != "2000" || cc["spent_today_eur"] != "0.00" || fmt.Sprint(cc["ceiling_eur"]) != "5000" {
		t.Fatalf("the record names the allowance and the day before the act: %v", cc)
	}

	out = approve()
	if out["verdict"] != "ALLOW" || out["effect"].(map[string]any)["ok"] != false || !strings.Contains(out["effect"].(map[string]any)["error"].(string), "over acme#shane's daily allowance: EUR 2400.00 of 2000.00") {
		t.Fatalf("the second draft goes over the day: %v", out)
	}
	records, _ = store.Records(agent)
	if cc := records[int(out["step"].(float64))].Claims()["control_chain"].(map[string]any); cc["spent_today_eur"] != "1200.00" {
		t.Fatalf("the day as it stood: %v", cc)
	}
	again, _ := log.Open(filepath.Join(dir, "store"))
	if n, _ := again.SpentOn("acme#shane", log.AllowanceDay(time.Now())); n != 120000 {
		t.Fatalf("the day is kept: %d", n)
	}
	mu.Lock()
	defer mu.Unlock()
	if creates != 1 {
		t.Fatalf("Odoo created %d orders; one fits the day", creates)
	}
}

// Shane enrolled a new phone: Tom revoked the entry of the old passkey. A mandate the old passkey
// signed no longer reads, whatever chain the agent presents; one signed by the new passkey does.
func TestARevokedPasskeyNoLongerSpeaks(t *testing.T) {
	odoo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":7,"name":"P00007","state":"draft","amount_total":12.0}]`))
	}))
	defer odoo.Close()
	now := time.Now()
	root := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xac}, 32))
	tom := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x70}, 32))
	oldPhone, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	newPhone, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kinds := policy.Builtin.Of(policy.OdooAdapter)
	tomTok, _ := registry.Issue(registry.Entry{ID: "acme#tom", Org: "acme", Parent: "acme", Holder: registry.JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(tom.Public().(ed25519.PublicKey))},
		Role: "director", Kinds: kinds, CeilingEUR: 25000, MayDelegate: true, IssuedAt: now.Unix() - 60, Expires: now.Unix() + 86400}, root)
	entry := func(k *ecdsa.PrivateKey, cred string) string {
		tok, _ := registry.Issue(registry.Entry{ID: "acme#shane", Org: "acme", Parent: "acme#tom", Holder: p256JWK(k), CredentialID: cred, Role: "buyer", Kinds: kinds,
			CeilingEUR: 5000, IssuedAt: now.Unix() - 60, Expires: now.Unix() + 86400}, tom)
		return tok
	}
	oldTok, newTok := entry(oldPhone, "b2xk"), entry(newPhone, "bmV3")
	rv, _ := registry.IssueRevocation(registry.Revocation{Revokes: registry.EntryDigest(oldTok), ID: "acme#shane", By: "acme#tom", IssuedAt: now.Unix()}, tom)

	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets")
	_ = os.MkdirAll(secrets, 0o700)
	_ = os.WriteFile(filepath.Join(secrets, "odoo-key-acme"), []byte("k\n"), 0o600)
	store, _ := log.Open(filepath.Join(dir, "store"))
	agent := "did:web:bextrust.abovebeyond.ai:acme#procurement-agent"
	issuer := "https://gate.example/control"
	s := &service{key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)), store: store, effects: effects.Registry{}, gateways: map[string]*gateway.Gateway{}, revoked: newRevokedList(time.Now),
		cfg: config{Issuer: issuer, Store: filepath.Join(dir, "store"), Secrets: secrets,
			Orgs: map[string]string{"acme": hex.EncodeToString(root.Public().(ed25519.PublicKey))}, Passkey: odooParty,
			Agents: map[string]struct {
				Grant policy.Grant `json:"grant"`
			}{agent: {Grant: policy.Grant{Principal: "acme", Kinds: kinds, Resources: []string{"odoo:acme/*"}, Org: "acme", Asks: "acme#shane"}}}}}
	s.effects.Add(effects.Odoo{SecretsDir: secrets, Instances: map[string]effects.OdooInstance{"acme": {Base: odoo.URL, DB: "acme"}}})
	s.revoked.registry[registry.EntryDigest(oldTok)] = rv
	read := policy.Action{Kind: "odoo.read", Resource: "odoo:acme/purchase.order", Params: map[string]any{"model": "purchase.order"}}
	mandate := func(k *ecdsa.PrivateKey, jti string) string {
		raw, _ := canonical.Encode(capability.Payload{Issuer: "acme#shane", Subject: agent, Audience: issuer, Task: capability.Task{Project: "acme"},
			Kinds: []string{"odoo.read"}, Resources: []string{"odoo:acme/*"}, IssuedAt: now.Unix(), Expires: now.Add(time.Hour).Unix(), ID: jti})
		return signWord(t, k, raw)
	}
	submit := func(word, entryTok string) map[string]any {
		raw, _ := json.Marshal(submitRequest{Agent: agent, Action: read, Capability: word, Chain: []string{tomTok, entryTok}})
		rec := httptest.NewRecorder()
		s.submit(rec, httptest.NewRequest("POST", "/v1/submit", bytes.NewReader(raw)))
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}
	if out := submit(mandate(oldPhone, "m-old"), oldTok); out["verdict"] != "DENY" || !strings.Contains(fmt.Sprint(out["reason"]), "revoked by acme#tom") {
		t.Fatalf("the old phone's mandate: %v", out)
	}
	if out := submit(mandate(newPhone, "m-new"), newTok); out["verdict"] != "ALLOW" {
		t.Fatalf("the new phone's mandate: %v", out)
	}
}
