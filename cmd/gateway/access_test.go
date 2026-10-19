package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/abovebeyond-ai/control/canonical"
	"github.com/abovebeyond-ai/control/effects"
	"github.com/abovebeyond-ai/control/gateway"
	"github.com/abovebeyond-ai/control/log"
	"github.com/abovebeyond-ai/control/policy"
	"github.com/abovebeyond-ai/control/registry"
)

func hashHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// call2 sends one request through the gateway's routes, with a bearer token when one is given.
func call2(mux http.Handler, method, path, token string, body any) (int, map[string]any, string) {
	var rd *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Body.String()
}

func veraPub() ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)).Public().(ed25519.PublicKey)
}

// readRig is a dry gateway with one action on its record, a client, a relay and a reader token.
func readRig(t *testing.T, mutate func(*config)) (*service, http.Handler, string) {
	t.Helper()
	dir := t.TempDir()
	store, _ := log.Open(filepath.Join(dir, "store"))
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32))
	agent := "did:webvh:QmTest:example.org#agent-fix"
	cfg := config{Issuer: "x", Store: filepath.Join(dir, "store"), Dry: true,
		ClientTokenSHA256: hashHex("client-secret"), RelayClientTokenSHA256: hashHex("relay-secret"),
		Readers: map[string]string{"acme-console": hashHex("reader-secret")},
		Agents: map[string]struct {
			Grant policy.Grant `json:"grant"`
		}{agent: {Grant: policy.Grant{Principal: "did:webvh:QmTest:example.org", Kinds: []string{"pull.open"}, Resources: []string{"x/y"}, MaxPerKind: 1}}}}
	if mutate != nil {
		mutate(&cfg)
	}
	if err := cfg.checkDoors(); err != nil {
		t.Fatal(err)
	}
	s := &service{key: key, store: store, effects: effects.Registry{}, gateways: map[string]*gateway.Gateway{}, cfg: cfg}
	mux := s.routes(veraPub())
	body := submitRequest{Run: "r", Agent: agent, Action: policy.Action{Kind: "pull.open", Resource: "x/y", Params: map[string]any{"branch": "b", "base": "main"}}}
	if code, out, _ := call2(mux, "POST", "/v1/submit", "client-secret", body); code != 200 {
		t.Fatalf("submit: %d %v", code, out)
	}
	return s, mux, agent
}

// Record bodies, attachments, proofs and the policy are the organisation's: without a reader's
// token they are refused, whoever asks, the client and the relay included.
func TestARecordReadWithoutTheReaderTokenIsRefused(t *testing.T) {
	s, mux, agent := readRig(t, nil)
	a := url.QueryEscape(agent)
	reads := []string{"/v1/records?agent=" + a, "/v1/attachment?agent=" + a + "&step=0&name=action", "/v1/attachment?agent=" + a + "&step=1&name=outcome", "/v1/proof?agent=" + a + "&step=0", "/v1/policy"}
	for _, path := range reads {
		for _, token := range []string{"", "client-secret", "relay-secret", "reader-secret-not"} {
			if code, _, body := call2(mux, "GET", path, token, nil); code != 401 || strings.Contains(body, "pull.open") {
				t.Fatalf("%s with %q: %d %s", path, token, code, body)
			}
		}
	}
	for _, path := range reads[:4] {
		if code, _, body := call2(mux, "GET", path, "reader-secret", nil); code != 200 {
			t.Fatalf("%s for the reader: %d %s", path, code, body)
		}
	}
	// Refused and served reads are both on the access record, the served ones by reader.
	raw, _ := readFile(filepath.Join(s.cfg.Store, "access.jsonl"))
	if !strings.Contains(raw, `"refused":true`) || !strings.Contains(raw, `"reader":"acme-console"`) {
		t.Fatalf("access record: %s", raw)
	}

	// In Confidential Space the records are closed even when no reader is named.
	sCS, _, agent2 := readRig(t, func(c *config) { c.Readers = nil })
	sCS.cfg.Attestation = attestationCS
	muxCS := sCS.routes(veraPub())
	if code, _, _ := call2(muxCS, "GET", "/v1/records?agent="+url.QueryEscape(agent2), "client-secret", nil); code != 401 {
		t.Fatalf("records in confidential space without readers: %d", code)
	}
	// A reader whose token is the client token is refused at start: the operator sets that one.
	bad := config{ClientTokenSHA256: hashHex("c"), Readers: map[string]string{"x": hashHex("c")}}
	if err := bad.checkDoors(); err == nil {
		t.Fatal("a reader with the client token was taken")
	}
	if err := (config{ClientTokenSHA256: hashHex("c"), RelayClientTokenSHA256: hashHex("c")}).checkDoors(); err == nil {
		t.Fatal("a relay with the client token was taken")
	}
}

func readFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	return string(raw), err
}

// What the anchor reads stays open to anyone, with no token: the key, the attestation, the
// agents, the checkpoints and the consistency proofs (gate-demo-box anchor/gate.go, service.go).
func TestTheAnchorsRoutesStayOpen(t *testing.T) {
	for _, attestation := range []string{"", attestationCS} {
		s, _, agent := readRig(t, nil)
		s.cfg.Attestation = attestation
		mux := s.routes(veraPub())
		a := url.QueryEscape(agent)
		_, cp, _ := call2(mux, "GET", "/v1/checkpoint?agent="+a, "", nil)
		size, _ := cp["tree_size"].(float64)
		if size < 3 {
			t.Fatalf("checkpoint: %v", cp)
		}
		for _, path := range []string{"/v1/key", "/v1/agents", "/v1/checkpoint?agent=" + a, "/v1/checkpoints?agent=" + a + "&after=0",
			"/v1/consistency?agent=" + a + "&m=1&n=" + strconv.Itoa(int(size)), "/v1/attestations"} {
			if code, _, body := call2(mux, "GET", path, "", nil); code != 200 {
				t.Fatalf("%q %s: %d %s", attestation, path, code, body)
			}
		}
		// A software gateway has no attestation to serve: 404, not a closed door.
		if code, _, _ := call2(mux, "GET", "/v1/attestation", "", nil); code == 401 || code == 403 {
			t.Fatalf("attestation: %d", code)
		}
		if code, _, _ := call2(mux, "GET", "/v1/attestation?digest=sha-256:"+strings.Repeat("0", 64), "", nil); code == 401 || code == 403 {
			t.Fatalf("attestation by digest: %d", code)
		}
	}
}

// relayRig is the Odoo gate with a client token for the agent, a token for the relay and a
// reader, its holder's chain carrying an encryption key so refusals can be sealed to it.
func relayRig(t *testing.T) (*stateRig, *service, http.Handler, *ecdh.PrivateKey) {
	r := newStateRig(t)
	enc, _ := ecdh.P256().GenerateKey(rand.Reader)
	now := time.Now()
	shaneTok, err := registry.Issue(registry.Entry{ID: "acme#shane", Org: "acme", Parent: "acme#tom", Holder: p256JWK(r.shane), Role: "buyer", Kinds: policy.Builtin.Of(policy.OdooAdapter),
		CeilingEUR: 5000, Enc: encKeyOf(t, enc), IssuedAt: now.Unix() - 60, Expires: now.Unix() + 86400}, r.tom)
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.chain = []string{r.chain[0], shaneTok}
	r.mu.Unlock()
	s := r.gate()
	s.cfg.ClientTokenSHA256 = hashHex("agent-secret")
	s.cfg.RelayClientTokenSHA256 = hashHex("relay-secret")
	s.cfg.Readers = map[string]string{"acme-console": hashHex("reader-secret")}
	return r, s, s.routes(veraPub()), enc
}

// The relay's token posts a word, a refusal and an adjustment and reads a waiting write's
// state; it cannot draft, read the params, the record, the effect or an amount.
func TestTheRelayTokenCannotReadParamsOrRecordsOrDraft(t *testing.T) {
	r, s, mux, _ := relayRig(t)
	// It cannot submit (draft) or mint a read token.
	raw, _ := json.Marshal(submitRequest{Agent: r.agent, Action: r.draft()})
	var draft map[string]any
	_ = json.Unmarshal(raw, &draft)
	if code, _, _ := call2(mux, "POST", "/v1/submit", "relay-secret", draft); code != 401 {
		t.Fatalf("the relay drafted: %d", code)
	}
	if code, _, _ := call2(mux, "GET", "/v1/github/read-token?owner=x", "relay-secret", nil); code != 401 {
		t.Fatalf("the relay minted: %d", code)
	}
	// The agent drafts with its own token and is answered what to have signed.
	code, asked, _ := call2(mux, "POST", "/v1/submit", "agent-secret", draft)
	if code != 202 {
		t.Fatalf("%d %v", code, asked)
	}
	id := asked["pending"].(string)
	payload, _ := base64.RawURLEncoding.DecodeString(asked["payload"].(string))
	waitFor(t, "the request announced", func() bool { return r.announcedFor(id) == 1 })

	// Waiting: the relay reads the state and nothing else.
	code, st, body := call2(mux, "GET", "/v1/pending/"+id, "relay-secret", nil)
	if code != 200 || st["state"] != "waiting" || len(st) != 1 {
		t.Fatalf("%d %s", code, body)
	}
	if code, _, _ := call2(mux, "GET", "/v1/pending/"+id, "", nil); code != 401 {
		t.Fatalf("no token read a pending write: %d", code)
	}
	// The word through the relay's door: answered as the relay is told, no effect.
	word := map[string]any{"capability": signWord(t, r.shane, payload), "chain": r.chain}
	code, out, body := call2(mux, "POST", "/v1/pending/"+id+"/word", "relay-secret", word)
	if code != 200 || out["verdict"] != "ALLOW" || out["effect"] != nil || out["token"] != nil {
		t.Fatalf("%d %s", code, body)
	}
	// Decided: the relay still reads the state only; the agent reads the record and effect.
	code, st, body = call2(mux, "GET", "/v1/pending/"+id, "relay-secret", nil)
	if code != 200 || st["state"] != "done" || len(st) != 1 || strings.Contains(body, "P00") || strings.Contains(body, "1200") {
		t.Fatalf("%d %s", code, body)
	}
	_, st, _ = call2(mux, "GET", "/v1/pending/"+id, "agent-secret", nil)
	if rec, _ := st["record"].(map[string]any); rec == nil || rec["effect"] == nil {
		t.Fatalf("the agent lost its record: %v", st)
	}
	// A second word, refusal or adjustment on the decided write answers no record either.
	for _, p := range []struct {
		path string
		body any
	}{{"/word", word}, {"/refuse", map[string]any{"by": "acme#shane"}}, {"/adjust", map[string]any{"holder": "acme#shane", "changes": []any{map[string]any{"path": "lines.0.qty", "value": 3}}}}} {
		code, _, body := call2(mux, "POST", "/v1/pending/"+id+p.path, "relay-secret", p.body)
		if code != 409 || strings.Contains(body, "effect") || strings.Contains(body, "token") || strings.Contains(body, "1200") {
			t.Fatalf("%s: %d %s", p.path, code, body)
		}
	}
	// And the records themselves are the reader's.
	if code, _, _ := call2(mux, "GET", "/v1/records?agent="+url.QueryEscape(r.agent), "relay-secret", nil); code != 401 {
		t.Fatalf("the relay read the records: %d", code)
	}
	if code, _, _ := call2(mux, "GET", "/v1/attachment?agent="+url.QueryEscape(r.agent)+"&step=0&name=action", "relay-secret", nil); code != 401 {
		t.Fatalf("the relay read the action: %d", code)
	}
	if code, _, _ := call2(mux, "GET", "/v1/records?agent="+url.QueryEscape(r.agent), "reader-secret", nil); code != 200 {
		t.Fatalf("the reader: %d", code)
	}
	_ = s
}

// What the relay carries of an adjustment names no label, value or bound: the answer is states
// and ids, a refusal a code and a generic text, and the detail is sealed to the holder.
func TestAdjustAnswersToTheRelayCarryNoLabelsOrValues(t *testing.T) {
	r, s, mux, enc := relayRig(t)
	raw, _ := json.Marshal(submitRequest{Agent: r.agent, Action: r.draft(), Reason: "Desks are short"})
	var draft map[string]any
	_ = json.Unmarshal(raw, &draft)
	_, asked, _ := call2(mux, "POST", "/v1/submit", "agent-secret", draft)
	id := asked["pending"].(string)
	waitFor(t, "the request announced", func() bool { return r.announcedFor(id) == 1 })
	s.pendMu.Lock()
	adj := s.pending[id].Adjust
	s.pendMu.Unlock()
	if len(adj) != 1 || adj[0].Max != 8 || adj[0].Label != "Corner Desk" {
		t.Fatalf("%+v", adj)
	}
	leaks := func(body string) bool {
		for _, w := range []string{"Corner Desk", "goes from", "\"min\"", "\"max\"", "\"label\"", "\"params\"", "product_id", "partner_id", "\"action\""} {
			if strings.Contains(body, w) {
				return true
			}
		}
		return false
	}
	// Out of bounds: a code, a generic text, and the detail sealed to the holder.
	code, out, body := call2(mux, "POST", "/v1/pending/"+id+"/adjust", "relay-secret",
		map[string]any{"holder": "acme#shane", "changes": []any{map[string]any{"path": "lines.0.qty", "value": 9}}})
	if code != 400 || out["code"] != "outside_view" || out["error"] != "the change is outside what the view allows" || leaks(body) || strings.Contains(body, `"8"`) {
		t.Fatalf("%d %s", code, body)
	}
	envs, _ := out["sealed"].([]any)
	if len(envs) != 1 {
		t.Fatalf("no sealed detail: %s", body)
	}
	var env sealedRequest
	b, _ := json.Marshal(envs[0])
	_ = json.Unmarshal(b, &env)
	plain := openSealed(t, enc, env, adjustRefusalInfo)
	if plain["code"] != "outside_view" || plain["detail"] != "Corner Desk goes from 1 to 8" || plain["pending"] != id || plain["sig"] == nil {
		t.Fatalf("%v", plain)
	}
	// Signed by the gate key over the plaintext without sig.
	sig, _ := hex.DecodeString(plain["sig"].(string))
	delete(plain, "sig")
	signed, _ := canonical.Encode(plain)
	if !ed25519.Verify(s.key.Public().(ed25519.PublicKey), signed, sig) {
		t.Fatal("the sealed refusal is not signed by the gate")
	}
	// Other refusals: no detail travels in the clear.
	for _, bad := range []map[string]any{
		{"holder": "acme#tom", "changes": []any{map[string]any{"path": "lines.0.qty", "value": 5}}},
		{"holder": "acme#shane", "changes": []any{map[string]any{"path": "lines.0.product_id", "value": 20}}},
		{"holder": "acme#shane", "changes": []any{map[string]any{"path": "lines.0.qty", "value": 2.5}}},
		{"holder": "acme#shane", "changes": []any{map[string]any{"path": "lines.0.qty", "value": 2}}},
	} {
		code, out, body := call2(mux, "POST", "/v1/pending/"+id+"/adjust", "relay-secret", bad)
		if msg, _ := out["error"].(string); code/100 == 2 || leaks(body) || strings.Contains(msg, "acme#") || adjustRefusals[out["code"].(string)] != msg {
			t.Fatalf("%v: %d %s", bad, code, body)
		}
	}
	// Taken: states and ids only.
	code, out, body = call2(mux, "POST", "/v1/pending/"+id+"/adjust", "relay-secret",
		map[string]any{"holder": "acme#shane", "changes": []any{map[string]any{"path": "lines.0.qty", "value": 5}}})
	if code != 200 || len(out) != 4 || out["state"] != "replaced" || out["replaced"] != id || out["by"] != out["pending"] || leaks(body) {
		t.Fatalf("%d %s", code, body)
	}
	code, st, body := call2(mux, "GET", "/v1/pending/"+id, "relay-secret", nil)
	if code != 200 || st["state"] != "replaced" || st["by"] != out["by"] || len(st) != 2 {
		t.Fatalf("%d %s", code, body)
	}
}

// openSealed is the phone's side of an envelope sealed with sealFor.
func openSealed(t *testing.T, priv *ecdh.PrivateKey, e sealedRequest, info string) map[string]any {
	t.Helper()
	k, err := hpke.NewDHKEMPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	encB, _ := base64.RawURLEncoding.DecodeString(e.Enc)
	ct, _ := base64.RawURLEncoding.DecodeString(e.CT)
	ad := map[string]any{"holder": e.Holder, "pending": e.Pending, "kid": e.Kid}
	if e.Exp != 0 {
		ad["exp"] = e.Exp
	}
	aad, _ := canonical.Encode(ad)
	rcp, err := hpke.NewRecipient(encB, k, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte(info))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := rcp.Open(aad, ct)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

// The writes that wait for a word are the organisation's to see: listed for its reader, with what
// each asks, and refused to anyone else.
func TestWaitingWritesAreListedForTheReaderOnly(t *testing.T) {
	s, mux, agent := readRig(t, nil)
	s.pending = map[string]*pendingWord{
		"w1": {ID: "w1", Holder: "acme#shane", State: "waiting", Expires: time.Now().Add(time.Hour),
			Req: submitRequest{Agent: agent, Action: policy.Action{Kind: "odoo.order_draft", Params: map[string]any{"partner_id": 77}}}},
		"w2": {ID: "w2", Holder: "acme#shane", State: "done", Expires: time.Now().Add(time.Hour)},
		"w3": {ID: "w3", Holder: "acme#robby", State: "waiting", Expires: time.Now().Add(-time.Minute)},
	}
	for _, token := range []string{"", "client-secret", "relay-secret"} {
		if code, _, body := call2(mux, "GET", "/v1/pending", token, nil); code != 401 || strings.Contains(body, "w1") {
			t.Fatalf("pending with %q: %d %s", token, code, body)
		}
	}
	code, out, body := call2(mux, "GET", "/v1/pending", "reader-secret", nil)
	list, _ := out["pending"].([]any)
	if code != 200 || len(list) != 1 || !strings.Contains(body, `"odoo.order_draft"`) || !strings.Contains(body, `"acme#shane"`) {
		t.Fatalf("pending for the reader: %d %s", code, body)
	}
	// The relay keeps its own route for one write's state alone.
	if code, _, _ := call2(mux, "GET", "/v1/pending/w2", "relay-secret", nil); code != 200 {
		t.Fatalf("the relay's state route: %d", code)
	}
}
