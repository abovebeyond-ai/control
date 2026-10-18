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
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abovebeyond-ai/control/effects"
	"github.com/abovebeyond-ai/control/gateway"
	"github.com/abovebeyond-ai/control/log"
	"github.com/abovebeyond-ai/control/policy"
	"github.com/abovebeyond-ai/control/registry"
)

// stateRig is a relay that keeps the gate's state as the contract says, an Odoo that remembers
// each draft's origin, and a holder whose passkey signs words; gates are made on it at will, as
// a restart makes a new one.
type stateRig struct {
	t          *testing.T
	mu         sync.Mutex
	blobs      []stateBlob
	serve      int // when >= 0, GET answers this blob instead of the latest
	announce   []map[string]any
	receipts   []envelope
	down       bool // the relay takes no announcement and no receipt
	creates    []string
	createdQty []float64
	stateKey   []byte

	relay, odoo *httptest.Server
	root, tom   ed25519.PrivateKey
	shane       *ecdsa.PrivateKey
	audit       *ecdh.PrivateKey
	chain       []string
	agent       string
}

var quickWaits sync.Once

func newStateRig(t *testing.T) *stateRig {
	// Short waits for every test of this package from here on: a gate's loops outlive its test.
	quickWaits.Do(func() {
		backoffMin, backoffMax, stateCoalesce = 10*time.Millisecond, 50*time.Millisecond, 10*time.Millisecond
	})
	r := &stateRig{t: t, serve: -1, agent: "did:web:bextrust.abovebeyond.ai:acme#procurement-agent"}
	r.stateKey = bytes.Repeat([]byte{0x5e}, 32)
	r.root = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xac}, 32))
	r.tom = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x70}, 32))
	r.shane, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	r.audit, _ = ecdh.P256().GenerateKey(rand.Reader)
	now := time.Now()
	kinds := policy.Builtin.Of(policy.OdooAdapter)
	tomTok, _ := registry.Issue(registry.Entry{ID: "acme#tom", Org: "acme", Parent: "acme", Holder: registry.JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(r.tom.Public().(ed25519.PublicKey))},
		Role: "director", Kinds: kinds, CeilingEUR: 25000, MayDelegate: true, IssuedAt: now.Unix() - 60, Expires: now.Unix() + 86400}, r.root)
	shaneTok, _ := registry.Issue(registry.Entry{ID: "acme#shane", Org: "acme", Parent: "acme#tom", Holder: p256JWK(r.shane), Role: "buyer", Kinds: kinds,
		CeilingEUR: 5000, IssuedAt: now.Unix() - 60, Expires: now.Unix() + 86400}, r.tom)
	r.chain = []string{tomTok, shaneTok}

	r.relay = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()
		switch {
		case req.URL.Path == "/api/gate/state" && req.Method == http.MethodPut:
			var b stateBlob
			_ = json.NewDecoder(req.Body).Decode(&b)
			if n := len(r.blobs); n > 0 && b.Seq <= r.blobs[n-1].Seq {
				w.WriteHeader(409)
				return
			}
			r.blobs = append(r.blobs, b)
			w.WriteHeader(201)
		case req.URL.Path == "/api/gate/state":
			if len(r.blobs) == 0 {
				w.WriteHeader(404)
				return
			}
			b := r.blobs[len(r.blobs)-1]
			if r.serve >= 0 {
				b = r.blobs[r.serve]
			}
			_ = json.NewEncoder(w).Encode(b)
		case req.URL.Path == "/api/registry/acme#shane":
			_ = json.NewEncoder(w).Encode(map[string]any{"chain": r.chain})
		case req.URL.Path == "/api/registry":
			_ = json.NewEncoder(w).Encode(map[string]any{"chains": []any{}})
		case r.down && (req.URL.Path == "/api/requests" || req.URL.Path == "/api/receipts"):
			w.WriteHeader(503)
		case req.URL.Path == "/api/requests":
			var a map[string]any
			_ = json.NewDecoder(req.Body).Decode(&a)
			r.announce = append(r.announce, a)
			w.WriteHeader(201)
		case req.URL.Path == "/api/receipts":
			var e envelope
			_ = json.NewDecoder(req.Body).Decode(&e)
			r.receipts = append(r.receipts, e)
			w.WriteHeader(201)
		default:
			w.WriteHeader(201)
		}
	}))
	t.Cleanup(r.relay.Close)

	orders := map[int64]string{} // id: origin
	r.odoo = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()
		var args map[string]any
		_ = json.NewDecoder(req.Body).Decode(&args)
		answer := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		switch strings.TrimPrefix(req.URL.Path, "/json/2/") {
		case "product.product/read":
			answer([]any{map[string]any{"id": 19, "display_name": "Corner Desk", "standard_price": 600.0, "purchase_ok": true}})
		case "res.partner/read":
			answer([]any{map[string]any{"id": 8, "name": "Supplier 8"}})
		case "product.supplierinfo/search_read", "purchase.order.line/search_read":
			answer([]any{})
		case "purchase.order/search_read":
			want := args["domain"].([]any)[0].([]any)[2]
			rows := []any{}
			for id, origin := range orders {
				if origin == want {
					rows = append(rows, map[string]any{"id": id})
				}
			}
			answer(rows)
		case "purchase.order/create":
			vals := args["vals_list"].([]any)[0].(map[string]any)
			origin, _ := vals["origin"].(string)
			id := int64(100 + len(orders))
			orders[id] = origin
			r.creates = append(r.creates, origin)
			line := vals["order_line"].([]any)[0].([]any)[2].(map[string]any)
			r.createdQty = append(r.createdQty, line["product_qty"].(float64))
			answer([]int64{id})
		case "purchase.order/read":
			id := int64(args["ids"].([]any)[0].(float64))
			answer([]any{map[string]any{"id": id, "name": fmt.Sprintf("P%05d", id), "state": "draft", "amount_total": 1200.0, "currency_id": []any{1, "EUR"},
				"company_id": []any{1, "Acme"}, "partner_id": []any{8, "Supplier 8"}, "order_line": []any{30}}})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(r.odoo.Close)
	return r
}

// gate is a gate as one starts: a key and a store of its own, the state key provisioned.
func (r *stateRig) gate() *service {
	t := r.t
	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets")
	_ = os.MkdirAll(secrets, 0o700)
	_ = os.WriteFile(filepath.Join(secrets, "odoo-key-acme"), []byte("odoo-secret\n"), 0o600)
	store, _ := log.Open(filepath.Join(dir, "store"))
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	kinds := policy.Builtin.Of(policy.OdooAdapter)
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	s := &service{done: done, key: key, store: store, effects: effects.Registry{}, gateways: map[string]*gateway.Gateway{},
		receipts: &outbox{kick: make(chan struct{}, 1)}, reqKick: make(chan struct{}, 1), state: newGateState(),
		cfg: config{Issuer: "https://gate.example/control", Store: filepath.Join(dir, "store"), Secrets: secrets, RelayURL: r.relay.URL, AuditEnc: encKeyOf(t, r.audit),
			Orgs: map[string]string{"acme": hex.EncodeToString(r.root.Public().(ed25519.PublicKey))}, Passkey: odooParty,
			Agents: map[string]struct {
				Grant policy.Grant `json:"grant"`
			}{r.agent: {Grant: policy.Grant{Principal: "acme", Kinds: kinds, Resources: []string{"odoo:acme/*"}, Org: "acme", Asks: "acme#shane"}}}}}
	var err error
	if s.prov, err = newProvisioner(); err != nil {
		t.Fatal(err)
	}
	s.prov.keys[stateKeyFile] = []byte(hex.EncodeToString(r.stateKey))
	s.effects.Add(effects.Odoo{SecretsDir: secrets, Instances: map[string]effects.OdooInstance{"acme": {Base: r.odoo.URL, DB: "acme"}}})
	return s
}

func (r *stateRig) draft() policy.Action {
	return policy.Action{Kind: "odoo.order_draft", Resource: "odoo:acme/purchase.order", Params: map[string]any{"partner_id": float64(8), "lines": []any{map[string]any{"product_id": float64(19), "qty": float64(2)}}}}
}

// ask submits the draft and answers the pending id and the payload the passkey signs.
func (r *stateRig) ask(s *service) (string, []byte) {
	r.t.Helper()
	raw, _ := json.Marshal(submitRequest{Agent: r.agent, Action: r.draft(), Reason: "Desks are short", Reasoning: reasoning{"Two desks are on back order.", "Supplier 8 is the only one with stock."}})
	rec := httptest.NewRecorder()
	s.submit(rec, httptest.NewRequest("POST", "/v1/submit", bytes.NewReader(raw)))
	var asked map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &asked)
	if rec.Code != 202 {
		r.t.Fatalf("%d %v", rec.Code, asked)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(asked["payload"].(string))
	return asked["pending"].(string), payload
}

func (r *stateRig) word(s *service, id string, payload []byte) map[string]any {
	r.t.Helper()
	body, _ := json.Marshal(map[string]any{"capability": signWord(r.t, r.shane, payload), "chain": r.chain})
	req := httptest.NewRequest("POST", "/v1/pending/x/word", bytes.NewReader(body))
	req.SetPathValue("id", id)
	rec := httptest.NewRecorder()
	s.word(rec, req)
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

// latest opens the blob the relay holds last, as the next gate would.
func (r *stateRig) latest() (int, statePlain) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.blobs) == 0 {
		return -1, statePlain{}
	}
	b := r.blobs[len(r.blobs)-1]
	raw, err := openState(r.stateKey, b)
	if err != nil {
		r.t.Fatal(err)
	}
	var p statePlain
	_ = json.Unmarshal(raw, &p)
	return len(r.blobs) - 1, p
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("waited in vain: %s", what)
}

func (r *stateRig) announcedFor(id string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, a := range r.announce {
		if a["pending"] == id {
			n++
		}
	}
	return n
}

// A gate that restarts while a word waits loses nothing: the next gate restores the word from
// the sealed state at the relay, announces it again, and performs it when the word comes, with
// the agent's reason and reasoning as they were.
func TestAWaitingWordSurvivesARestart(t *testing.T) {
	r := newStateRig(t)
	s1 := r.gate()
	s1.startState()
	id, payload := r.ask(s1)
	waitFor(t, "the waiting word in the state at the relay", func() bool {
		_, p := r.latest()
		return len(p.Pending) == 1 && p.Pending[0].ID == id && p.Pending[0].Announcement != nil
	})
	r.mu.Lock()
	for _, b := range r.blobs {
		if strings.Contains(b.CT, "Desks") {
			t.Fatal("the relay can read the state")
		}
	}
	r.mu.Unlock()

	s2 := r.gate() // s1 is gone: a new key, a new store
	s2.startState()
	waitFor(t, "the word restored", func() bool {
		s2.pendMu.Lock()
		defer s2.pendMu.Unlock()
		return s2.pending[id] != nil
	})
	waitFor(t, "the word announced again", func() bool { return r.announcedFor(id) == 2 })
	s2.pendMu.Lock()
	p := s2.pending[id]
	if p.State != "waiting" || p.Req.Reason != "Desks are short" || len(p.Req.Reasoning) != 2 {
		t.Fatalf("%+v", p.Req)
	}
	s2.pendMu.Unlock()

	out := r.word(s2, id, payload)
	if out["verdict"] != "ALLOW" || out["effect"].(map[string]any)["ok"] != true {
		t.Fatalf("%v", out)
	}
	if len(r.creates) != 1 || r.creates[0] != "bextrust:"+id {
		t.Fatalf("drafts created: %q", r.creates)
	}
	// The decision is stored too, with a higher seq.
	waitFor(t, "the decision in the state", func() bool {
		_, st := r.latest()
		return len(st.Pending) == 1 && st.Pending[0].State == "done"
	})
	r.mu.Lock()
	for i := 1; i < len(r.blobs); i++ {
		if r.blobs[i].Seq <= r.blobs[i-1].Seq {
			t.Fatalf("seq went from %d to %d", r.blobs[i-1].Seq, r.blobs[i].Seq)
		}
	}
	r.mu.Unlock()
}

// Receipts the relay did not take while it was away are in the state; the next gate delivers
// them, with backoff, once the relay is back, and the recipients' counts go on from where they
// were.
func TestTheOutboxIsDeliveredAfterTheRelayWasDown(t *testing.T) {
	r := newStateRig(t)
	r.down = true
	s1 := r.gate()
	s1.startState()
	id, payload := r.ask(s1)
	if out := r.word(s1, id, payload); out["verdict"] != "ALLOW" {
		t.Fatalf("%v", out)
	}
	if s1.flushReceipts() {
		t.Fatal("the relay is down, and the outbox says it is empty")
	}
	waitFor(t, "the receipts in the state", func() bool {
		_, p := r.latest()
		// Shane's entry has no key here, so the audit copy is the one envelope.
		return len(p.Receipts.Jobs) == 0 && len(p.Receipts.Envelopes) == 1 && p.Receipts.Counts.Seq["acme#audit"] == 1
	})

	r.mu.Lock()
	r.down = false
	r.mu.Unlock()
	s2 := r.gate()
	go s2.deliverReceipts()
	go s2.deliverRequestsLoop()
	s2.startState()
	waitFor(t, "the receipts delivered", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.receipts) == 1
	})
	r.mu.Lock()
	for _, e := range r.receipts {
		if e.Holder == "acme#audit" {
			raw, err := openReceipt(r.audit, e)
			if err != nil || !strings.Contains(string(raw), "Supplier 8 is the only one with stock.") {
				t.Fatalf("%v %s", err, raw)
			}
		}
	}
	r.mu.Unlock()
	if c := s2.loadCounts(); c.Seq["acme#audit"] != 1 {
		t.Fatalf("the counts were not restored: %v", c.Seq)
	}
	waitFor(t, "an empty outbox in the state", func() bool {
		_, p := r.latest()
		return len(p.Receipts.Envelopes) == 0
	})
}

// The relay hands a new gate an older blob, from before the word was decided: the word comes
// back, and when it is given again the draft is found in Odoo by its origin, not made twice.
func TestAnOldStateCannotMakeADraftTwice(t *testing.T) {
	r := newStateRig(t)
	s1 := r.gate()
	s1.startState()
	id, payload := r.ask(s1)
	var old int
	waitFor(t, "the waiting word in the state", func() bool {
		i, p := r.latest()
		old = i
		return len(p.Pending) == 1 && p.Pending[0].State == "waiting" && p.Pending[0].Announcement != nil
	})
	first := r.word(s1, id, payload)
	if first["verdict"] != "ALLOW" {
		t.Fatalf("%v", first)
	}
	r.mu.Lock()
	r.serve = old
	r.mu.Unlock()

	s2 := r.gate()
	s2.startState()
	waitFor(t, "the old word restored", func() bool {
		s2.pendMu.Lock()
		defer s2.pendMu.Unlock()
		return s2.pending[id] != nil
	})
	again := r.word(s2, id, payload)
	effect := again["effect"].(map[string]any)
	detail, _ := effect["detail"].(map[string]any)
	if again["verdict"] != "ALLOW" || effect["ok"] != true || detail["already"] != true || detail["name"] != "P00100" {
		t.Fatalf("%v", again)
	}
	if len(r.creates) != 1 {
		t.Fatalf("drafts created: %q", r.creates)
	}
}

// Without a state key the gate keeps its state in memory, as before, and stores nothing.
func TestNoStateKeyKeepsTheStateInMemory(t *testing.T) {
	r := newStateRig(t)
	s := r.gate()
	delete(s.prov.keys, stateKeyFile)
	s.startState()
	r.ask(s)
	time.Sleep(50 * time.Millisecond)
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.blobs) != 0 || s.state.started {
		t.Fatal("a gate without a state key stored state")
	}
}

// The blob opens only under its key and at its seq.
func TestTheStateBlobIsBoundToItsSeq(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	b, err := sealState(key, 7, 1, []byte(`{"v":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openState(key, b); err != nil {
		t.Fatal(err)
	}
	moved := b
	moved.Seq = 9
	if _, err := openState(key, moved); err == nil {
		t.Fatal("a blob opened under another seq")
	}
	if _, err := openState(bytes.Repeat([]byte{2}, 32), b); err == nil {
		t.Fatal("a blob opened under another key")
	}
	for _, text := range []string{hex.EncodeToString(key), base64.StdEncoding.EncodeToString(key)} {
		if k, err := parseStateKey([]byte(text + "\n")); err != nil || !bytes.Equal(k, key) {
			t.Fatalf("%q: %v", text, err)
		}
	}
	if _, err := parseStateKey([]byte("short")); err == nil {
		t.Fatal("a short state key was taken")
	}
}
