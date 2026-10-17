package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/abovebeyond-ai/control/canonical"
	"github.com/abovebeyond-ai/control/capability"
	"github.com/abovebeyond-ai/control/gateway"
)

// A write that needs a person's word and comes without one is not refused: it waits for the
// word (docs/odoo-gate.md). The gateway judges it against the grant first, without a record,
// since a person must never be asked to put a word to what the grant refuses anyway. It then
// writes the payload the person's passkey is to sign, a capability for this one act, ten
// minutes long, and answers 202 with it and its challenge. The relay shows it on the person's
// phone and brings back the signed word with the registry chain, or the refusal.
//
// Nothing is recorded while a write waits, because nothing has been judged under a word yet.
// The judgement comes with the answer: the word verified or not, the refusal, or the end of
// the ten minutes, each a request record with its effect and result like every action.
//
// The waiting writes live in memory. A restart forgets them; the hand asks again, and the
// person signs again. A word for a forgotten write still verifies as a word for that act, but
// only a submission can present it, and a hand that holds the word can do no more with it than
// the person allowed.

// wordWindow is how long a word for one act is good for, and how long a write waits for it.
const wordWindow = 10 * time.Minute

// maxWaiting bounds the writes waiting at once, so a hand cannot fill the gateway's memory.
const maxWaiting = 256

type pendingWord struct {
	ID        string
	Holder    string
	Req       submitRequest
	Body      []byte // the submission as the hand sent it, for its signature
	Signature []byte
	Payload   []byte // the capability payload the passkey is to sign, canonical
	Expires   time.Time
	State     string         // waiting, done, refused, expired
	Record    map[string]any // the answer once it is decided
	Done      time.Time
	busy      bool // being decided right now
}

// asksWord holds a write that needs a person's word and came without one, and answers 202 with
// what the person is to sign. It returns false when the submission is judged as it is: no
// organisation, a capability attached, a kind that needs no word, or a write the grant refuses,
// which is then recorded as refused like any other.
func (s *service) asksWord(w http.ResponseWriter, g *gateway.Gateway, req submitRequest, body, signature []byte) bool {
	grant := s.cfg.Agents[req.Agent].Grant
	if grant.Org == "" || req.Capability != "" || !g.NeedsWord(req.Action.Kind) {
		return false
	}
	if verdict, _ := g.Precheck(req.Run, req.Action); verdict != "ALLOW" || !g.SubmitterHolds(body, signature) {
		return false
	}
	// Parameters that have no canonical form cannot be named by a word; the submission then
	// meets the judgement, which fails closed on them.
	if _, err := canonical.Digest(map[string]any{"kind": req.Action.Kind, "resource": req.Action.Resource, "params": req.Action.Params}); err != nil {
		return false
	}
	holder := req.Holder
	if holder == "" {
		holder = grant.Asks
	}
	if holder == "" || !strings.HasPrefix(holder, grant.Org+"#") {
		v := g.Refuse(req.Run, req.Action, req.Principal, req.Extension, body, signature, "nobody of "+grant.Org+" to ask for a word: the grant names nobody and the submission names "+orNobody(holder))
		status, out := s.settle(context.Background(), g, req, v)
		writeJSON(w, status, out)
		return true
	}
	now := time.Now()
	idRaw := make([]byte, 16)
	_, _ = rand.Read(idRaw)
	id := hex.EncodeToString(idRaw)
	payload := capability.Payload{Issuer: holder, Subject: req.Agent, Audience: s.cfg.Issuer,
		Task:  capability.Task{Project: grant.Org},
		Kinds: []string{req.Action.Kind}, Resources: []string{req.Action.Resource},
		IssuedAt: now.Unix(), Expires: now.Add(wordWindow).Unix(), ID: "word-" + id, Act: capability.ActDigest(req.Action)}
	raw, err := canonical.Encode(payload)
	if err != nil {
		return false
	}
	p := &pendingWord{ID: id, Holder: holder, Req: req, Body: body, Signature: signature, Payload: raw, Expires: time.Unix(payload.Expires, 0), State: "waiting"}
	s.pendMu.Lock()
	if s.pending == nil {
		s.pending = map[string]*pendingWord{}
	}
	waiting := 0
	for _, q := range s.pending {
		if q.State == "waiting" {
			waiting++
		}
	}
	if waiting >= maxWaiting {
		s.pendMu.Unlock()
		writeJSON(w, 429, map[string]any{"error": fmt.Sprintf("%d writes already wait for a word", waiting)})
		return true
	}
	s.pending[id] = p
	s.pendMu.Unlock()
	asked := map[string]any{"pending": id, "holder": holder, "payload": base64.RawURLEncoding.EncodeToString(raw), "challenge": capability.Challenge(raw),
		"action": map[string]any{"kind": req.Action.Kind, "resource": req.Action.Resource, "params": req.Action.Params}}
	go s.announceSealed(p)
	writeJSON(w, 202, asked)
	return true
}

func orNobody(s string) string {
	if s == "" {
		return "nobody"
	}
	return s
}

// announce posts what announceSealed made to the relay. The relay is a channel and holds no key:
// an announcement that does not arrive delays the write, it cannot forge one.
func (s *service) announce(asked map[string]any) {
	base := s.cfg.RelayURL
	if base == "" {
		base = os.Getenv("RELAY_URL")
	}
	if base == "" {
		return
	}
	body, _ := json.Marshal(asked)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/api/requests", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "relay: %v\n", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "relay: the word for %v was not announced: %v\n", asked["pending"], err)
		return
	}
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode/100 != 2 {
		fmt.Fprintf(os.Stderr, "relay: the word for %v was not announced: %d\n", asked["pending"], res.StatusCode)
	}
}

// claim takes a waiting write to decide it, or says why it cannot be: unknown, being decided,
// decided, or expired just now (which is then recorded, and its record answered).
func (s *service) claim(id string) (*pendingWord, int, map[string]any) {
	s.pendMu.Lock()
	p, ok := s.pending[id]
	if !ok {
		s.pendMu.Unlock()
		return nil, 404, map[string]any{"error": "no write waits under that id"}
	}
	if p.busy {
		s.pendMu.Unlock()
		return nil, 409, map[string]any{"state": p.State, "error": "the write is being decided"}
	}
	if p.State != "waiting" {
		s.pendMu.Unlock()
		return nil, 409, map[string]any{"state": p.State, "record": p.Record}
	}
	p.busy = true
	s.pendMu.Unlock()
	if !time.Now().Before(p.Expires) {
		status, out := s.expire(p)
		if status == 200 {
			status = 410
		}
		return nil, status, map[string]any{"state": "expired", "record": out}
	}
	return p, 0, nil
}

// decided closes a write with its record; a store that could not write leaves it waiting.
func (s *service) decided(p *pendingWord, state string, status int, out map[string]any) {
	s.pendMu.Lock()
	defer s.pendMu.Unlock()
	p.busy = false
	if status == 503 {
		return
	}
	p.State, p.Record, p.Done = state, out, time.Now()
}

// release gives a claimed write back, still waiting.
func (s *service) release(p *pendingWord) {
	s.pendMu.Lock()
	p.busy = false
	s.pendMu.Unlock()
}

// expire records that the word did not come in time: a refusal, with its effect and result.
func (s *service) expire(p *pendingWord) (int, map[string]any) {
	g, err := s.gateway(p.Req.Agent)
	if err != nil {
		s.release(p)
		return 503, map[string]any{"error": err.Error()}
	}
	v := g.Refuse(p.Req.Run, p.Req.Action, p.Holder, p.Req.Extension, p.Body, p.Signature,
		"no word from "+p.Holder+" before "+p.Expires.UTC().Format(time.RFC3339))
	req := p.Req
	req.asked = p.Holder
	status, out := s.settle(context.Background(), g, req, v)
	s.decided(p, "expired", status, out)
	return status, out
}

// word is POST /v1/pending/{id}/word: the person's passkey word and the registry chain behind
// it, judged like any capability, and the write performed when it holds. A word that does not
// hold is a refusal on the record, and the write is decided with it.
func (s *service) word(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Capability string   `json:"capability"`
		Chain      []string `json:"chain"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil || in.Capability == "" {
		writeJSON(w, 400, map[string]any{"error": "a word is {capability, chain}"})
		return
	}
	p, status, view := s.claim(r.PathValue("id"))
	if p == nil {
		writeJSON(w, status, view)
		return
	}
	g, err := s.gateway(p.Req.Agent)
	if err != nil {
		s.release(p)
		writeJSON(w, 403, map[string]any{"error": err.Error()})
		return
	}
	req := p.Req
	req.Capability, req.Chain, req.asked = in.Capability, in.Chain, p.Holder
	v := g.SubmitChained(req.Run, req.Action, p.Holder, req.Extension, req.Premises, p.Body, p.Signature, req.Capability, req.Chain)
	status, out := s.settle(r.Context(), g, req, v)
	s.decided(p, "done", status, out)
	writeJSON(w, status, forRelay(out))
}

// refuse is POST /v1/pending/{id}/refuse: the person said no. A refusal is not signed, since
// refusing can only keep something from happening; the record says who the relay says refused.
func (s *service) refuse(w http.ResponseWriter, r *http.Request) {
	var in struct {
		By string `json:"by"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in)
	p, status, view := s.claim(r.PathValue("id"))
	if p == nil {
		writeJSON(w, status, view)
		return
	}
	g, err := s.gateway(p.Req.Agent)
	if err != nil {
		s.release(p)
		writeJSON(w, 403, map[string]any{"error": err.Error()})
		return
	}
	ext := map[string]any{}
	for k, v := range p.Req.Extension {
		ext[k] = v
	}
	ext["control_refused"] = map[string]any{"by": in.By, "pending": p.ID}
	v := g.Refuse(p.Req.Run, p.Req.Action, p.Holder, ext, p.Body, p.Signature, "refused by "+orNobody(in.By))
	req := p.Req
	req.asked = p.Holder
	status, out := s.settle(r.Context(), g, req, v)
	s.decided(p, "refused", status, out)
	writeJSON(w, status, forRelay(out))
}

// forRelay is what the relay is told of a decided write: the verdict and where it is recorded.
// What was done, to which order, for how much, the person and the agent read in their receipts.
func forRelay(out map[string]any) map[string]any {
	m := map[string]any{}
	for _, k := range []string{"verdict", "reason", "step", "action", "error"} {
		if v, ok := out[k]; ok {
			m[k] = v
		}
	}
	return m
}

// pendingState is GET /v1/pending/{id}: waiting, done, refused or expired, with the record
// once there is one. A write past its ten minutes is recorded as expired when it is asked for.
func (s *service) pendingState(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.pendMu.Lock()
	p, ok := s.pending[id]
	expired := ok && p.State == "waiting" && !p.busy && !time.Now().Before(p.Expires)
	if expired {
		p.busy = true
	}
	s.pendMu.Unlock()
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "no write waits under that id"})
		return
	}
	if expired {
		s.expire(p)
	}
	s.pendMu.Lock()
	out := map[string]any{"state": p.State, "record": p.Record}
	s.pendMu.Unlock()
	writeJSON(w, 200, out)
}

// sweepPending records the writes whose word did not come in time, and forgets decided ones
// after an hour.
func (s *service) sweepPending(every time.Duration) {
	for range time.Tick(every) {
		s.sweepOnce(time.Now())
	}
}

func (s *service) sweepOnce(now time.Time) {
	var due []*pendingWord
	s.pendMu.Lock()
	for id, p := range s.pending {
		switch {
		case p.State == "waiting" && !p.busy && !now.Before(p.Expires):
			p.busy = true
			due = append(due, p)
		case p.State != "waiting" && !p.busy && now.Sub(p.Done) > time.Hour:
			delete(s.pending, id)
		}
	}
	s.pendMu.Unlock()
	for _, p := range due {
		s.expire(p)
	}
}
