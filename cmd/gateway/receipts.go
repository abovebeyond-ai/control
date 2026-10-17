package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/abovebeyond-ai/control/canonical"
	"github.com/abovebeyond-ai/control/effects"
	"github.com/abovebeyond-ai/control/gateway"
	"github.com/abovebeyond-ai/control/registry"
)

// Sealed receipts (docs/odoo-gate.md): under a grant that names an organisation, every action
// ends with a receipt for the person it was taken in the name of, sealed with HPKE to the key
// their phone holds (their registry entry's enc) and a second time to the organisation's audit
// key (audit_enc). The relay stores and forwards the envelopes and cannot read them.
//
// Nothing of this is on the request path. settle writes a job file in the store's outbox; a
// worker resolves the keys, seals one envelope per key, and posts them to the relay, retrying
// until the relay takes them. Files, so a restart loses no receipt. A receipt that cannot be
// made or delivered never changes a verdict: the records are the evidence, the receipt a copy.

// receiptInfo is HPKE's info for every receipt envelope.
const receiptInfo = "bextrust receipt v1"

// receiptJob is a receipt waiting to be sealed: the plaintext, its holder, and the holder's key
// when the verified chain of the action already named it.
type receiptJob struct {
	ID        string           `json:"id"`
	Holder    string           `json:"holder"`
	At        int64            `json:"at"`
	HolderEnc *registry.EncKey `json:"holder_enc,omitempty"`
	Plaintext json.RawMessage  `json:"plaintext"`
}

// envelope is one sealed receipt for one key, as the relay takes it.
type envelope struct {
	Holder string `json:"holder"`
	ID     string `json:"id"`
	At     int64  `json:"at"`
	Kid    string `json:"kid"`
	Enc    string `json:"enc"`
	CT     string `json:"ct"`
}

// outbox is where receipts wait: job-*.json to seal, env-*.json to deliver.
type outbox struct {
	dir  string
	mu   sync.Mutex // one flush at a time
	kick chan struct{}
}

func (s *service) outboxDir() string { return filepath.Join(s.store.Dir, "outbox") }

// receipt writes the job for an action that has all its records. It returns nothing: a job
// that cannot be written is logged, and the action stands as recorded.
func (s *service) receipt(g *gateway.Gateway, req submitRequest, v gateway.Verdict, records []any, last int, outcome any) {
	grant := s.cfg.Agents[req.Agent].Grant
	if grant.Org == "" {
		return
	}
	holder, enc := "", (*registry.EncKey)(nil)
	switch {
	case v.Signer != nil:
		holder, enc = v.Signer.ID, v.Signer.Enc
	case req.asked != "":
		holder = req.asked
	default:
		holder = grant.Asks
	}
	if holder == "" {
		fmt.Fprintf(os.Stderr, "receipt: %s/%d has nobody to go to\n", req.Agent, last)
		return
	}
	id := fmt.Sprintf("%s/%d", req.Agent, last)
	at := time.Now().Unix()
	effect := receiptEffect(outcome)
	plain := map[string]any{
		"v": 1, "id": id, "holder": holder, "at": at, "agent": req.Agent,
		"kind": req.Action.Kind, "resource": req.Action.Resource, "params": req.Action.Params,
		"verdict": v.Verdict, "reason": v.Reason, "asked": req.asked != "",
		"effect": effect, "records": records, "gate_key": hex.EncodeToString(s.key.Public().(ed25519.PublicKey)),
	}
	if plain["params"] == nil {
		plain["params"] = map[string]any{}
	}
	if cc, ok := v.Token.Claims()["control_chain"].(map[string]any); ok {
		chain := map[string]any{}
		for _, k := range []string{"entries", "ceiling_eur", "daily_eur", "spent_today_eur"} {
			if x, ok := cc[k]; ok {
				chain[k] = x
			}
		}
		// The day after the act, when the effect says where it ended up.
		if after, ok := effect["spent_today_eur"]; ok {
			chain["spent_today_eur"] = after
		}
		plain["chain"] = chain
	}
	raw, err := canonical.Encode(plain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "receipt: %s cannot be put in canonical form: %v\n", id, err)
		return
	}
	job := receiptJob{ID: id, Holder: holder, At: at, HolderEnc: enc, Plaintext: raw}
	if err := writeAtomic(filepath.Join(s.outboxDir(), "job-"+fileKey(holder, id, "")+".json"), job); err != nil {
		fmt.Fprintf(os.Stderr, "receipt: %s could not be queued: %v\n", id, err)
		return
	}
	s.kickReceipts()
}

// receiptEffect is the adapter's detail, flat, with ok and the error beside it; a refusal or a
// dry run says it was not performed.
func receiptEffect(outcome any) map[string]any {
	out := map[string]any{}
	switch o := outcome.(type) {
	case effects.Outcome:
		for k, v := range o.Detail {
			out[k] = v
		}
		out["ok"] = o.OK
		if o.Error != "" {
			out["error"] = o.Error
		}
	case map[string]any:
		for k, v := range o {
			out[k] = v
		}
		out["ok"] = false
	}
	return out
}

func (s *service) kickReceipts() {
	if s.receipts == nil {
		return
	}
	select {
	case s.receipts.kick <- struct{}{}:
	default:
	}
}

// deliverReceipts runs the outbox: at every kick and once a minute, so what the relay did not
// take is tried again.
func (s *service) deliverReceipts() {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		s.flushReceipts()
		select {
		case <-s.receipts.kick:
		case <-tick.C:
		}
	}
}

// flushReceipts seals every waiting job and posts every waiting envelope, once.
func (s *service) flushReceipts() {
	s.receipts.mu.Lock()
	defer s.receipts.mu.Unlock()
	dir := s.outboxDir()
	jobs, _ := filepath.Glob(filepath.Join(dir, "job-*.json"))
	for _, path := range jobs {
		var job receiptJob
		raw, err := os.ReadFile(path)
		if err != nil || json.Unmarshal(raw, &job) != nil {
			fmt.Fprintf(os.Stderr, "receipt: %s is unreadable, set aside\n", path)
			_ = os.Rename(path, path+".bad")
			continue
		}
		if err := s.seal(job); err != nil {
			fmt.Fprintf(os.Stderr, "receipt: %s waits: %v\n", job.ID, err)
			continue
		}
		_ = os.Remove(path)
	}
	envs, _ := filepath.Glob(filepath.Join(dir, "env-*.json"))
	for _, path := range envs {
		var e envelope
		raw, err := os.ReadFile(path)
		if err != nil || json.Unmarshal(raw, &e) != nil {
			_ = os.Rename(path, path+".bad")
			continue
		}
		status, err := s.postReceipt(raw)
		switch {
		case err == nil && status/100 == 2:
			_ = os.Remove(path)
		case err != nil || (status != 400 && status != 413 && status != 422):
			// Away, or not taking receipts yet (a relay without the mailbox answers 404): the
			// rest waits for the next round.
			fmt.Fprintf(os.Stderr, "receipt: %s for %s not delivered (%d %v), tried again later\n", e.ID, e.Holder, status, err)
			return
		default:
			fmt.Fprintf(os.Stderr, "receipt: the relay refused %s for %s (%d), set aside\n", e.ID, e.Holder, status)
			_ = os.Rename(path, path+".refused")
		}
	}
}

// seal makes the envelopes of one job: the holder's key, and the audit key under "<org>#audit".
// A recipient without a key gets no envelope, and that is logged; an error means the job is
// tried again (the relay could not be asked for the holder's chain).
func (s *service) seal(job receiptJob) error {
	type recipient struct {
		holder string
		key    *registry.EncKey
	}
	var to []recipient
	key := job.HolderEnc
	if key == nil {
		var err error
		if key, err = s.holderEnc(job.Holder); err != nil {
			return err
		}
	}
	if key != nil {
		to = append(to, recipient{job.Holder, key})
	} else {
		fmt.Fprintf(os.Stderr, "receipt: %s has no encryption key; no envelope for %s\n", job.Holder, job.ID)
	}
	if org, _, ok := strings.Cut(job.Holder, "#"); ok && s.cfg.AuditEnc != nil {
		to = append(to, recipient{org + "#audit", s.cfg.AuditEnc})
	} else {
		fmt.Fprintf(os.Stderr, "receipt: no audit_enc configured; no audit envelope for %s\n", job.ID)
	}
	for _, r := range to {
		e, err := sealReceipt(*r.key, r.holder, job.ID, job.At, job.Plaintext)
		if err != nil {
			fmt.Fprintf(os.Stderr, "receipt: %s could not be sealed for %s: %v\n", job.ID, r.holder, err)
			continue
		}
		if err := writeAtomic(filepath.Join(s.outboxDir(), "env-"+fileKey(r.holder, job.ID, e.Kid)+".json"), e); err != nil {
			return err
		}
	}
	return nil
}

// holderEnc is the key a holder's receipts are sealed to, read from their chain at the relay
// and verified down from the organisation's pinned root like any chain: the relay cannot hand
// over a key Acme's people did not sign. nil, nil: the chain holds and names no key.
func (s *service) holderEnc(holder string) (*registry.EncKey, error) {
	base := s.relayBase()
	if base == "" {
		return nil, errors.New("no relay to ask for " + holder + "'s chain")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/registry/"+url.PathEscape(holder), nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("the relay: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode == 404 {
		return nil, nil
	}
	var out struct {
		Chain []string `json:"chain"`
	}
	if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out) != nil {
		return nil, fmt.Errorf("the relay answered %d for %s's chain", res.StatusCode, holder)
	}
	roots, err := s.cfg.orgKeys()
	if err != nil {
		return nil, err
	}
	entries, err := registry.VerifyChain(out.Chain, roots, time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "receipt: %s's chain at the relay does not hold: %v\n", holder, err)
		return nil, nil
	}
	if leaf := entries[len(entries)-1]; leaf.ID == holder {
		return leaf.Enc, nil
	}
	return nil, nil
}

func (s *service) relayBase() string {
	base := s.cfg.RelayURL
	if base == "" {
		base = os.Getenv("RELAY_URL")
	}
	return strings.TrimRight(base, "/")
}

// postReceipt hands one envelope to the relay, as the gate announces words (pending.go).
func (s *service) postReceipt(body []byte) (int, error) {
	base := s.relayBase()
	if base == "" {
		return 0, errors.New("no relay")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/receipts", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	return res.StatusCode, nil
}

// sealReceipt seals a plaintext to one key: HPKE base mode, DHKEM(P-256, HKDF-SHA256),
// HKDF-SHA256, AES-128-GCM, info "bextrust receipt v1", and as aad the canonical JSON of the
// envelope's header, so the relay cannot move a receipt to another holder, id or time.
func sealReceipt(key registry.EncKey, holder, id string, at int64, plaintext []byte) (envelope, error) {
	point, err := key.Point()
	if err != nil {
		return envelope{}, err
	}
	pub, err := ecdh.P256().NewPublicKey(point)
	if err != nil {
		return envelope{}, err
	}
	pk, err := hpke.NewDHKEMPublicKey(pub)
	if err != nil {
		return envelope{}, err
	}
	aad, err := receiptAAD(holder, id, at, key.Kid)
	if err != nil {
		return envelope{}, err
	}
	enc, sender, err := hpke.NewSender(pk, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte(receiptInfo))
	if err != nil {
		return envelope{}, err
	}
	ct, err := sender.Seal(aad, plaintext)
	if err != nil {
		return envelope{}, err
	}
	b64 := base64.RawURLEncoding.EncodeToString
	return envelope{Holder: holder, ID: id, At: at, Kid: key.Kid, Enc: b64(enc), CT: b64(ct)}, nil
}

// receiptAAD is the canonical JSON of {"holder","id","at","kid"}.
func receiptAAD(holder, id string, at int64, kid string) ([]byte, error) {
	return canonical.Encode(map[string]any{"holder": holder, "id": id, "at": at, "kid": kid})
}

// openReceipt is the phone's side, for tests and for Acme's audit tool to mirror.
func openReceipt(priv *ecdh.PrivateKey, e envelope) ([]byte, error) {
	k, err := hpke.NewDHKEMPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	enc, err1 := base64.RawURLEncoding.DecodeString(e.Enc)
	ct, err2 := base64.RawURLEncoding.DecodeString(e.CT)
	if err1 != nil || err2 != nil {
		return nil, errors.New("the envelope is not base64url")
	}
	aad, err := receiptAAD(e.Holder, e.ID, e.At, e.Kid)
	if err != nil {
		return nil, err
	}
	r, err := hpke.NewRecipient(enc, k, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte(receiptInfo))
	if err != nil {
		return nil, err
	}
	return r.Open(aad, ct)
}

// fileKey names a receipt's files without letting an id choose a path.
func fileKey(holder, id, kid string) string {
	sum := sha256.Sum256([]byte(holder + "\x00" + id + "\x00" + kid))
	return hex.EncodeToString(sum[:12])
}
