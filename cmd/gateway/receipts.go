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
	"github.com/abovebeyond-ai/control/capability"
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

// receiptJob is one action's receipt waiting to be sealed: the full plaintext without the
// recipient's part, the person it was taken for, their chain when the act verified one, and the
// supplier it concerns, if any.
type receiptJob struct {
	ID      string          `json:"id"`
	Holder  string          `json:"holder"`
	At      int64           `json:"at"`
	Chain   []string        `json:"chain,omitempty"`
	Partner int64           `json:"partner,omitempty"`
	Base    json.RawMessage `json:"base"`
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

// outbox is where receipts wait: job-*.json to seal, env-*.json to deliver, and seq.json, the
// count of envelopes sealed to each recipient (receiptCounts).
type outbox struct {
	mu   sync.Mutex // one flush at a time
	kick chan struct{}

	obsMu   sync.Mutex
	obs     [][]registry.Entry // the organisation's observers, verified
	obsAt   time.Time
	obsFrom string
}

func (s *service) outboxDir() string { return filepath.Join(s.store.Dir, "outbox") }

// receipt writes the job for an action that has all its records: verdicts holds the request,
// effect and result, in that order. It returns nothing: a job that cannot be written is logged,
// and the action stands as recorded.
//
// answer is what the result record's control_outcome digests (kept beside it as its outcome), so
// a reader holding the receipt checks it against the record and finds the order name there.
func (s *service) receipt(g *gateway.Gateway, req submitRequest, verdicts []gateway.Verdict, outcome, answer any) {
	grant := s.cfg.Agents[req.Agent].Grant
	if grant.Org == "" || len(verdicts) == 0 {
		return
	}
	v := verdicts[0]
	last := verdicts[len(verdicts)-1].Step
	holder := ""
	var chain []string
	switch {
	case v.Signer != nil:
		holder, chain = v.Signer.ID, req.Chain
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
	records := make([]any, len(verdicts))
	steps := make([]any, len(verdicts))
	leaves := make([]any, len(verdicts))
	size := last + 1
	for i, x := range verdicts {
		records[i] = x.Token
		c := x.Token.Claims()
		proof, err := g.InclusionAt(x.Step, size)
		if err != nil {
			fmt.Fprintf(os.Stderr, "receipt: %s has no inclusion proof for step %d: %v\n", id, x.Step, err)
			return
		}
		steps[i] = map[string]any{"step": x.Step, "proof": proof}
		leaves[i] = map[string]any{"step": x.Step, "snapshot": c["canonical_snapshot_hash"], "verdict": c["verdict"]}
	}
	cp, err := g.CheckpointAt(size)
	if err != nil {
		fmt.Fprintf(os.Stderr, "receipt: %s has no checkpoint: %v\n", id, err)
		return
	}
	base := map[string]any{
		"v": 1, "id": id, "holder": holder, "at": at, "agent": req.Agent,
		"kind": req.Action.Kind, "resource": req.Action.Resource, "params": req.Action.Params,
		"verdict": v.Verdict, "reason": v.Reason, "asked": req.asked != "",
		"effect": effect, "records": records, "gate_key": hex.EncodeToString(s.key.Public().(ed25519.PublicKey)),
		// The proof of each record into the checkpoint that closes the action; the anchor
		// answers which minute anchored that checkpoint (GET /anchor/proof?root=).
		"inclusion": map[string]any{"tree_size": size, "steps": steps, "leaves": leaves, "checkpoint": cp},
		"outcome":   answer,
	}
	if base["params"] == nil {
		base["params"] = map[string]any{}
	}
	if strings.HasPrefix(req.Capability, capability.PasskeyPrefix+".") {
		base["authority"] = map[string]any{"word": req.Capability, "chain": req.Chain}
	}
	if cc, ok := v.Token.Claims()["control_chain"].(map[string]any); ok {
		limits := map[string]any{}
		for _, k := range []string{"entries", "ceiling_eur", "daily_eur", "spent_today_eur"} {
			if x, ok := cc[k]; ok {
				limits[k] = x
			}
		}
		// The day after the act, when the effect says where it ended up.
		if after, ok := effect["spent_today_eur"]; ok {
			limits["spent_today_eur"] = after
		}
		base["chain"] = limits
	}
	raw, err := json.Marshal(base)
	if err != nil {
		fmt.Fprintf(os.Stderr, "receipt: %s cannot be written: %v\n", id, err)
		return
	}
	job := receiptJob{ID: id, Holder: holder, At: at, Chain: chain, Partner: partnerOf(req.Action.Params, effect), Base: raw}
	if err := writeAtomic(filepath.Join(s.outboxDir(), "job-"+fileKey(holder, id, "")+".json"), job); err != nil {
		fmt.Fprintf(os.Stderr, "receipt: %s could not be queued: %v\n", id, err)
		return
	}
	s.kickReceipts()
}

// partnerOf is the supplier an action concerns: the partner a draft names, or the one Odoo gave
// the order back with.
func partnerOf(params map[string]any, effect map[string]any) int64 {
	for _, v := range []any{params["partner_id"], effect["partner_id"]} {
		switch n := v.(type) {
		case float64:
			return int64(n)
		case int64:
			return n
		case int:
			return int64(n)
		case json.Number:
			x, _ := n.Int64()
			return x
		}
	}
	return 0
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

// reasonClass is the reason as a summary gives it: one of within grant, refused, over limit,
// expired, failed (allowed, and the far end did not do it).
func reasonClass(verdict, reason string, effect map[string]any) string {
	errText, _ := effect["error"].(string)
	switch {
	case strings.HasPrefix(reason, "no word from"):
		return "expired"
	case verdict != "ALLOW":
		return "refused"
	case strings.Contains(errText, "ceiling") || strings.Contains(errText, "daily allowance"):
		return "over limit"
	case effect["ok"] == false:
		return "failed"
	}
	return "within grant"
}

// summarize is what an observer with summary detail receives: what kind of act, how it ended,
// the amounts and limits, who and when, and the proof that the action's records are in the
// gate's log, with no parameters, no names of products or partners, no prices and no records.
// The leaves (snapshot digest and verdict per step) let it check the inclusion proofs without
// seeing a record.
func summarize(base map[string]any) map[string]any {
	effect, _ := base["effect"].(map[string]any)
	out := map[string]any{
		"v": base["v"], "id": base["id"], "holder": base["holder"], "at": base["at"], "agent": base["agent"],
		"kind": base["kind"], "verdict": base["verdict"], "asked": base["asked"], "gate_key": base["gate_key"],
		"reason_class": reasonClass(fmt.Sprint(base["verdict"]), fmt.Sprint(base["reason"]), effect),
		"inclusion":    base["inclusion"],
	}
	for _, k := range []string{"amount_total", "currency", "state"} {
		if x, ok := effect[k]; ok {
			out[k] = x
		}
	}
	if c, ok := base["chain"].(map[string]any); ok {
		limits := map[string]any{}
		for _, k := range []string{"ceiling_eur", "daily_eur", "spent_today_eur"} {
			if x, ok := c[k]; ok {
				limits[k] = x
			}
		}
		out["limits"] = limits
	}
	return out
}

// recipient is one key a receipt is sealed to.
type recipient struct {
	id     string // the envelope's holder: a person, a manager, an observer, or <org>#audit
	key    *registry.EncKey
	detail string // full or summary
	role   string // holder, manager, observer, audit
}

// recipients of an action taken for the holder whose verified chain is chain: the holder, every
// entry above them that may delegate and has a key (their managers, in full), the observers
// whose view covers the holder (filtered to their partners when they name some), and the
// organisation's audit key. One envelope per id.
func (s *service) recipients(holder string, chain []registry.Entry, partner int64, observers [][]registry.Entry, now time.Time) []recipient {
	var out []recipient
	seen := map[string]bool{}
	add := func(r recipient) {
		if r.key == nil || seen[r.id] {
			return
		}
		seen[r.id] = true
		out = append(out, r)
	}
	if n := len(chain); n > 0 && chain[n-1].ID == holder {
		add(recipient{holder, chain[n-1].Enc, "full", "holder"})
		for i := n - 2; i >= 0; i-- {
			if chain[i].MayDelegate {
				add(recipient{chain[i].ID, chain[i].Enc, "full", "manager"})
			}
		}
		for _, oc := range observers {
			if !registry.Covers(oc, chain, now) {
				continue
			}
			o := oc[len(oc)-1]
			if len(o.Sees.Partners) > 0 && !containsInt(o.Sees.Partners, partner) {
				continue
			}
			add(recipient{o.ID, o.Enc, o.Sees.Detail, "observer"})
		}
	}
	if org, _, ok := strings.Cut(holder, "#"); ok && s.cfg.AuditEnc != nil {
		add(recipient{org + "#audit", s.cfg.AuditEnc, "full", "audit"})
	}
	return out
}

func containsInt(list []int64, x int64) bool {
	for _, y := range list {
		if y == x {
			return true
		}
	}
	return false
}

// receiptCounts is seq.json: how many envelopes the gate sealed to each recipient, ever and per
// day. Each receipt carries its recipient's numbers, signed: a recipient who sees seq jump knows
// a receipt did not reach them, and the relay cannot fill the gap with one of its own.
type receiptCounts struct {
	Seq map[string]int64 `json:"seq"`
	Day map[string]int64 `json:"day"` // "<recipient> <YYYY-MM-DD>"
}

func (s *service) loadCounts() receiptCounts {
	c := receiptCounts{Seq: map[string]int64{}, Day: map[string]int64{}}
	if raw, err := os.ReadFile(filepath.Join(s.outboxDir(), "seq.json")); err == nil {
		_ = json.Unmarshal(raw, &c)
	}
	if c.Seq == nil {
		c.Seq = map[string]int64{}
	}
	if c.Day == nil {
		c.Day = map[string]int64{}
	}
	return c
}

// seal makes the envelopes of one job and counts them. An error means the job is tried again
// (the relay could not be asked for a chain); nothing was counted then.
func (s *service) seal(job receiptJob) error {
	var base map[string]any
	dec := json.NewDecoder(bytes.NewReader(job.Base))
	dec.UseNumber()
	if err := dec.Decode(&base); err != nil {
		return fmt.Errorf("the job's plaintext: %w", err)
	}
	roots, err := s.cfg.orgKeys()
	if err != nil {
		return err
	}
	now := time.Now()
	var chain []registry.Entry
	if len(job.Chain) > 0 {
		chain, err = registry.VerifyChain(job.Chain, roots, now)
		if err != nil {
			fmt.Fprintf(os.Stderr, "receipt: the chain of %s no longer holds: %v\n", job.ID, err)
			chain = nil
		}
	}
	if chain == nil {
		toks, err := s.relayChain(job.Holder)
		if err != nil {
			return err
		}
		if len(toks) > 0 {
			if chain, err = registry.VerifyChain(toks, roots, now); err != nil {
				fmt.Fprintf(os.Stderr, "receipt: %s's chain at the relay does not hold: %v\n", job.Holder, err)
				chain = nil
			}
		}
	}
	observers := s.observers(strings.SplitN(job.Holder, "#", 2)[0], roots, now)
	to := s.recipients(job.Holder, chain, job.Partner, observers, now)
	if len(chain) == 0 || chain[len(chain)-1].Enc == nil {
		fmt.Fprintf(os.Stderr, "receipt: %s has no encryption key; no envelope of %s for them\n", job.Holder, job.ID)
	}
	counts := s.loadCounts()
	day := now.UTC().Format("2006-01-02")
	priv := s.key
	for _, r := range to {
		plain := base
		if r.detail == "summary" {
			plain = summarize(base)
		} else {
			plain = map[string]any{}
			for k, v := range base {
				plain[k] = v
			}
		}
		counts.Seq[r.id]++
		counts.Day[r.id+" "+day]++
		plain["recipient"], plain["detail"], plain["role"] = r.id, r.detail, r.role
		plain["seq"], plain["day"], plain["day_count"] = counts.Seq[r.id], day, counts.Day[r.id+" "+day]
		delete(plain, "sig")
		signed, err := canonical.Encode(plain)
		if err != nil {
			return fmt.Errorf("%s for %s cannot be put in canonical form: %w", job.ID, r.id, err)
		}
		plain["sig"] = hex.EncodeToString(ed25519.Sign(priv, signed))
		raw, err := canonical.Encode(plain)
		if err != nil {
			return err
		}
		e, err := sealReceipt(*r.key, r.id, job.ID, job.At, raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "receipt: %s could not be sealed for %s: %v\n", job.ID, r.id, err)
			continue
		}
		if err := writeAtomic(filepath.Join(s.outboxDir(), "env-"+fileKey(r.id, job.ID, e.Kid)+".json"), e); err != nil {
			return err
		}
	}
	return writeAtomic(filepath.Join(s.outboxDir(), "seq.json"), counts)
}

// relayChain is a holder's chain as the relay serves it; nil when the relay knows no such
// entry. What it hands over is verified by the caller from the pinned root.
func (s *service) relayChain(holder string) ([]string, error) {
	base := s.relayBase()
	if base == "" {
		return nil, errors.New("no relay to ask for " + holder + "'s chain")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/registry/"+url.PathEscape(holder), nil)
	res, err := s.relayDo(req)
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
	return out.Chain, nil
}

// observers are the organisation's observer chains from the relay, each verified from the
// pinned root, kept for a minute. A relay that is away leaves the last list in place; one that
// leaves an observer out costs that observer its receipts, which its seq shows.
func (s *service) observers(org string, roots map[string]ed25519.PublicKey, now time.Time) [][]registry.Entry {
	o := s.receipts
	if o == nil {
		return nil
	}
	o.obsMu.Lock()
	defer o.obsMu.Unlock()
	if o.obsFrom == org && now.Sub(o.obsAt) < time.Minute {
		return o.obs
	}
	base := s.relayBase()
	if base == "" {
		return o.obs
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/registry?org="+url.QueryEscape(org)+"&role="+registry.RoleObserver, nil)
	res, err := s.relayDo(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "receipt: the relay's observers of %s: %v\n", org, err)
		return o.obs
	}
	defer res.Body.Close()
	var out struct {
		Chains [][]string `json:"chains"`
	}
	if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(&out) != nil {
		fmt.Fprintf(os.Stderr, "receipt: the relay answered %d for the observers of %s\n", res.StatusCode, org)
		return o.obs
	}
	var list [][]registry.Entry
	for _, toks := range out.Chains {
		entries, err := registry.VerifyChain(toks, roots, now)
		if err != nil {
			fmt.Fprintf(os.Stderr, "receipt: an observer chain at the relay does not hold: %v\n", err)
			continue
		}
		if entries[len(entries)-1].Role == registry.RoleObserver {
			list = append(list, entries)
		}
	}
	o.obs, o.obsAt, o.obsFrom = list, now, org
	return list
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
	res, err := s.relayDo(req)
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
	aad, err := receiptAAD(holder, id, at, key.Kid)
	if err != nil {
		return envelope{}, err
	}
	enc, ct, err := hpkeSeal(key, receiptInfo, aad, plaintext)
	if err != nil {
		return envelope{}, err
	}
	b64 := base64.RawURLEncoding.EncodeToString
	return envelope{Holder: holder, ID: id, At: at, Kid: key.Kid, Enc: b64(enc), CT: b64(ct)}, nil
}

// hpkeSeal is the one suite every envelope uses: base mode, DHKEM(P-256, HKDF-SHA256),
// HKDF-SHA256, AES-128-GCM; info names what is sealed, aad binds the envelope's header.
func hpkeSeal(key registry.EncKey, info string, aad, plaintext []byte) (enc, ct []byte, err error) {
	point, err := key.Point()
	if err != nil {
		return nil, nil, err
	}
	pub, err := ecdh.P256().NewPublicKey(point)
	if err != nil {
		return nil, nil, err
	}
	pk, err := hpke.NewDHKEMPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	enc, sender, err := hpke.NewSender(pk, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte(info))
	if err != nil {
		return nil, nil, err
	}
	ct, err = sender.Seal(aad, plaintext)
	return enc, ct, err
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
