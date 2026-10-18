package main

// Durable state (docs/odoo-gate.md, availability). A gate in Confidential Space keeps nothing on
// disk that outlives it, and a gate that restarts must lose no waiting word and no receipt. So
// the gate keeps its waiting words and its outbox (receipts not yet taken by the relay, and the
// count of envelopes sealed to each recipient) in one blob, sealed with AES-256-GCM under a
// state key the organisation provisions, and stores it at the relay after every change:
//
//	PUT /api/gate/state  {"v":1,"seq":<n>,"at":<unix>,"nonce":<b64url>,"ct":<b64url>}
//	GET /api/gate/state  the latest
//
// with aad = "bextrust gate state v1" || seq (8 bytes, big endian). The relay keeps the blobs and
// cannot read them. A gate that starts fetches the latest once it holds the state key, drops what
// expired, announces its waiting words again and delivers its outbox. Without a state key it
// works from memory, as before, and says so.
//
// The relay could hand back an older blob and so bring back a word that was already decided.
// That cannot make a write happen twice: a word's write carries its pending id to Odoo (a draft's
// origin is "bextrust:<pending>"), and the adapter answers with what is already there instead of
// writing again (effects.OdooPendingParam).

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// stateKeyFile is the provisioned state key: 32 bytes, written as hex or base64.
	stateKeyFile = "state-key"
	stateInfo    = "bextrust gate state v1"
)

// Delivery to the relay retries from backoffMin, doubling, up to backoffMax, and never gives up.
// stateCoalesce gathers a burst of changes into one store. Variables, so tests run quickly.
var (
	backoffMin    = time.Second
	backoffMax    = time.Minute
	stateCoalesce = 200 * time.Millisecond
)

type backoff struct{ d time.Duration }

func (b *backoff) next() time.Duration {
	if b.d == 0 {
		b.d = backoffMin
	} else if b.d *= 2; b.d > backoffMax {
		b.d = backoffMax
	}
	return b.d
}

func (b *backoff) reset() { b.d = 0 }

// gateState is the state blob's keeper: its key once provisioned, the seq of the last blob, and
// whether the latest blob at the relay was read (nothing is stored before, or a fresh gate would
// put an empty state on top of the one it is to restore).
type gateState struct {
	mu       sync.Mutex
	key      []byte
	seq      uint64
	started  bool
	restored bool
	kick     chan struct{}
	puts     int // blobs the relay took, for tests
}

func newGateState() *gateState { return &gateState{kick: make(chan struct{}, 1)} }

// stateBlob is what the relay keeps.
type stateBlob struct {
	V     int    `json:"v"`
	Seq   uint64 `json:"seq"`
	At    int64  `json:"at"`
	Nonce string `json:"nonce"`
	CT    string `json:"ct"`
}

// statePlain is what the blob seals.
type statePlain struct {
	V        int          `json:"v"`
	Pending  []storedWord `json:"pending"`
	Receipts storedOutbox `json:"receipts"`
}

// storedWord is a waiting or decided word with everything needed to decide it after a restart:
// the submission as the agent sent and signed it (reason and reasoning with it), the payload the
// passkey signs, and the announcement the relay is to show.
type storedWord struct {
	ID           string          `json:"id"`
	Holder       string          `json:"holder"`
	Req          submitRequest   `json:"req"`
	Body         []byte          `json:"body"`
	Signature    []byte          `json:"signature,omitempty"`
	Payload      []byte          `json:"payload"`
	Expires      int64           `json:"expires"`
	State        string          `json:"state"`
	Record       map[string]any  `json:"record,omitempty"`
	Done         int64           `json:"done,omitempty"`
	Announcement json.RawMessage `json:"announcement,omitempty"`
}

// storedOutbox is the receipts outbox: jobs to seal, envelopes to deliver, and the counts.
type storedOutbox struct {
	Jobs      []receiptJob  `json:"jobs"`
	Envelopes []envelope    `json:"envelopes"`
	Counts    receiptCounts `json:"counts"`
}

// parseStateKey reads a provisioned state key: 64 hex characters or base64 of 32 bytes.
func parseStateKey(text []byte) ([]byte, error) {
	s := strings.TrimSpace(string(text))
	if k, err := hex.DecodeString(s); err == nil && len(k) == 32 {
		return k, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if k, err := enc.DecodeString(s); err == nil && len(k) == 32 {
			return k, nil
		}
	}
	return nil, errors.New("the state-key is not 32 bytes in hex or base64")
}

func stateAAD(seq uint64) []byte {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], seq)
	return append([]byte(stateInfo), n[:]...)
}

func sealState(key []byte, seq uint64, at int64, plain []byte) (stateBlob, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return stateBlob{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return stateBlob{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return stateBlob{}, err
	}
	b64 := base64.RawURLEncoding.EncodeToString
	return stateBlob{V: 1, Seq: seq, At: at, Nonce: b64(nonce), CT: b64(gcm.Seal(nil, nonce, plain, stateAAD(seq)))}, nil
}

func openState(key []byte, b stateBlob) ([]byte, error) {
	if b.V != 1 {
		return nil, fmt.Errorf("a state blob of version %d", b.V)
	}
	nonce, err1 := base64.RawURLEncoding.DecodeString(b.Nonce)
	ct, err2 := base64.RawURLEncoding.DecodeString(b.CT)
	if err1 != nil || err2 != nil {
		return nil, errors.New("the state blob is not base64url")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("the state blob's nonce has the wrong length")
	}
	plain, err := gcm.Open(nil, nonce, ct, stateAAD(b.Seq))
	if err != nil {
		return nil, errors.New("the state blob does not open under this state key")
	}
	return plain, nil
}

// stateChanged asks for the state to be stored; a burst of changes makes one store.
func (s *service) stateChanged() {
	if s.state == nil {
		return
	}
	select {
	case s.state.kick <- struct{}{}:
	default:
	}
}

// startState begins keeping the state once there is a state key and a relay: restore first,
// then store after every change. It is called at start and after every provisioning.
func (s *service) startState() {
	if s.state == nil {
		return
	}
	st := s.state
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.started {
		return
	}
	raw, ok := s.prov.key(stateKeyFile)
	if !ok {
		return
	}
	key, err := parseStateKey(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "state: %v; waiting words and the outbox stay in memory only\n", err)
		return
	}
	if s.relayBase() == "" {
		fmt.Fprintln(os.Stderr, "state: a state-key but no relay to keep the state at; waiting words and the outbox stay in memory only")
		return
	}
	st.key, st.started = key, true
	go s.runState()
}

// runState restores, then stores after every change, retrying each with backoff.
func (s *service) runState() {
	var b backoff
	for {
		err := s.restoreState()
		if err == nil {
			break
		}
		d := b.next()
		fmt.Fprintf(os.Stderr, "state: the latest state could not be read from the relay (%v); again in %s\n", err, d)
		if !s.sleep(d) {
			return
		}
	}
	s.stateChanged()
	for {
		select {
		case <-s.done:
			return
		case <-s.state.kick:
		}
		if !s.sleep(stateCoalesce) {
			return
		}
		b.reset()
		for {
			err := s.storeState()
			if err == nil {
				break
			}
			d := b.next()
			fmt.Fprintf(os.Stderr, "state: not stored at the relay (%v); again in %s\n", err, d)
			if !s.sleep(d) {
				return
			}
		}
	}
}

// sleep waits d, or answers false when the gateway stops first.
func (s *service) sleep(d time.Duration) bool {
	select {
	case <-s.done:
		return false
	case <-time.After(d):
		return true
	}
}

func (s *service) stateURL() string { return s.relayBase() + "/api/gate/state" }

// fetchState is the latest blob at the relay; nil when it has none.
func (s *service) fetchState() (*stateBlob, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.stateURL(), nil)
	if err != nil {
		return nil, err
	}
	res, err := s.relayDo(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode == 404 {
		return nil, nil
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("the relay answered %d", res.StatusCode)
	}
	var b stateBlob
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<20)).Decode(&b); err != nil {
		return nil, fmt.Errorf("the relay's state does not parse: %w", err)
	}
	return &b, nil
}

// restoreState reads the latest blob and takes what it holds into this gate.
func (s *service) restoreState() error {
	b, err := s.fetchState()
	if err != nil {
		return err
	}
	st := s.state
	if b == nil {
		st.mu.Lock()
		st.restored = true
		st.mu.Unlock()
		fmt.Fprintln(os.Stderr, "state: the relay holds no state yet; starting empty")
		return nil
	}
	plain, err := openState(st.key, *b)
	st.mu.Lock()
	if b.Seq > st.seq {
		st.seq = b.Seq
	}
	st.mu.Unlock()
	if err != nil {
		// Not this key's, or altered: nothing to take, and the next store goes on top with a
		// higher seq. The relay keeps the earlier blobs.
		fmt.Fprintf(os.Stderr, "state: blob %d: %v; starting without it\n", b.Seq, err)
		st.mu.Lock()
		st.restored = true
		st.mu.Unlock()
		return nil
	}
	var p statePlain
	if err := json.Unmarshal(plain, &p); err != nil || p.V != 1 {
		fmt.Fprintf(os.Stderr, "state: blob %d holds no state of version 1; starting without it\n", b.Seq)
		st.mu.Lock()
		st.restored = true
		st.mu.Unlock()
		return nil
	}
	words, receipts := s.applyState(p, time.Now())
	st.mu.Lock()
	st.restored = true
	st.mu.Unlock()
	fmt.Fprintf(os.Stderr, "state: restored blob %d: %d word(s), %d receipt job(s) and envelope(s)\n", b.Seq, words, receipts)
	if !s.deliverRequests() {
		s.kickRequests()
	}
	s.kickReceipts()
	return nil
}

// applyState takes a restored state: the words that have not expired (each announced again),
// decided ones for an hour, the receipts outbox, and each recipient's count, never lower.
func (s *service) applyState(p statePlain, now time.Time) (words, receipts int) {
	s.pendMu.Lock()
	if s.pending == nil {
		s.pending = map[string]*pendingWord{}
	}
	for _, w := range p.Pending {
		if _, ok := s.pending[w.ID]; ok {
			continue
		}
		expires := time.Unix(w.Expires, 0)
		if w.State == "waiting" && !now.Before(expires) {
			continue
		}
		if w.State != "waiting" && now.Sub(time.Unix(w.Done, 0)) > time.Hour {
			continue
		}
		req := w.Req
		if len(req.Files) > 0 {
			req.Action.Attached = map[string]any{"files": req.Files}
		}
		q := &pendingWord{ID: w.ID, Holder: w.Holder, Req: req, Body: w.Body, Signature: w.Signature, Payload: w.Payload, Expires: expires,
			State: w.State, Record: w.Record, Announcement: w.Announcement, restored: true}
		if w.Done != 0 {
			q.Done = time.Unix(w.Done, 0)
		}
		s.pending[w.ID] = q
		words++
	}
	var reannounce []*pendingWord
	for _, q := range s.pending {
		if q.restored && q.State == "waiting" && q.Announcement == nil {
			reannounce = append(reannounce, q)
		}
	}
	s.pendMu.Unlock()
	for _, q := range reannounce {
		go s.announceSealed(q)
	}
	dir := s.outboxDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "state: the outbox: %v\n", err)
		return words, 0
	}
	for _, j := range p.Receipts.Jobs {
		path := filepath.Join(dir, "job-"+fileKey(j.Holder, j.ID, "")+".json")
		if _, err := os.Stat(path); err == nil {
			continue
		}
		if writeAtomic(path, j) == nil {
			receipts++
		}
	}
	for _, e := range p.Receipts.Envelopes {
		path := filepath.Join(dir, "env-"+fileKey(e.Holder, e.ID, e.Kid)+".json")
		if _, err := os.Stat(path); err == nil {
			continue
		}
		if writeAtomic(path, e) == nil {
			receipts++
		}
	}
	if s.receipts != nil {
		s.receipts.mu.Lock()
		defer s.receipts.mu.Unlock()
	}
	counts := s.loadCounts()
	for k, v := range p.Receipts.Counts.Seq {
		if v > counts.Seq[k] {
			counts.Seq[k] = v
		}
	}
	for k, v := range p.Receipts.Counts.Day {
		if v > counts.Day[k] {
			counts.Day[k] = v
		}
	}
	if err := writeAtomic(filepath.Join(dir, "seq.json"), counts); err != nil {
		fmt.Fprintf(os.Stderr, "state: the receipt counts: %v\n", err)
	}
	return words, receipts
}

// snapshot is the state as it stands: every word, and the receipts outbox as its files are.
func (s *service) snapshot() statePlain {
	p := statePlain{V: 1, Pending: []storedWord{}, Receipts: storedOutbox{Jobs: []receiptJob{}, Envelopes: []envelope{}}}
	s.pendMu.Lock()
	for _, q := range s.pending {
		w := storedWord{ID: q.ID, Holder: q.Holder, Req: q.Req, Body: q.Body, Signature: q.Signature, Payload: q.Payload,
			Expires: q.Expires.Unix(), State: q.State, Record: q.Record, Announcement: q.Announcement}
		if !q.Done.IsZero() {
			w.Done = q.Done.Unix()
		}
		p.Pending = append(p.Pending, w)
	}
	s.pendMu.Unlock()
	// Between two flushes, so a job and the envelopes sealed from it are never both taken.
	if s.receipts != nil {
		s.receipts.mu.Lock()
		defer s.receipts.mu.Unlock()
	}
	dir := s.outboxDir()
	jobs, _ := filepath.Glob(filepath.Join(dir, "job-*.json"))
	for _, path := range jobs {
		var j receiptJob
		if raw, err := os.ReadFile(path); err == nil && json.Unmarshal(raw, &j) == nil {
			p.Receipts.Jobs = append(p.Receipts.Jobs, j)
		}
	}
	envs, _ := filepath.Glob(filepath.Join(dir, "env-*.json"))
	for _, path := range envs {
		var e envelope
		if raw, err := os.ReadFile(path); err == nil && json.Unmarshal(raw, &e) == nil {
			p.Receipts.Envelopes = append(p.Receipts.Envelopes, e)
		}
	}
	p.Receipts.Counts = s.loadCounts()
	return p
}

// storeState seals the state as it stands under the next seq and puts it at the relay. A relay
// that holds a higher seq (409) tells the gate where to go on from.
func (s *service) storeState() error {
	st := s.state
	st.mu.Lock()
	if !st.restored {
		st.mu.Unlock()
		return nil
	}
	st.seq++
	seq, key := st.seq, st.key
	st.mu.Unlock()
	plain, err := json.Marshal(s.snapshot())
	if err != nil {
		return err
	}
	b, err := sealState(key, seq, time.Now().Unix(), plain)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(b)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, s.stateURL(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := s.relayDo(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode == 409 {
		if latest, err := s.fetchState(); err == nil && latest != nil {
			st.mu.Lock()
			if latest.Seq > st.seq {
				st.seq = latest.Seq
			}
			st.mu.Unlock()
		}
		return fmt.Errorf("the relay holds a later seq than %d", seq)
	}
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("the relay answered %d", res.StatusCode)
	}
	st.mu.Lock()
	st.puts++
	st.mu.Unlock()
	return nil
}
