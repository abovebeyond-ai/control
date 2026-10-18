package main

// Who may call what. Three credentials reach the gateway, and each opens its own doors:
//
//   - the client token (client_token, client_token_sha256, CLIENT_TOKEN_SHA256): the hand. It
//     submits, decides a waiting write and reads it whole, record and effect included.
//   - the relay's token (relay_client_token_sha256, RELAY_CLIENT_TOKEN_SHA256): the channel
//     that carries a person's word. It posts the word, the refusal and the adjustment, and reads
//     a waiting write's state (waiting, done, refused, expired, replaced, by): never the params,
//     the record, the effect or an amount. Not to be confused with relay_token, which the
//     gateway presents to the relay.
//   - a reader token (readers): the organisation's own readers, by name, each a SHA-256. Record
//     bodies, attachments, inclusion proofs and the policy are served to them only, once any
//     reader is configured and always in Confidential Space. Readers have no environment
//     override on purpose: in Confidential Space the operator sets the environment, and the
//     operator is the party these routes are closed to. A reader's hash travels in the baked
//     configuration, which the image digest the organisation checks covers.
//
// What an anchor needs stays open to anyone: the key, the attestation, the checkpoints, the
// consistency proofs and the agents (their ids and grant digests). They carry tree sizes and
// roots, no record.

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"sort"
	"strings"
)

const (
	callerClient = "client"
	callerRelay  = "relay"
)

// bearer is the request's bearer token, empty when there is none.
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
}

// sha256Matches says whether got hashes to want (hex), in constant time; never for an empty want.
func sha256Matches(got, want string) bool {
	want = strings.ToLower(strings.TrimSpace(want))
	if want == "" {
		return false
	}
	sum := sha256.Sum256([]byte(got))
	return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(want)) == 1
}

// clientConfigured says whether submissions need a token at all.
func (c config) clientConfigured() bool {
	return c.ClientToken != "" || c.ClientTokenSHA256 != ""
}

// callerOf names the door a request comes through: the client, the relay, or none. A gateway
// without a client token takes everyone as the client, as it always did.
func (s *service) callerOf(r *http.Request) string {
	got := bearer(r)
	if !s.cfg.clientConfigured() {
		return callerClient
	}
	client := true
	if s.cfg.ClientToken != "" && subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.ClientToken)) != 1 {
		client = false
	}
	if s.cfg.ClientTokenSHA256 != "" && !sha256Matches(got, s.cfg.ClientTokenSHA256) {
		client = false
	}
	if client {
		return callerClient
	}
	if got != "" && sha256Matches(got, s.cfg.RelayClientTokenSHA256) {
		return callerRelay
	}
	return ""
}

// authed lets the client through, and nobody else.
func (s *service) authed(next http.HandlerFunc) http.HandlerFunc {
	return s.byCaller(map[string]http.HandlerFunc{callerClient: next})
}

// byCaller serves each door its own handler; a caller without one is refused. Fail closed by
// construction: a handler is reached only through a door that names it.
func (s *service) byCaller(handlers map[string]http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		next, ok := handlers[s.callerOf(r)]
		if !ok {
			writeJSON(w, 401, map[string]any{"error": "a client token is required to submit"})
			return
		}
		next(w, r)
	}
}

// readersRequired says whether record bodies are closed to anyone without a reader token: once
// a reader is named, and always in Confidential Space, where the operator runs the only path in.
func (c config) readersRequired() bool {
	return len(c.Readers) > 0 || c.Attestation == attestationCS
}

// readerOf names the reader whose token the request carries, empty when none.
func (s *service) readerOf(r *http.Request) string {
	got := bearer(r)
	if got == "" {
		return ""
	}
	names := make([]string, 0, len(s.cfg.Readers))
	for n := range s.cfg.Readers {
		names = append(names, n)
	}
	sort.Strings(names)
	found := ""
	for _, n := range names {
		if sha256Matches(got, s.cfg.Readers[n]) && found == "" {
			found = n
		}
	}
	return found
}

// reader guards a read that returns record bodies, params, outcomes, amounts or reasons: with
// readers required, only a reader's token opens it. Every read, served or refused, is recorded.
func (s *service) reader(what string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.readersRequired() {
			s.accessed(what, next)(w, r)
			return
		}
		name := s.readerOf(r)
		if name == "" {
			s.recordAccess(what, r, map[string]any{"refused": true})
			writeJSON(w, 401, map[string]any{"error": "a reader token of the organisation is required to read records"})
			return
		}
		s.recordAccess(what, r, map[string]any{"reader": name})
		next(w, r)
	}
}

// checkDoors refuses a configuration where two doors share a credential: the relay's token
// opening the client's door, or a reader's, would give the relay what its scope keeps from it.
func (c config) checkDoors() error {
	relay := strings.ToLower(strings.TrimSpace(c.RelayClientTokenSHA256))
	if err := c.checkReaders(); err != nil {
		return err
	}
	if relay == "" {
		return nil
	}
	if relay == strings.ToLower(strings.TrimSpace(c.ClientTokenSHA256)) || (c.ClientToken != "" && sha256Matches(c.ClientToken, relay)) {
		return errors.New("relay_client_token_sha256 is the client token: the relay must have a token of its own")
	}
	for name, h := range c.Readers {
		if relay == strings.ToLower(strings.TrimSpace(h)) {
			return errors.New("relay_client_token_sha256 is the token of reader " + name)
		}
	}
	return nil
}

// checkReaders holds each reader to a SHA-256 of its own: a reader's token that is also the
// client token would open the records to whoever sets the client token, the operator included.
func (c config) checkReaders() error {
	client := strings.ToLower(strings.TrimSpace(c.ClientTokenSHA256))
	for name, h := range c.Readers {
		h = strings.ToLower(strings.TrimSpace(h))
		if raw, err := hex.DecodeString(h); err != nil || len(raw) != sha256.Size {
			return errors.New("readers: " + name + " is not a SHA-256 in hex")
		}
		if h == client || (c.ClientToken != "" && sha256Matches(c.ClientToken, h)) {
			return errors.New("readers: " + name + " is the client token")
		}
	}
	return nil
}
